package v39

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type skillPath struct {
	ID   string
	Path string
}

func AnalyzeInput(input string, limits Limits) ([]OverlayResult, error) {
	limits = normalizedLimits(limits)
	skills, err := discoverSkills(input)
	if err != nil {
		return nil, err
	}
	results := make([]OverlayResult, 0, len(skills))
	for _, skill := range skills {
		results = append(results, safeAnalyzeSkill(skill.ID, skill.Path, limits))
	}
	return results, nil
}

func safeAnalyzeSkill(skillID, root string, limits Limits) (result OverlayResult) {
	started := time.Now()
	defer func() {
		if recovered := recover(); recovered != nil {
			stats := newStats()
			stats.markIncomplete("internal v39 analysis error")
			result = OverlayResult{
				SkillID:       skillID,
				Version:       Version,
				Verdict:       "suspicious",
				Category:      "ast08",
				Evidence:      fmt.Sprintf("OWASP AST08 behavior overlay failed closed while analyzing %s", filepath.Base(root)),
				Confidence:    0.70,
				Stats:         stats,
				DurationMilli: time.Since(started).Milliseconds(),
				ScannedAt:     time.Now().UTC(),
			}
		}
	}()
	return AnalyzeSkill(skillID, root, limits)
}

type overlayCandidate struct {
	Path     string
	Rel      string
	Size     int64
	Priority int
}

func AnalyzeSkill(skillID, root string, limits Limits) OverlayResult {
	started := time.Now()
	limits = normalizedLimits(limits)
	stats := newStats()
	facts := make([]Fact, 0, 64)
	candidates := collectCandidates(root, limits, &stats)
	var rawRetained int64

	for _, candidate := range candidates {
		if stats.FilesAnalyzed >= limits.MaxFilesPerSkill {
			stats.markTruncated("analyzed-file limit reached")
			break
		}
		if len(facts) >= limits.MaxFactsPerSkill {
			stats.markTruncated("behavior-fact limit reached")
			break
		}
		remainingRaw := limits.MaxSkillBytes - rawRetained
		if remainingRaw <= 0 {
			stats.markTruncated("skill raw-byte limit reached")
			break
		}

		if isArchiveName(candidate.Rel) {
			if candidate.Size > limits.MaxArchiveBytes || candidate.Size > remainingRaw {
				stats.markTruncated("archive exceeds raw-byte budget")
				continue
			}
			remainingArchiveBytes := limits.MaxArchiveExpandedBytes - stats.ArchiveBytes
			remainingArchiveEntries := limits.MaxArchiveEntries - stats.ArchiveEntries
			if remainingArchiveBytes <= 0 || remainingArchiveEntries <= 0 {
				stats.markTruncated("per-skill archive budget reached")
				break
			}
			data, err := os.ReadFile(candidate.Path)
			if err != nil {
				stats.ReadErrors++
				stats.markIncomplete("archive read failed")
				continue
			}
			rawRetained += int64(len(data))
			stats.BytesRead += int64(len(data))
			archiveLimits := clippedMaterialLimits(limits, stats)
			archiveLimits.MaxArchiveExpandedBytes = remainingArchiveBytes
			archiveLimits.MaxArchiveEntries = remainingArchiveEntries
			materials := ExtractArchive(candidate.Rel, data, archiveLimits, &stats)
			stats.FilesAnalyzed++
			if !appendMaterialFacts(&facts, materials, limits, &stats) {
				break
			}
			continue
		}

		if !isTextCandidate(candidate.Rel) {
			continue
		}
		perFile := limits.MaxFileBytes
		if perFile > remainingRaw {
			perFile = remainingRaw
		}
		data, sampled, err := readSampled(candidate.Path, candidate.Size, perFile)
		if err != nil {
			stats.ReadErrors++
			stats.markIncomplete("file read failed")
			continue
		}
		if sampled {
			stats.SampledFiles++
		}
		rawRetained += int64(len(data))
		stats.BytesRead += int64(len(data))
		materials := MaterializeText(candidate.Rel, data, clippedMaterialLimits(limits, stats))
		stats.FilesAnalyzed++
		if !appendMaterialFacts(&facts, materials, limits, &stats) {
			break
		}
	}

	chain := ClassifyFacts(facts)
	result := OverlayResult{
		SkillID:       skillID,
		Version:       Version,
		Verdict:       "benign",
		Category:      "benign",
		Evidence:      "v39 behavior overlay found no high-confidence behavior chain",
		Stats:         stats,
		DurationMilli: time.Since(started).Milliseconds(),
		ScannedAt:     time.Now().UTC(),
	}
	if chain.Verdict != "" {
		result.Verdict = chain.Verdict
		result.Category = chain.Category
		result.Confidence = chain.Confidence
		result.Facts = chain.Facts
		result.Evidence = buildEvidence(chain)
	}
	return result
}

func collectCandidates(root string, limits Limits, stats *ScanStats) []overlayCandidate {
	candidates := make([]overlayCandidate, 0, min(limits.MaxFilesPerSkill, 256))
	walkErr := filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			stats.ReadErrors++
			stats.markIncomplete("filesystem walk error")
			if filePath == root {
				return walkErr
			}
			return nil
		}
		if entry == nil {
			stats.ReadErrors++
			stats.markIncomplete("empty directory entry")
			return nil
		}
		if entry.IsDir() {
			if filePath != root && shouldSkipDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		stats.FilesVisited++
		if entry.Type()&os.ModeSymlink != 0 {
			stats.SkippedSymlinks++
			stats.markIncomplete("symlink skipped")
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			stats.ReadErrors++
			stats.markIncomplete("file metadata read failed")
			return nil
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 {
			return nil
		}
		rel, err := filepath.Rel(root, filePath)
		if err != nil {
			stats.ReadErrors++
			stats.markIncomplete("relative path resolution failed")
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !isArchiveName(rel) && !isTextCandidate(rel) {
			return nil
		}
		if len(candidates) >= limits.MaxCandidateFiles {
			stats.markTruncated("candidate-file limit reached")
			return filepath.SkipAll
		}
		candidates = append(candidates, overlayCandidate{
			Path:     filePath,
			Rel:      rel,
			Size:     info.Size(),
			Priority: candidatePriority(rel),
		})
		return nil
	})
	if walkErr != nil {
		stats.ReadErrors++
		stats.markIncomplete("filesystem walk aborted")
	}
	stats.CandidateFiles = len(candidates)
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority < candidates[j].Priority
		}
		return candidates[i].Rel < candidates[j].Rel
	})
	return candidates
}

func candidatePriority(rel string) int {
	lower := strings.ToLower(filepath.ToSlash(rel))
	base := filepath.Base(lower)
	switch {
	case base == "skill.md", strings.Contains(base, "manifest"), base == "package.json", base == "mcp.json", base == "settings.json":
		return 0
	case strings.Contains(lower, ".github/workflows/"), strings.Contains(lower, ".gitlab-ci"), strings.Contains(lower, ".cursor/rules/"), strings.Contains(lower, ".claude/"), strings.Contains(lower, ".husky/"), strings.Contains(lower, "devcontainer"), strings.Contains(lower, ".envrc"):
		return 0
	case base == "dockerfile", base == "makefile", base == "jenkinsfile", base == "setup.py", base == "pyproject.toml", base == "build.rs":
		return 0
	case isArchiveName(lower):
		return 1
	case isExecutablePath(lower):
		return 2
	case isMetadataPath(lower):
		return 3
	default:
		return 4
	}
}

func clippedMaterialLimits(limits Limits, stats ScanStats) Limits {
	remainingVariants := limits.MaxDecodedVariantsPerSkill - stats.DecodedVariants
	remainingBytes := limits.MaxDecodedBytesPerSkill - stats.DecodedBytes
	if remainingVariants <= 0 || remainingBytes <= 0 {
		limits.MaxDecodeDepth = 0
		limits.MaxDecodedVariantsPerFile = 0
		limits.MaxDecodedBytesPerFile = 0
		return limits
	}
	if limits.MaxDecodedVariantsPerFile > remainingVariants {
		limits.MaxDecodedVariantsPerFile = remainingVariants
	}
	if limits.MaxDecodedBytesPerFile > remainingBytes {
		limits.MaxDecodedBytesPerFile = remainingBytes
	}
	return limits
}

func appendMaterialFacts(facts *[]Fact, materials []Material, limits Limits, stats *ScanStats) bool {
	for _, material := range materials {
		if material.Decoded {
			stats.DecodedVariants++
			stats.DecodedBytes += int64(len(material.Text))
		}
		extracted := ExtractFacts(material)
		remaining := limits.MaxFactsPerSkill - len(*facts)
		if remaining <= 0 {
			stats.markTruncated("behavior-fact limit reached")
			return false
		}
		if len(extracted) > remaining {
			*facts = append(*facts, extracted[:remaining]...)
			stats.FactsExtracted = len(*facts)
			stats.markTruncated("behavior-fact limit reached")
			return false
		}
		*facts = append(*facts, extracted...)
		stats.FactsExtracted = len(*facts)
	}
	if stats.DecodedVariants >= limits.MaxDecodedVariantsPerSkill || stats.DecodedBytes >= limits.MaxDecodedBytesPerSkill {
		stats.markTruncated("per-skill decoded-material budget reached")
	}
	return true
}

func normalizedLimits(limits Limits) Limits {
	defaults := DefaultLimits()
	if limits.MaxCandidateFiles <= 0 {
		limits.MaxCandidateFiles = defaults.MaxCandidateFiles
	}
	if limits.MaxFilesPerSkill <= 0 {
		limits.MaxFilesPerSkill = defaults.MaxFilesPerSkill
	}
	if limits.MaxFileBytes <= 0 {
		limits.MaxFileBytes = defaults.MaxFileBytes
	}
	if limits.MaxSkillBytes <= 0 {
		limits.MaxSkillBytes = defaults.MaxSkillBytes
	}
	if limits.MaxDecodeDepth <= 0 {
		limits.MaxDecodeDepth = defaults.MaxDecodeDepth
	}
	if limits.MaxDecodedVariantsPerFile <= 0 {
		limits.MaxDecodedVariantsPerFile = defaults.MaxDecodedVariantsPerFile
	}
	if limits.MaxDecodedBytesPerFile <= 0 {
		limits.MaxDecodedBytesPerFile = defaults.MaxDecodedBytesPerFile
	}
	if limits.MaxDecodedVariantsPerSkill <= 0 {
		limits.MaxDecodedVariantsPerSkill = defaults.MaxDecodedVariantsPerSkill
	}
	if limits.MaxDecodedBytesPerSkill <= 0 {
		limits.MaxDecodedBytesPerSkill = defaults.MaxDecodedBytesPerSkill
	}
	if limits.MaxFactsPerSkill <= 0 {
		limits.MaxFactsPerSkill = defaults.MaxFactsPerSkill
	}
	if limits.MaxArchiveBytes <= 0 {
		limits.MaxArchiveBytes = defaults.MaxArchiveBytes
	}
	if limits.MaxArchiveExpandedBytes <= 0 {
		limits.MaxArchiveExpandedBytes = defaults.MaxArchiveExpandedBytes
	}
	if limits.MaxArchiveEntries <= 0 {
		limits.MaxArchiveEntries = defaults.MaxArchiveEntries
	}
	if limits.MaxArchiveDepth <= 0 {
		limits.MaxArchiveDepth = defaults.MaxArchiveDepth
	}
	if limits.MaxCompressionRatio <= 0 {
		limits.MaxCompressionRatio = defaults.MaxCompressionRatio
	}
	return limits
}
