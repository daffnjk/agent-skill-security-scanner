package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	incompleteScanExitCode = 3
	maxScanErrorSamples    = 5
	maxCandidateFiles      = maxBlobsPerSkill * 8
)

var stableCategoryOrder = []string{
	"ast01", "ast02", "ast03", "ast04", "ast05",
	"ast06", "ast07", "ast08", "ast09", "ast10",
}

// ScanStatus describes whether all supported content was inspected. Oversized
// text files that are successfully head/tail sampled are reported, but do not by
// themselves make a scan incomplete. Read failures, skipped opaque payloads,
// symlinks, and resource-budget exhaustion do.
type ScanStatus struct {
	Complete           bool
	Truncated          bool
	InternalError      string
	FilesVisited       int
	FilesAnalyzed      int
	FilesSkipped       int
	ReadErrors         int
	SampledFiles       int
	SkippedSymlinks    int
	SkippedOpaque      int
	SkippedUnsupported int
	TruncateReason     string
	ErrorSamples       []string
}

// ScanMetadata is the audit-oriented companion record written beside the
// competition-compatible four-field results.jsonl output.
type ScanMetadata struct {
	SkillID            string   `json:"skill_id"`
	Complete           bool     `json:"complete"`
	Truncated          bool     `json:"truncated"`
	InternalError      string   `json:"internal_error,omitempty"`
	FilesVisited       int      `json:"files_visited"`
	FilesAnalyzed      int      `json:"files_analyzed"`
	FilesSkipped       int      `json:"files_skipped"`
	ReadErrors         int      `json:"read_errors"`
	SampledFiles       int      `json:"sampled_files"`
	SkippedSymlinks    int      `json:"skipped_symlinks"`
	SkippedOpaque      int      `json:"skipped_opaque"`
	SkippedUnsupported int      `json:"skipped_unsupported"`
	TruncateReason     string   `json:"truncate_reason,omitempty"`
	ErrorSamples       []string `json:"error_samples,omitempty"`
}

type fileCandidate struct {
	Path     string
	Rel      string
	Size     int64
	Base     bool
	Explain  bool
	Priority int
}

func init() {
	normalizeLoopRuleDefinitions()
}

// normalizeLoopRuleDefinitions fixes the historical mismatch between lower-case
// file content and mixed-case rule needles (for example ObjectInputStream and
// YAML.load). It runs once before any scan or test.
func normalizeLoopRuleDefinitions() {
	for i := range loop16To115Rules {
		rule := &loop16To115Rules[i]
		for j := range rule.PathAny {
			rule.PathAny[j] = strings.ToLower(rule.PathAny[j])
		}
		for groupIndex := range rule.Groups {
			for needleIndex := range rule.Groups[groupIndex] {
				rule.Groups[groupIndex][needleIndex] = strings.ToLower(rule.Groups[groupIndex][needleIndex])
			}
		}
	}
}

func validateInputRoot(root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", root)
	}
	if _, err := os.ReadDir(root); err != nil {
		return err
	}
	return nil
}

func newScanStatus() ScanStatus {
	return ScanStatus{Complete: true}
}

func (status *ScanStatus) addReadError(path string, err error) {
	if err == nil {
		return
	}
	status.Complete = false
	status.ReadErrors++
	if len(status.ErrorSamples) < maxScanErrorSamples {
		status.ErrorSamples = append(status.ErrorSamples, fmt.Sprintf("%s: %v", sanitizePath(path), err))
	}
}

func (status *ScanStatus) markTruncated(reason string) {
	status.Complete = false
	status.Truncated = true
	if status.TruncateReason == "" {
		status.TruncateReason = reason
	}
}

func (status *ScanStatus) markIncomplete(reason string) {
	status.Complete = false
	if status.TruncateReason == "" {
		status.TruncateReason = reason
	}
}

func collectFilesDualStatus(root string) ([]FileBlob, []FileBlob, ScanStatus) {
	status := newScanStatus()
	candidates := make([]fileCandidate, 0, 256)

	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			status.addReadError(path, walkErr)
			if path == root {
				return walkErr
			}
			return nil
		}
		if entry == nil {
			status.addReadError(path, fmt.Errorf("empty directory entry"))
			return nil
		}
		if entry.IsDir() {
			if path != root && shouldSkipDir(entry.Name()) && shouldSkipDirV26(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		status.FilesVisited++
		if entry.Type()&os.ModeSymlink != 0 {
			status.FilesSkipped++
			status.SkippedSymlinks++
			status.markIncomplete("one or more symlinks were not followed")
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			status.FilesSkipped++
			status.addReadError(path, err)
			return nil
		}
		if info.Size() <= 0 {
			status.FilesSkipped++
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			status.FilesSkipped++
			status.addReadError(path, err)
			return nil
		}
		rel = filepath.ToSlash(rel)
		binaryCandidate := isExecutableBinaryPath(rel)
		if shouldSkipFile(rel) && !binaryCandidate {
			status.FilesSkipped++
			status.SkippedUnsupported++
			if isOpaqueExecutableOrArchive(rel) {
				status.SkippedOpaque++
				status.markIncomplete("opaque executable or archive content was skipped")
			}
			return nil
		}

		baseCandidate := !pathHasSkippedDir(rel, shouldSkipDir) && (isInterestingFile(rel) || binaryCandidate)
		explainCandidate := !pathHasSkippedDir(rel, shouldSkipDirV26) && (isInterestingFileV26(rel) || binaryCandidate)
		if !baseCandidate && !explainCandidate {
			status.FilesSkipped++
			status.SkippedUnsupported++
			return nil
		}
		if len(candidates) >= maxCandidateFiles {
			status.markTruncated(fmt.Sprintf("candidate file limit %d reached", maxCandidateFiles))
			return filepath.SkipAll
		}
		candidates = append(candidates, fileCandidate{
			Path:     path,
			Rel:      rel,
			Size:     info.Size(),
			Base:     baseCandidate,
			Explain:  explainCandidate,
			Priority: scanCandidatePriority(rel),
		})
		return nil
	})
	if walkErr != nil && status.ReadErrors == 0 {
		status.addReadError(root, walkErr)
	}

	// Security-sensitive metadata, package lifecycle files, CI configuration, and
	// source code consume the bounded budget before ordinary documentation. This
	// prevents filename ordering or documentation padding from starving key files.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority < candidates[j].Priority
		}
		return candidates[i].Rel < candidates[j].Rel
	})

	baseBlobs := make([]FileBlob, 0, minInt(len(candidates), maxBlobsPerSkill))
	explainBlobs := make([]FileBlob, 0, minInt(len(candidates), maxBlobsPerSkill))
	var baseTotal int64
	var explainTotal int64

	for index, candidate := range candidates {
		baseFull := len(baseBlobs) >= maxBlobsPerSkill || baseTotal >= maxTotalBytes
		explainFull := len(explainBlobs) >= maxBlobsPerSkill || explainTotal >= maxTotalBytes
		if baseFull && explainFull {
			status.FilesSkipped += len(candidates) - index
			status.markTruncated("all scan profiles exhausted their resource budgets")
			break
		}

		data, err := readFileSampled(candidate.Path, candidate.Size, maxFileBytes)
		if err != nil {
			status.FilesSkipped++
			status.addReadError(candidate.Rel, err)
			continue
		}
		if len(data) == 0 {
			status.FilesSkipped++
			status.markIncomplete("a supported file produced no readable content")
			continue
		}
		if candidate.Size > maxFileBytes {
			status.SampledFiles++
		}

		binaryCandidate := isExecutableBinaryPath(candidate.Rel)
		lower, ok := decodeTextLower(data)
		magic := ""
		if binaryCandidate {
			lower, ok = "", true
			magic = binaryMagicLabel(data)
		}
		if !ok {
			status.FilesSkipped++
			status.SkippedUnsupported++
			status.markIncomplete("a text-like candidate decoded as binary or unsupported content")
			continue
		}
		dataLen := int64(len(data))
		appended := false

		if candidate.Base {
			switch {
			case len(baseBlobs) >= maxBlobsPerSkill:
				status.markTruncated(fmt.Sprintf("base profile file limit %d reached", maxBlobsPerSkill))
			case baseTotal+dataLen > maxTotalBytes:
				status.markTruncated(fmt.Sprintf("base profile text limit %d bytes reached", maxTotalBytes))
			default:
				baseBlobs = append(baseBlobs, FileBlob{
					Rel:      candidate.Rel,
					Lower:    lower,
					IsDoc:    isDocPath(candidate.Rel),
					IsMeta:   isManifestPath(candidate.Rel),
					IsCode:   isCodePath(candidate.Rel),
					IsBinary: binaryCandidate,
					Magic:    magic,
					Size:     dataLen,
				})
				baseTotal += dataLen
				appended = true
			}
		}

		if candidate.Explain {
			switch {
			case len(explainBlobs) >= maxBlobsPerSkill:
				status.markTruncated(fmt.Sprintf("explain profile file limit %d reached", maxBlobsPerSkill))
			case explainTotal+dataLen > maxTotalBytes:
				status.markTruncated(fmt.Sprintf("explain profile text limit %d bytes reached", maxTotalBytes))
			default:
				explainBlobs = append(explainBlobs, FileBlob{
					Rel:      candidate.Rel,
					Lower:    lower,
					IsDoc:    isDocPath(candidate.Rel),
					IsMeta:   isManifestPath(candidate.Rel),
					IsCode:   isCodePathV26(candidate.Rel),
					IsBinary: binaryCandidate,
					Magic:    magic,
					Size:     dataLen,
				})
				explainTotal += dataLen
				appended = true
			}
		}

		if appended {
			status.FilesAnalyzed++
		} else {
			status.FilesSkipped++
		}
	}

	if status.FilesAnalyzed == 0 {
		status.markIncomplete("no supported file content was analyzed")
	}
	sort.Slice(baseBlobs, func(i, j int) bool { return baseBlobs[i].Rel < baseBlobs[j].Rel })
	sort.Slice(explainBlobs, func(i, j int) bool { return explainBlobs[i].Rel < explainBlobs[j].Rel })
	return baseBlobs, explainBlobs, status
}

func scanCandidatePriority(rel string) int {
	path := strings.ToLower(filepath.ToSlash(rel))
	base := filepath.Base(path)
	if isManifestPath(path) || isPackagePathV26(path) || isKnownTextConfigPath(path) ||
		base == "skill.md" || strings.HasSuffix(path, ".tf") ||
		strings.Contains(path, ".github/workflows/") || strings.Contains(path, ".vscode/") ||
		strings.Contains(path, ".cursor/") || strings.Contains(path, ".claude/") {
		return 0
	}
	if isCodePathV26(path) {
		return 1
	}
	if isDocPath(path) {
		return 2
	}
	return 3
}

func isOpaqueExecutableOrArchive(rel string) bool {
	lower := strings.ToLower(rel)
	for _, suffix := range []string{
		".zip", ".tar", ".gz", ".7z", ".exe", ".dll", ".so", ".dylib", ".class", ".wasm",
	} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func enforceScanCompleteness(report SkillReport, status ScanStatus) SkillReport {
	report.Scan = status
	if status.Complete {
		return report
	}

	warning := "scan incomplete: " + scanStatusSummary(status)
	if report.Verdict == "benign" || report.EngineCategory == "benign" || report.EngineCategory == "" {
		report.Verdict = "suspicious"
		report.EngineCategory = "ast08"
		if report.CategoryScore == nil {
			report.CategoryScore = map[string]float64{}
		}
		if report.CategoryScore["ast08"] < 2.5 {
			report.CategoryScore["ast08"] = 2.5
		}
		report.EvidenceText = truncateSentence("OWASP AST08 scanner completeness: "+warning+"; a benign verdict is not emitted for an incomplete scan.", 420)
		return report
	}

	report.EvidenceText = truncateSentence(warning+"; "+report.EvidenceText, 420)
	return report
}

func scanStatusSummary(status ScanStatus) string {
	parts := make([]string, 0, 6)
	if status.InternalError != "" {
		parts = append(parts, "internal scanner error")
	}
	if status.TruncateReason != "" {
		parts = append(parts, status.TruncateReason)
	}
	if status.ReadErrors > 0 {
		parts = append(parts, fmt.Sprintf("%d read error(s)", status.ReadErrors))
	}
	if status.SkippedSymlinks > 0 {
		parts = append(parts, fmt.Sprintf("%d symlink(s) skipped", status.SkippedSymlinks))
	}
	if status.SkippedOpaque > 0 {
		parts = append(parts, fmt.Sprintf("%d opaque file(s) skipped", status.SkippedOpaque))
	}
	if len(parts) == 0 {
		parts = append(parts, "the supported input surface was not fully scanned")
	}
	return strings.Join(parts, ", ")
}

func newScanMetadata(skillID string, status ScanStatus) ScanMetadata {
	return ScanMetadata{
		SkillID:            skillID,
		Complete:           status.Complete,
		Truncated:          status.Truncated,
		InternalError:      status.InternalError,
		FilesVisited:       status.FilesVisited,
		FilesAnalyzed:      status.FilesAnalyzed,
		FilesSkipped:       status.FilesSkipped,
		ReadErrors:         status.ReadErrors,
		SampledFiles:       status.SampledFiles,
		SkippedSymlinks:    status.SkippedSymlinks,
		SkippedOpaque:      status.SkippedOpaque,
		SkippedUnsupported: status.SkippedUnsupported,
		TruncateReason:     status.TruncateReason,
		ErrorSamples:       append([]string(nil), status.ErrorSamples...),
	}
}

func partialScansAllowed() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SKILLSCAN_ALLOW_PARTIAL"))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func countIncompleteScans(rows []ScanMetadata) int {
	count := 0
	for _, row := range rows {
		if !row.Complete {
			count++
		}
	}
	return count
}

func writeScanMetadata(outputDir string, rows []ScanMetadata) error {
	outPath := filepath.Join(outputDir, "scan-metadata.jsonl")
	tmpPath := outPath + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(out)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for _, row := range rows {
		if err := encoder.Encode(row); err != nil {
			_ = out.Close()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return commitResults(tmpPath, outPath)
}

func blendedScore(primary string, scores map[string]float64) float64 {
	blended := scores[primary]
	seen := make(map[string]struct{}, len(stableCategoryOrder))
	for _, category := range stableCategoryOrder {
		seen[category] = struct{}{}
		if category == primary {
			continue
		}
		blended += minFloat(scores[category], 4.0) * 0.18
	}

	// Future categories remain deterministic until stableCategoryOrder is updated.
	extra := make([]string, 0)
	for category := range scores {
		if _, known := seen[category]; !known && category != primary {
			extra = append(extra, category)
		}
	}
	sort.Strings(extra)
	for _, category := range extra {
		blended += minFloat(scores[category], 4.0) * 0.18
	}
	return blended
}

func structuredJSONCapability(content, capability string) (found, enabled bool) {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return false, false
	}
	var value any
	if err := json.Unmarshal([]byte(trimmed), &value); err != nil {
		return false, false
	}
	return inspectJSONCapability(value, normalizeCapability(capability), false)
}

func inspectJSONCapability(value any, target string, capabilityContext bool) (found, enabled bool) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := typed[key]
			normalizedKey := normalizeCapability(key)
			if normalizedKey == target {
				found = true
				if jsonCapabilityValueEnabled(child) {
					enabled = true
				}
			}
			childContext := capabilityContext || isCapabilityContainer(normalizedKey)
			childFound, childEnabled := inspectJSONCapability(child, target, childContext)
			found = found || childFound
			enabled = enabled || childEnabled
		}
	case []any:
		for _, child := range typed {
			if capabilityContext {
				if text, ok := child.(string); ok && normalizeCapability(text) == target {
					found = true
					enabled = true
				}
			}
			childFound, childEnabled := inspectJSONCapability(child, target, capabilityContext)
			found = found || childFound
			enabled = enabled || childEnabled
		}
	}
	return found, enabled
}

func jsonCapabilityValueEnabled(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case float64:
		return typed != 0
	case string:
		value := strings.ToLower(strings.TrimSpace(typed))
		switch value {
		case "", "false", "disabled", "deny", "denied", "none", "no", "off", "0":
			return false
		default:
			return true
		}
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return false
	}
}

func isCapabilityContainer(normalized string) bool {
	switch normalized {
	case "permission", "permissions", "capability", "capabilities", "scope", "scopes", "allowedpermissions", "requiredpermissions":
		return true
	default:
		return false
	}
}

func normalizeCapability(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("_", "", "-", "", ".", "", " ", "")
	return replacer.Replace(value)
}

func isRuleActiveMaterial(blob FileBlob) bool {
	path := strings.ToLower(blob.Rel)
	return blob.IsCode || blob.IsMeta || isPackagePath(path) || isKnownTextConfigPath(path) || isSkillFacingMaterial(blob)
}

func isBenignInstructionalContext(content string) bool {
	markers := []string{
		"for educational purposes", "security training", "malware analysis", "example only",
		"demo only", "test fixture", "unit test", "do not run", "do not execute",
		"benign example", "sample payload",
	}
	if !hasAny(content, markers) {
		return false
	}

	strongBehavior := []string{
		"requests.post", "requests.put", "axios.post", "fetch(", "curl ", "wget ",
		"| bash", "| sh", "source <(", "subprocess", "child_process", "os.system",
		"eval(", "exec(", "webhook", "send credentials", "upload secrets", "read .env",
		"id_rsa", "secret_access_key", "private key", "postinstall", "preinstall", "docker.sock",
	}
	narrative := []string{
		"discuss", "describe", "example", "sample", "training", "fixture", "mock", "inert",
		"illustrate", "demonstrate", "should detect", "no skill code", "does not execute", "do not run", "do not execute",
	}
	imperative := []string{
		"you must", "assistant must", "agent must", "when invoked", "before proceeding",
		"run this", "execute this", "paste into", "silently", "secretly", "| bash", "| sh", "source <(",
	}

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !hasAny(line, strongBehavior) {
			continue
		}
		if hasAny(line, markers) && hasAny(line, narrative) && !hasAny(line, imperative) {
			continue
		}
		return false
	}
	return true
}

func hasPinnedPrimaryFinding(report SkillReport) bool {
	needles := []string{
		"remote skill instruction execution", "agent memory persistence", "claude/cursor config-file hijack",
		"workspace spyware behavior", "mcp configuration launches", "hidden prompt payload",
		"clickfix-style social engineering", "browser extension credential bridge", "cloud metadata or localhost pivot",
		"prototype pollution or config injection", "invisible instruction smuggling", "hot-reload remote module",
		"scanner result tampering", "agent instruction credential exfiltration", "agent identity persistence",
		"websocket command channel", "local agent control hijack", "unsafe deserialization payload",
		"credential trap with outbound sink", "mcp/tool metadata prompt injection",
		"dependency confusion or mutable installer path", "known dependency-confusion or typosquat",
		"repository workflow/config executes", "bundled local binary", "startup or scheduled persistence",
		"cross-platform port appears", "agent instruction data exfiltration", "brand impersonation metadata",
		"project auto-run configuration hijack", "docker/build recipe pulls", "escaped payload evasion",
	}
	for _, finding := range report.Findings {
		if finding.Category == report.EngineCategory && hasAny(strings.ToLower(finding.Reason), needles) {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
