package v39

import "time"

const Version = "v39-overlay-1"

// Limits bounds every operation performed by the v39 overlay. The overlay never
// executes target code and does not access URLs referenced by a Skill.
type Limits struct {
	MaxCandidateFiles          int
	MaxFilesPerSkill           int
	MaxFileBytes               int64
	MaxSkillBytes              int64
	MaxDecodeDepth             int
	MaxDecodedVariantsPerFile  int
	MaxDecodedBytesPerFile     int64
	MaxDecodedVariantsPerSkill int
	MaxDecodedBytesPerSkill    int64
	MaxFactsPerSkill           int
	MaxArchiveBytes            int64
	MaxArchiveExpandedBytes    int64
	MaxArchiveEntries          int
	MaxArchiveDepth            int
	MaxCompressionRatio        int64
}

func DefaultLimits() Limits {
	return Limits{
		MaxCandidateFiles:          32768,
		MaxFilesPerSkill:           4096,
		MaxFileBytes:               1 << 20,
		MaxSkillBytes:              24 << 20,
		MaxDecodeDepth:             2,
		MaxDecodedVariantsPerFile:  12,
		MaxDecodedBytesPerFile:     2 << 20,
		MaxDecodedVariantsPerSkill: 4096,
		MaxDecodedBytesPerSkill:    16 << 20,
		MaxFactsPerSkill:           8192,
		MaxArchiveBytes:            8 << 20,
		MaxArchiveExpandedBytes:    8 << 20,
		MaxArchiveEntries:          256,
		MaxArchiveDepth:            2,
		MaxCompressionRatio:        50,
	}
}

type BaseResult struct {
	SkillID        string `json:"skill_id"`
	Verdict        string `json:"verdict"`
	EngineCategory string `json:"engine_category"`
	EvidenceText   string `json:"evidence_text"`
}

type Material struct {
	Path        string
	Text        string
	Origin      string
	Depth       int
	Decoded     bool
	FromArchive bool
}

type FactKind string

const (
	FactSecretSource      FactKind = "secret-source"
	FactWorkspaceSource   FactKind = "workspace-source"
	FactOutboundSink      FactKind = "outbound-sink"
	FactRemoteFetch       FactKind = "remote-fetch"
	FactCommandExec       FactKind = "command-exec"
	FactInstallTrigger    FactKind = "install-trigger"
	FactUnsafeDeserialize FactKind = "unsafe-deserialize"
	FactUntrustedInput    FactKind = "untrusted-input"
	FactDynamicLoad       FactKind = "dynamic-load"
	FactUpdateTrigger     FactKind = "update-trigger"
	FactHostControl       FactKind = "host-control"
	FactHiddenPrompt      FactKind = "hidden-prompt"
	FactSafeClaim         FactKind = "safe-claim"
	FactBroadPermission   FactKind = "broad-permission"
	FactPersistence       FactKind = "persistence"
	FactObfuscation       FactKind = "obfuscation"
)

type Fact struct {
	Kind        FactKind `json:"kind"`
	Path        string   `json:"path"`
	Detail      string   `json:"detail"`
	Executable  bool     `json:"executable"`
	Instruction bool     `json:"instruction"`
	Decoded     bool     `json:"decoded"`
	Archive     bool     `json:"archive"`
	Strong      bool     `json:"strong"`
}

type Chain struct {
	Name       string
	Verdict    string
	Category   string
	Confidence float64
	Facts      []Fact
}

type ScanStats struct {
	Complete        bool     `json:"complete"`
	FilesVisited    int      `json:"files_visited"`
	CandidateFiles  int      `json:"candidate_files"`
	FilesAnalyzed   int      `json:"files_analyzed"`
	SampledFiles    int      `json:"sampled_files"`
	BytesRead       int64    `json:"bytes_read"`
	DecodedVariants int      `json:"decoded_variants"`
	DecodedBytes    int64    `json:"decoded_bytes"`
	FactsExtracted  int      `json:"facts_extracted"`
	ArchiveEntries  int      `json:"archive_entries"`
	ArchiveBytes    int64    `json:"archive_expanded_bytes"`
	SkippedSymlinks int      `json:"skipped_symlinks"`
	ReadErrors      int      `json:"read_errors"`
	Truncated       bool     `json:"truncated"`
	Reasons         []string `json:"reasons,omitempty"`
}

type OverlayResult struct {
	SkillID       string    `json:"skill_id"`
	Version       string    `json:"version"`
	Verdict       string    `json:"verdict"`
	Category      string    `json:"category"`
	Evidence      string    `json:"evidence"`
	Confidence    float64   `json:"confidence"`
	Facts         []Fact    `json:"facts,omitempty"`
	Stats         ScanStats `json:"stats"`
	DurationMilli int64     `json:"duration_ms"`
	ScannedAt     time.Time `json:"scanned_at"`
}

func newStats() ScanStats {
	return ScanStats{Complete: true}
}

func (s *ScanStats) markIncomplete(reason string) {
	s.Complete = false
	if reason == "" {
		return
	}
	for _, existing := range s.Reasons {
		if existing == reason {
			return
		}
	}
	if len(s.Reasons) < 8 {
		s.Reasons = append(s.Reasons, reason)
	}
}

func (s *ScanStats) markTruncated(reason string) {
	s.Truncated = true
	s.markIncomplete(reason)
}
