package main

// AnalysisMetadata is additive; results.jsonl retains its four-field contract.
type AnalysisMetadata struct {
	SchemaVersion        int                             `json:"schema_version"`
	RunID                string                          `json:"run_id"`
	SkillID              string                          `json:"skill_id"`
	Scanner              ScannerIdentity                 `json:"scanner"`
	InputDigest          string                          `json:"input_digest,omitempty"`
	InputDigestScope     string                          `json:"input_digest_scope"`
	Coverage             Coverage                        `json:"coverage"`
	ExternalDependencies []ExternalInstructionDependency `json:"external_dependencies,omitempty"`
	TriggerLayer         string                          `json:"trigger_layer,omitempty"`
	TriggerScore         float64                         `json:"trigger_score,omitempty"`
	TriggerCondition     string                          `json:"trigger_condition,omitempty"`
	TriggerFindings      []FindingAudit                  `json:"trigger_findings,omitempty"`
	CategoryScores       map[string]float64              `json:"category_scores,omitempty"`
	ExplainCategory      string                          `json:"explain_category,omitempty"`
	ExplainEvidence      string                          `json:"explain_evidence,omitempty"`
}

func newAnalysisMetadata(skillID string, report SkillReport) AnalysisMetadata {
	return AnalysisMetadata{
		SchemaVersion: 2, SkillID: skillID, Scanner: currentScannerIdentity(), InputDigest: report.Scan.InputDigest, InputDigestScope: "supported-read-bytes-v1", Coverage: report.Scan.Coverage,
		ExternalDependencies: report.Scan.ExternalDependencies,
		TriggerLayer:         report.TriggerLayer, TriggerScore: report.TriggerScore, TriggerCondition: report.TriggerCondition, TriggerFindings: report.TriggerFindings,
		CategoryScores: report.CategoryScore, ExplainCategory: report.ExplainCategory, ExplainEvidence: report.ExplainEvidence,
	}
}

func writeAnalysisMetadata(outputDir string, rows []AnalysisMetadata) error {
	return writeJSONLinesAtomic(outputDir, "analysis-metadata.jsonl", rows)
}
