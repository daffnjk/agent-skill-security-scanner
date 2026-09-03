package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
)

// AnalysisMetadata keeps v41 scoring and trigger diagnostics separate from the
// stable four-field results.jsonl contract used by existing integrations.
type AnalysisMetadata struct {
	SkillID          string             `json:"skill_id"`
	TriggerLayer     string             `json:"trigger_layer,omitempty"`
	TriggerScore     float64            `json:"trigger_score,omitempty"`
	TriggerCondition string             `json:"trigger_condition,omitempty"`
	TriggerFindings  []FindingAudit     `json:"trigger_findings,omitempty"`
	CategoryScores   map[string]float64 `json:"category_scores,omitempty"`
	ExplainCategory  string             `json:"explain_category,omitempty"`
	ExplainEvidence  string             `json:"explain_evidence,omitempty"`
}

func newAnalysisMetadata(skillID string, report SkillReport) AnalysisMetadata {
	return AnalysisMetadata{
		SkillID:          skillID,
		TriggerLayer:     report.TriggerLayer,
		TriggerScore:     report.TriggerScore,
		TriggerCondition: report.TriggerCondition,
		TriggerFindings:  report.TriggerFindings,
		CategoryScores:   report.CategoryScore,
		ExplainCategory:  report.ExplainCategory,
		ExplainEvidence:  report.ExplainEvidence,
	}
}

func writeAnalysisMetadata(outputDir string, rows []AnalysisMetadata) error {
	outPath := filepath.Join(outputDir, "analysis-metadata.jsonl")
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
