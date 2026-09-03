package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestResultContractRemainsFourFields(t *testing.T) {
	t.Parallel()
	data, err := json.Marshal(Result{
		SkillID:        "example",
		Verdict:        "malicious",
		EngineCategory: "ast01",
		EvidenceText:   "evidence",
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	want := []string{"engine_category", "evidence_text", "skill_id", "verdict"}
	got := make([]string, 0, len(decoded))
	for key := range decoded {
		got = append(got, key)
	}
	sortStrings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("result keys = %v, want %v", got, want)
	}
}

func TestWriteAnalysisMetadata(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rows := []AnalysisMetadata{{
		SkillID:          "example",
		TriggerLayer:     "base",
		TriggerScore:     5.1,
		TriggerCondition: "max_score_gte_4.65",
	}}
	if err := writeAnalysisMetadata(dir, rows); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "analysis-metadata.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatalf("missing metadata row: %v", scanner.Err())
	}
	var got AnalysisMetadata
	if err := json.Unmarshal(scanner.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.SkillID != "example" || got.TriggerLayer != "base" || got.TriggerScore != 5.1 {
		t.Fatalf("unexpected metadata: %+v", got)
	}
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
