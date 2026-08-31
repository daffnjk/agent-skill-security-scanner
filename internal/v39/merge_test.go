package v39

import (
	"os"
	"testing"
)

func TestMergePromotesBenignBase(t *testing.T) {
	base := BaseResult{SkillID: "x", Verdict: "benign", EngineCategory: "benign", EvidenceText: "clean"}
	overlay := OverlayResult{SkillID: "x", Verdict: "malicious", Category: "ast01", Evidence: "graph", Confidence: 0.99}
	got := Merge(base, overlay)
	if got.Verdict != "malicious" || got.EngineCategory != "ast01" || got.EvidenceText != "graph" {
		t.Fatalf("unexpected merge: %+v", got)
	}
}

func TestMergeCorrectsModifierCategoryForExecutableOutcome(t *testing.T) {
	base := BaseResult{SkillID: "x", Verdict: "malicious", EngineCategory: "ast08", EvidenceText: "encoded"}
	overlay := OverlayResult{
		SkillID: "x", Verdict: "malicious", Category: "ast01", Evidence: "source to sink", Confidence: 0.99,
		Facts: []Fact{{Kind: FactSecretSource, Executable: true, Strong: true}, {Kind: FactOutboundSink, Executable: true, Strong: true}},
	}
	got := Merge(base, overlay)
	if got.EngineCategory != "ast01" {
		t.Fatalf("expected AST01 override, got %+v", got)
	}
}

func TestMergeKeepsAST04ForInstructionOnlyPrompt(t *testing.T) {
	base := BaseResult{SkillID: "x", Verdict: "malicious", EngineCategory: "ast04", EvidenceText: "prompt"}
	overlay := OverlayResult{
		SkillID: "x", Verdict: "malicious", Category: "ast01", Evidence: "instruction", Confidence: 0.99,
		Facts: []Fact{{Kind: FactSecretSource, Instruction: true}, {Kind: FactOutboundSink, Instruction: true}},
	}
	got := Merge(base, overlay)
	if got.EngineCategory != "ast04" {
		t.Fatalf("instruction-only prompt must keep AST04, got %+v", got)
	}
}

func TestMergePreservesExactSchemaFields(t *testing.T) {
	rows := []BaseResult{{SkillID: "x", Verdict: "benign", EngineCategory: "benign", EvidenceText: "clean"}}
	dir := t.TempDir()
	if err := WriteResultsAtomic(dir, rows); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadResults(dir + "/results.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0] != rows[0] {
		t.Fatalf("round trip mismatch: %+v", loaded)
	}
}

func TestMergeMissingBaseRowFailsClosed(t *testing.T) {
	overlay := OverlayResult{SkillID: "missing", Verdict: "benign", Category: "benign", Evidence: "no chain"}
	got := Merge(BaseResult{}, overlay)
	if got.Verdict != "suspicious" || got.EngineCategory != "ast08" {
		t.Fatalf("missing base row must fail closed: %+v", got)
	}
}

func TestReadResultsRejectsDuplicateSkillID(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/results.jsonl"
	body := "{\"skill_id\":\"x\",\"verdict\":\"benign\",\"engine_category\":\"benign\",\"evidence_text\":\"a\"}\n" +
		"{\"skill_id\":\"x\",\"verdict\":\"malicious\",\"engine_category\":\"ast01\",\"evidence_text\":\"b\"}\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadResults(path); err == nil {
		t.Fatal("expected duplicate skill_id error")
	}
}
