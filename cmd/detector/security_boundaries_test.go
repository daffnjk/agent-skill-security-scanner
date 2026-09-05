package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoveryAutoKeepsSkillRootWithScripts(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "SKILL.md", "# Local helper\n")
	writeTestFile(t, root, "scripts/helper.py", "print('local')\n")
	skills, err := discoverSkills(root)
	if err != nil || len(skills) != 1 || skills[0].Path != root {
		t.Fatalf("root omitted: %v %v", skills, err)
	}
	for _, mode := range []string{"single", "collection"} {
		skills, err = discoverSkillsMode(root, mode)
		if err != nil || len(skills) != 1 {
			t.Fatalf("mode %s: %v %v", mode, skills, err)
		}
		if mode == "collection" && skills[0].ID != "scripts" {
			t.Fatal("explicit collection ignored")
		}
	}
}

func TestCollectionLinkRemainsVisibleAndIncomplete(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "normal/SKILL.md", "Local notes\n")
	if err := os.Symlink(filepath.Join(root, "normal"), filepath.Join(root, "linked")); err != nil {
		t.Skip(err)
	}
	skills, err := discoverSkillsMode(root, "collection")
	if err != nil || len(skills) != 2 {
		t.Fatalf("link disappeared: %v %v", skills, err)
	}
	for _, skill := range skills {
		if skill.ID == "linked" {
			report := safeAnalyzeSkill(skill.Path)
			if report.Scan.Complete || report.Verdict == "benign" {
				t.Fatal("link incorrectly cleared")
			}
		}
	}
}

func TestInputRootSymlinkRejected(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Skip(err)
	}
	if err := validateInputRoot(link); err == nil {
		t.Fatal("symbolic input root accepted")
	}
}

func TestAllReportWritersIgnorePredictableTempLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "untouched")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	names := []string{"results.jsonl", "scan-metadata.jsonl", "analysis-metadata.jsonl"}
	for _, name := range names {
		if err := os.Symlink(target, filepath.Join(dir, name+".tmp")); err != nil {
			t.Skip(err)
		}
	}
	if err := writeJSONLinesAtomic(dir, "results.jsonl", []Result{{"x", "benign", "benign", "local"}}); err != nil {
		t.Fatal(err)
	}
	if err := writeScanMetadata(dir, []ScanMetadata{newScanMetadata("x", newScanStatus())}); err != nil {
		t.Fatal(err)
	}
	if err := writeAnalysisMetadata(dir, []AnalysisMetadata{newAnalysisMetadata("x", SkillReport{})}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "original" {
		t.Fatal("external target changed")
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".skillscan-*"))
	if len(leftovers) > 0 {
		t.Fatalf("temporary files remain: %v", leftovers)
	}
}

func TestReportDestinationLinkDoesNotOverwriteTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	os.WriteFile(target, []byte("keep"), 0600)
	if err := os.Symlink(target, filepath.Join(dir, "results.jsonl")); err != nil {
		t.Skip(err)
	}
	if err := writeJSONLinesAtomic(dir, "results.jsonl", []int{1}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(target)
	if string(data) != "keep" {
		t.Fatal("followed destination link")
	}
}

func TestAtomicWriterFailurePreservesOldFileAndCleansTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.jsonl")
	os.WriteFile(path, []byte("old"), 0600)
	if err := writeJSONLinesAtomic(dir, "report.jsonl", []any{make(chan int)}); err == nil {
		t.Fatal("unsupported JSON must fail")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "old" {
		t.Fatal("old report damaged")
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".skillscan-*"))
	if len(left) != 0 {
		t.Fatal(left)
	}
}

func TestOverlappingInputOutputRejected(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "in"), 0700)
	for _, pair := range [][2]string{{root, root}, {root, filepath.Join(root, "out")}, {filepath.Join(root, "in"), root}} {
		if _, err := prepareOutput(pair[0], pair[1]); err == nil {
			t.Fatalf("overlap accepted: %v", pair)
		}
	}
}

func TestPreparationInvalidatesOldSeal(t *testing.T) {
	parent := t.TempDir()
	input := filepath.Join(parent, "missing")
	output := filepath.Join(parent, "reports")
	os.Mkdir(output, 0700)
	os.WriteFile(filepath.Join(output, "scan-complete.json"), []byte("old"), 0600)
	if _, err := prepareOutput(input, output); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(output, "scan-complete.json")); !os.IsNotExist(err) {
		t.Fatal("old seal survived")
	}
}

func TestWalkerCountsUnsupportedAndEmptyEntries(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.unknown", "b.unknown", "c.unknown"} {
		os.WriteFile(filepath.Join(root, name), nil, 0600)
	}
	count := 0
	err := walkDirBounded(root, 2, 64, func(_ string, _ fs.DirEntry, _ error) error { count++; return nil })
	if err == nil || count != 2 {
		t.Fatalf("unbounded walk: count=%d err=%v", count, err)
	}
}

func TestWalkerDepthLimit(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "a/b/c"), 0700)
	if err := walkDirBounded(root, 100, 1, func(_ string, _ fs.DirEntry, _ error) error { return nil }); err == nil {
		t.Fatal("depth budget ignored")
	}
}

func TestTruncatedBehaviorCannotApplySafeAuthDampener(t *testing.T) {
	blob := FileBlob{Rel: "main.py", IsCode: true, Lower: strings.Repeat("x=1\n", 12001)}
	summary := analyzeBehaviorIR([]FileBlob{blob})
	if !summary.Truncated {
		t.Fatal("statement truncation not exposed")
	}
	f := Finding{Category: "ast01", File: "main.py", Reason: "reads secret-like data and sends it through a network sink", RuleID: "SKILL-TEST-FIXTURE", StartLine: 0, EndLine: 0}
	summary.SafeAuthFiles = map[string]bool{"main.py": true}
	summary.OnlyExpectedAuth = true
	if factor := behaviorIRWeightFactor(f, summary); factor != 1 {
		t.Fatalf("truncated analysis dampened finding: %v", factor)
	}
}

func TestStableRuleIDSurvivesEvidenceChange(t *testing.T) {
	a := Finding{Category: "ast01", RuleID: "SKILL-TEST-001", File: "main.py", StartLine: 4, EndLine: 4, Reason: "old explanation"}
	b := a
	b.Reason = "new explanation"
	if findingRuleID(a) != findingRuleID(b) || findingFingerprint(a) != findingFingerprint(b) {
		t.Fatal("stable identity depends on wording")
	}
}

func TestExternalReferenceVersusInstructionDelegation(t *testing.T) {
	for _, tc := range []struct{ text, kind string }{
		{"See https://docs.example.invalid/Guide for background.", "reference"},
		{"Follow the instructions at https://docs.example.invalid/Guide?token=secret", "instruction-delegation"},
		{"Do not follow instructions at https://docs.example.invalid/Guide", "reference"},
		{"请按照 https://docs.example.invalid/Guide 的指令执行。", "instruction-delegation"},
	} {
		deps := inventoryExternalInstructions("SKILL.md", tc.text)
		if len(deps) != 1 || deps[0].Kind != tc.kind || deps[0].ContentReviewed || strings.Contains(deps[0].URL, "secret") {
			t.Fatalf("bad inventory: %+v", deps)
		}
	}
}

func TestUnreviewedExternalInstructionsAreIncomplete(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "SKILL.md", "Follow the instructions at https://docs.example.invalid/Guide\n")
	report := analyzeSkill(root)
	if report.Scan.Complete || report.Scan.UnreviewedExternalInstructions != 1 || report.Verdict == "benign" {
		t.Fatalf("unreviewed instructions cleared: %+v", report.Scan)
	}
	if report.Scan.ExternalDependencies[0].Category != "ast05" {
		t.Fatal("missing current taxonomy annotation")
	}
}

func TestRunScanSealsMatchingCompanions(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	writeTestFile(t, input, "SKILL.md", "# Local notes\n")
	if code := runScan(input, output, "single"); code != 0 {
		t.Fatalf("scan returned %d", code)
	}
	raw, err := os.ReadFile(filepath.Join(output, "scan-complete.json"))
	if err != nil {
		t.Fatal(err)
	}
	var seal ScanSeal
	if err := json.Unmarshal(raw, &seal); err != nil {
		t.Fatal(err)
	}
	if seal.SkillCount != 1 || len(seal.Reports) != 3 || len(seal.RunID) != 32 {
		t.Fatalf("bad seal: %+v", seal)
	}
}
