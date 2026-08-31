#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_between(text: str, start: str, end: str, replacement: str) -> str:
    start_index = text.index(start)
    end_index = text.index(end, start_index)
    return text[:start_index] + replacement.rstrip() + "\n\n" + text[end_index:]


def replace_exact(text: str, old: str, new: str, *, expected: int = 1) -> str:
    actual = text.count(old)
    if actual != expected:
        raise RuntimeError(f"expected {expected} occurrences, found {actual}: {old[:100]!r}")
    return text.replace(old, new)


def replace_in_span(text: str, start: str, end: str, old: str, new: str, *, expected: int = 1) -> str:
    start_index = text.index(start)
    end_index = text.index(end, start_index)
    segment = text[start_index:end_index]
    segment = replace_exact(segment, old, new, expected=expected)
    return text[:start_index] + segment + text[end_index:]


main_path = ROOT / "cmd/detector/main.go"
text = main_path.read_text()
text = replace_exact(text, '\t"io/fs"\n', "", expected=1)

text = replace_between(
    text,
    "type SkillReport struct {",
    "\n\nconst (",
    '''type SkillReport struct {
\tVerdict        string
\tEngineCategory string
\tEvidenceText   string
\tFindings       []Finding
\tCategoryScore  map[string]float64
\tScan           ScanStatus
}''',
)

text = replace_between(
    text,
    "func main() {",
    "func safeAnalyzeSkill",
    '''func main() {
\tinputDir := getenv("SKILLS_DIR", defaultInputDir)
\toutputDir := getenv("OUTPUT_DIR", defaultOutputDir)
\tif len(os.Args) >= 2 && os.Args[1] != "" {
\t\tinputDir = os.Args[1]
\t}
\tif len(os.Args) >= 3 && os.Args[2] != "" {
\t\toutputDir = os.Args[2]
\t}
\tif err := validateInputRoot(inputDir); err != nil {
\t\tfail("validate input dir", err)
\t}
\tif err := os.MkdirAll(outputDir, 0o755); err != nil {
\t\tfail("create output dir", err)
\t}
\toutPath := filepath.Join(outputDir, "results.jsonl")
\ttmpPath := outPath + ".tmp"
\tout, err := os.Create(tmpPath)
\tif err != nil {
\t\tfail("create results.jsonl.tmp", err)
\t}
\twriter := bufio.NewWriter(out)

\tskills, err := discoverSkills(inputDir)
\tif err != nil {
\t\tfail("discover skills", err)
\t}
\tmetadataRows := make([]ScanMetadata, 0, len(skills))
\tenc := json.NewEncoder(writer)
\tenc.SetEscapeHTML(false)
\tfor _, skill := range skills {
\t\treport := safeAnalyzeSkill(skill.Path)
\t\tmetadataRows = append(metadataRows, newScanMetadata(skill.ID, report.Scan))
\t\tres := Result{
\t\t\tSkillID:        skill.ID,
\t\t\tVerdict:        report.Verdict,
\t\t\tEngineCategory: report.EngineCategory,
\t\t\tEvidenceText:   report.EvidenceText,
\t\t}
\t\tif err := enc.Encode(res); err != nil {
\t\t\tfail("write result", err)
\t\t}
\t}
\tif err := writer.Flush(); err != nil {
\t\tfail("flush results.jsonl", err)
\t}
\tif err := out.Close(); err != nil {
\t\tfail("close results.jsonl.tmp", err)
\t}
\tif err := commitResults(tmpPath, outPath); err != nil {
\t\tfail("commit results.jsonl", err)
\t}
\tif err := writeScanMetadata(outputDir, metadataRows); err != nil {
\t\tfail("write scan-metadata.jsonl", err)
\t}

\tif incomplete := countIncompleteScans(metadataRows); incomplete > 0 && !partialScansAllowed() {
\t\t_, _ = fmt.Fprintf(os.Stderr, "scan incomplete: %d skill(s); see %s\\n", incomplete, filepath.Join(outputDir, "scan-metadata.jsonl"))
\t\tos.Exit(incompleteScanExitCode)
\t}
}''',
)

text = replace_between(
    text,
    "func safeAnalyzeSkill",
    "func confidenceFor",
    '''func safeAnalyzeSkill(root string) (report SkillReport) {
\tdefer func() {
\t\tif recovered := recover(); recovered != nil {
\t\t\tstatus := newScanStatus()
\t\t\tstatus.InternalError = fmt.Sprint(recovered)
\t\t\tstatus.markIncomplete("internal scanner error")
\t\t\treport = SkillReport{
\t\t\t\tVerdict:        "suspicious",
\t\t\t\tEngineCategory: "ast08",
\t\t\t\tEvidenceText:   fmt.Sprintf("OWASP AST08 scanner failure: an internal scanner error occurred while processing %s; the target was not classified as benign.", sanitizePath(filepath.Base(root))),
\t\t\t\tCategoryScore:  map[string]float64{"ast08": 2.5},
\t\t\t\tScan:           status,
\t\t\t}
\t\t}
\t}()
\treturn analyzeSkill(root)
}''',
)

text = replace_between(
    text,
    "func discoverSkills",
    "func analyzeSkill",
    '''func discoverSkills(input string) ([]skillPath, error) {
\tentries, err := os.ReadDir(input)
\tif err != nil {
\t\treturn nil, err
\t}
\tvar out []skillPath
\tfor _, entry := range entries {
\t\tif !entry.IsDir() {
\t\t\tcontinue
\t\t}
\t\tname := entry.Name()
\t\tif strings.HasPrefix(name, ".") {
\t\t\tcontinue
\t\t}
\t\tout = append(out, skillPath{ID: name, Path: filepath.Join(input, name)})
\t}
\tif len(out) == 0 {
\t\tout = append(out, skillPath{ID: filepath.Base(filepath.Clean(input)), Path: input})
\t}
\tsort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
\treturn out, nil
}''',
)

text = replace_between(
    text,
    "func analyzeSkill(root string) SkillReport {",
    "func analyzeSkillV25",
    '''func analyzeSkill(root string) SkillReport {
\tbaseBlobs, explainBlobs, status := collectFilesDualStatus(root)
\tbase := analyzeSkillV25FromBlobs(baseBlobs)
\tresult := base

\tif base.Verdict == "benign" {
\t\texplain := analyzeSkillV26ExplainFromBlobs(explainBlobs)
\t\tif shouldPromoteFromExplain(explain) {
\t\t\tresult = explain
\t\t}
\t\treturn enforceScanCompleteness(result, status)
\t}

\t// Keep high-confidence primary findings without coupling control flow to the
\t// rendered evidence text.
\tif hasPinnedPrimaryFinding(base) {
\t\treturn enforceScanCompleteness(base, status)
\t}

\texplain := analyzeSkillV26ExplainFromBlobs(explainBlobs)
\tif explain.EngineCategory != "" && explain.EngineCategory != "benign" && explain.Verdict != "benign" {
\t\tbase.EngineCategory = explain.EngineCategory
\t\tbase.EvidenceText = explain.EvidenceText
\t\tif len(explain.CategoryScore) > 0 {
\t\t\tbase.CategoryScore = explain.CategoryScore
\t\t}
\t\tif len(explain.Findings) > 0 {
\t\t\tbase.Findings = explain.Findings
\t\t}
\t}
\treturn enforceScanCompleteness(base, status)
}''',
)

text = replace_between(
    text,
    "func analyzeSkillV25(root string) SkillReport {",
    "func analyzeSkillV25FromBlobs",
    '''func analyzeSkillV25(root string) SkillReport {
\tbase, _, status := collectFilesDualStatus(root)
\treturn enforceScanCompleteness(analyzeSkillV25FromBlobs(base), status)
}''',
)

text = replace_between(
    text,
    "func collectFiles(root string) []FileBlob {",
    "func collectFilesDual",
    '''func collectFiles(root string) []FileBlob {
\tbase, _, _ := collectFilesDualStatus(root)
\treturn base
}''',
)

text = replace_between(
    text,
    "func collectFilesDual(root string) ([]FileBlob, []FileBlob) {",
    "func analyzeFile",
    '''func collectFilesDual(root string) ([]FileBlob, []FileBlob) {
\tbase, explain, _ := collectFilesDualStatus(root)
\treturn base, explain
}''',
)

old_blended = '''\tblended := maxScore
\tfor cat, sc := range scores {
\t\tif cat == category {
\t\t\tcontinue
\t\t}
\t\tblended += minFloat(sc, 4.0) * 0.18
\t}'''
text = replace_exact(text, old_blended, "\tblended := blendedScore(category, scores)", expected=2)

text = replace_between(
    text,
    "func analyzeLoop16To115File",
    "func analyzeLoop16To115CrossFile",
    '''func analyzeLoop16To115File(blob FileBlob) []Finding {
\tcontent := blob.Lower
\tif content == "" {
\t\treturn nil
\t}
\tpath := strings.ToLower(blob.Rel)
\tactive := isRuleActiveMaterial(blob)
\tout := make([]Finding, 0, 8)
\tfor _, rule := range loop16To115Rules {
\t\tif rule.ActiveOnly && !active {
\t\t\tcontinue
\t\t}
\t\tif len(rule.PathAny) > 0 && !hasAny(path, rule.PathAny) {
\t\t\tcontinue
\t\t}
\t\tif rule.SuppressInstructionalDocs && blob.IsDoc && benignInstructionalContext(content) {
\t\t\tcontinue
\t\t}
\t\tmatched := true
\t\tfor _, group := range rule.Groups {
\t\t\tif !hasAny(content, group) {
\t\t\t\tmatched = false
\t\t\t\tbreak
\t\t\t}
\t\t}
\t\tif matched {
\t\t\tout = append(out, Finding{rule.Category, rule.Weight, blob.Rel, fmt.Sprintf("loop%d: %s", rule.Loop, rule.Reason), rule.Strong})
\t\t}
\t}
\tsort.SliceStable(out, func(i, j int) bool {
\t\tif out[i].Strong != out[j].Strong {
\t\t\treturn out[i].Strong
\t\t}
\t\tif out[i].Weight != out[j].Weight {
\t\t\treturn out[i].Weight > out[j].Weight
\t\t}
\t\tif out[i].Category != out[j].Category {
\t\t\treturn out[i].Category < out[j].Category
\t\t}
\t\treturn out[i].Reason < out[j].Reason
\t})
\tif len(out) > 6 {
\t\tout = out[:6]
\t}
\treturn out
}''',
)

text = replace_in_span(
    text,
    "func analyzeLoop16To115CrossFile",
    "func openClawCampaignIndicator",
    "\t\tif b.IsCode || b.IsMeta || isPackagePath(b.Rel) || isKnownTextConfigPath(b.Rel) {",
    "\t\tif isRuleActiveMaterial(b) {",
)

text = replace_between(
    text,
    "func benignInstructionalContext(c string) bool {",
    "func isV31PrimaryEvidence",
    '''func benignInstructionalContext(c string) bool {
\treturn isBenignInstructionalContext(c)
}''',
)

text = replace_exact(
    text,
    "\tsort.Slice(arr, func(i, j int) bool { return arr[i].V > arr[j].V })",
    '''\tsort.Slice(arr, func(i, j int) bool {
\t\tif arr[i].V != arr[j].V {
\t\t\treturn arr[i].V > arr[j].V
\t\t}
\t\treturn arr[i].K < arr[j].K
\t})''',
)

text = replace_between(
    text,
    "func manifestCapabilityEnabled(c, cap string) bool {",
    "func manifestDangerousPrivilege",
    '''func manifestCapabilityEnabled(c, cap string) bool {
\ttrimmed := strings.TrimSpace(c)
\tif (strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")) && json.Valid([]byte(trimmed)) {
\t\t_, enabled := structuredJSONCapability(trimmed, cap)
\t\treturn enabled
\t}

\tdisabled := []string{"\\\"" + cap + "\\\":false", "\\\"" + cap + "\\\": false", cap + ": false", cap + "=false", "'" + cap + "': false", "'" + cap + "':false"}
\tif hasAny(c, disabled) {
\t\treturn false
\t}
\tenabled := []string{"\\\"" + cap + "\\\":true", "\\\"" + cap + "\\\": true", cap + ": true", cap + "=true", "'" + cap + "': true", "'" + cap + "':true", "\\\"" + cap + "\\\"", "'" + cap + "'", "- " + cap}
\treturn hasAny(c, enabled)
}''',
)

text = replace_between(
    text,
    "func readFileSampled(path string, size, limit int64) ([]byte, error) {",
    "func decodeTextLower",
    '''func readFileSampled(path string, size, limit int64) ([]byte, error) {
\tif limit <= 0 {
\t\treturn nil, fmt.Errorf("invalid sample limit %d", limit)
\t}
\tfile, err := os.Open(path)
\tif err != nil {
\t\treturn nil, err
\t}
\tdefer file.Close()
\tif size <= 0 || size <= limit {
\t\treturn io.ReadAll(io.LimitReader(file, limit))
\t}
\theadLimit := limit / 2
\ttailLimit := limit - headLimit
\thead, err := io.ReadAll(io.LimitReader(file, headLimit))
\tif err != nil {
\t\treturn nil, err
\t}
\tif _, err := file.Seek(size-tailLimit, io.SeekStart); err != nil {
\t\treturn nil, fmt.Errorf("seek sampled tail: %w", err)
\t}
\ttail, err := io.ReadAll(io.LimitReader(file, tailLimit))
\tif err != nil {
\t\treturn nil, fmt.Errorf("read sampled tail: %w", err)
\t}
\tout := make([]byte, 0, len(head)+len(tail)+32)
\tout = append(out, head...)
\tout = append(out, '\\n', '[', '.', '.', '.', 's', 'n', 'i', 'p', '.', '.', '.', ']', '\\n')
\tout = append(out, tail...)
\treturn out, nil
}''',
)

text = replace_exact(text, '".desktop", ".reg"}', '".desktop", ".reg", ".tf"}', expected=2)

text = replace_between(
    text,
    "func analyzeSkillV26Explain(root string) SkillReport {",
    "func analyzeSkillV26ExplainFromBlobs",
    '''func analyzeSkillV26Explain(root string) SkillReport {
\t_, explain, status := collectFilesDualStatus(root)
\treturn enforceScanCompleteness(analyzeSkillV26ExplainFromBlobs(explain), status)
}''',
)

text = replace_between(
    text,
    "func collectFilesV26(root string) []FileBlob {",
    "func analyzeFileV26",
    '''func collectFilesV26(root string) []FileBlob {
\t_, explain, _ := collectFilesDualStatus(root)
\treturn explain
}''',
)

main_path.write_text(text)
