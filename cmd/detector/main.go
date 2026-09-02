package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf16"
)

type Result struct {
	SkillID        string `json:"skill_id"`
	Verdict        string `json:"verdict"`
	EngineCategory string `json:"engine_category"`
	EvidenceText   string `json:"evidence_text"`
}

type FindingAudit struct {
	RuleID   string  `json:"rule_id"`
	Category string  `json:"category"`
	Weight   float64 `json:"weight"`
	File     string  `json:"file"`
	Reason   string  `json:"reason"`
	Strong   bool    `json:"strong"`
}

type Finding struct {
	Category string
	Weight   float64
	File     string
	Reason   string
	Strong   bool
}

type FileBlob struct {
	Rel      string
	Lower    string
	IsDoc    bool
	IsMeta   bool
	IsCode   bool
	IsBinary bool
	Magic    string
	Size     int64
}

type SkillReport struct {
	Verdict          string
	EngineCategory   string
	EvidenceText     string
	Findings         []Finding
	CategoryScore    map[string]float64
	TriggerLayer     string
	TriggerScore     float64
	TriggerCondition string
	TriggerFindings  []FindingAudit
	ExplainCategory  string
	ExplainEvidence  string
	Scan             ScanStatus
}

const (
	defaultInputDir  = "/data/skills"
	defaultOutputDir = "/output"
	maxFileBytes     = 1024 * 1024
	maxTotalBytes    = 24 * 1024 * 1024
	maxBlobsPerSkill = 4096
)

func main() {
	inputDir := getenv("SKILLS_DIR", defaultInputDir)
	outputDir := getenv("OUTPUT_DIR", defaultOutputDir)
	if len(os.Args) >= 2 && os.Args[1] != "" {
		inputDir = os.Args[1]
	}
	if len(os.Args) >= 3 && os.Args[2] != "" {
		outputDir = os.Args[2]
	}
	if err := validateInputRoot(inputDir); err != nil {
		fail("validate input dir", err)
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fail("create output dir", err)
	}
	outPath := filepath.Join(outputDir, "results.jsonl")
	tmpPath := outPath + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		fail("create results.jsonl.tmp", err)
	}
	writer := bufio.NewWriter(out)

	skills, err := discoverSkills(inputDir)
	if err != nil {
		fail("discover skills", err)
	}
	metadataRows := make([]ScanMetadata, 0, len(skills))
	auditRows := make([]AnalysisMetadata, 0, len(skills))
	enc := json.NewEncoder(writer)
	enc.SetEscapeHTML(false)
	for _, skill := range skills {
		report := safeAnalyzeSkill(skill.Path)
		metadataRows = append(metadataRows, newScanMetadata(skill.ID, report.Scan))
		auditRows = append(auditRows, newAnalysisMetadata(skill.ID, report))
		res := Result{
			SkillID:        skill.ID,
			Verdict:        report.Verdict,
			EngineCategory: report.EngineCategory,
			EvidenceText:   report.EvidenceText,
		}
		if err := enc.Encode(res); err != nil {
			fail("write result", err)
		}
	}
	if err := writer.Flush(); err != nil {
		fail("flush results.jsonl", err)
	}
	if err := out.Close(); err != nil {
		fail("close results.jsonl.tmp", err)
	}
	if err := commitResults(tmpPath, outPath); err != nil {
		fail("commit results.jsonl", err)
	}
	if err := writeScanMetadata(outputDir, metadataRows); err != nil {
		fail("write scan-metadata.jsonl", err)
	}
	if err := writeAnalysisMetadata(outputDir, auditRows); err != nil {
		fail("write analysis-metadata.jsonl", err)
	}

	if incomplete := countIncompleteScans(metadataRows); incomplete > 0 && !partialScansAllowed() {
		_, _ = fmt.Fprintf(os.Stderr, "scan incomplete: %d skill(s); see %s\n", incomplete, filepath.Join(outputDir, "scan-metadata.jsonl"))
		os.Exit(incompleteScanExitCode)
	}
}

func safeAnalyzeSkill(root string) (report SkillReport) {
	defer func() {
		if recovered := recover(); recovered != nil {
			status := newScanStatus()
			status.InternalError = fmt.Sprint(recovered)
			status.markIncomplete("internal scanner error")
			report = SkillReport{
				Verdict:        "suspicious",
				EngineCategory: "ast08",
				EvidenceText:   fmt.Sprintf("OWASP AST08 scanner failure: an internal scanner error occurred while processing %s; the target was not classified as benign.", sanitizePath(filepath.Base(root))),
				CategoryScore:  map[string]float64{"ast08": 2.5},
				Scan:           status,
			}
		}
	}()
	return analyzeSkill(root)
}

func confidenceFor(report SkillReport) float64 {
	if report.Verdict == "benign" || report.EngineCategory == "benign" {
		return 0.72
	}
	score := report.CategoryScore[report.EngineCategory]
	if score >= 8.0 {
		return 0.98
	}
	if score >= 5.5 {
		return 0.90
	}
	if score >= 3.0 {
		return 0.76
	}
	return 0.62
}

type skillPath struct{ ID, Path string }

func discoverSkills(input string) ([]skillPath, error) {
	entries, err := os.ReadDir(input)
	if err != nil {
		return nil, err
	}
	var out []skillPath
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		out = append(out, skillPath{ID: name, Path: filepath.Join(input, name)})
	}
	if len(out) == 0 {
		out = append(out, skillPath{ID: filepath.Base(filepath.Clean(input)), Path: input})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func analyzeSkill(root string) SkillReport {
	// v33 keeps the v32 detection policy but collects the v25 and v26 file views
	// in a single filesystem pass. That removes the largest benign-heavy overhead
	// without changing the scoring thresholds or the high-confidence promotion gate.
	baseBlobs, explainBlobs, status := collectFilesDualStatus(root)
	base := analyzeSkillV25FromBlobs(baseBlobs)
	if base.Verdict == "benign" {
		// v32: do not fully replace the conservative verdict path, but allow the
		// broader v26 extractor to promote only high-confidence, behavior-backed
		// chains that the v25 path intentionally skipped (for example dist/build
		// extension code, TOML/prototype-pollution loaders, or cloud-metadata pivots).
		// This recovers recall while keeping weak governance/metadata/cross-platform
		// hints from turning every benign integration into a malicious row.
		explain := analyzeSkillV26ExplainFromBlobs(explainBlobs)
		if shouldPromoteFromExplain(explain) {
			explain.TriggerLayer = "explain-promotion"
			return enforceScanCompleteness(explain, status)
		}
		base.ExplainCategory = explain.EngineCategory
		base.ExplainEvidence = explain.EvidenceText
		return enforceScanCompleteness(base, status)
	}
	// v31 adds a small set of high-confidence campaign/config rules to the v25 verdict path.
	// When one of those rules is the primary reason, keep its AST category/evidence rather
	// than letting the older v26 explain-only selector rewrite it away.
	if hasPinnedPrimaryFinding(base) || isV31PrimaryEvidence(base.EvidenceText) {
		return enforceScanCompleteness(base, status)
	}
	explain := analyzeSkillV26ExplainFromBlobs(explainBlobs)
	if explain.EngineCategory == "" || explain.EngineCategory == "benign" || explain.Verdict == "benign" {
		base.ExplainCategory = explain.EngineCategory
		base.ExplainEvidence = explain.EvidenceText
		return enforceScanCompleteness(base, status)
	}
	// v40: explain-only findings may add context, but they must never replace the
	// category, evidence, score, or findings that actually triggered the verdict.
	base.ExplainCategory = explain.EngineCategory
	base.ExplainEvidence = explain.EvidenceText
	return enforceScanCompleteness(base, status)
}

func findingRuleID(f Finding) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(f.Category + "|" + f.Reason)))
	return fmt.Sprintf("%s-%08x", strings.ToUpper(f.Category), h.Sum32())
}

func auditTriggerFindings(findings []Finding, category string, limit int) []FindingAudit {
	selected := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.Category == category {
			selected = append(selected, finding)
		}
	}
	sort.SliceStable(selected, func(i, j int) bool {
		if selected[i].Strong != selected[j].Strong {
			return selected[i].Strong
		}
		return selected[i].Weight > selected[j].Weight
	})
	if len(selected) > limit {
		selected = selected[:limit]
	}
	audits := make([]FindingAudit, 0, len(selected))
	for _, finding := range selected {
		audits = append(audits, FindingAudit{
			RuleID:   findingRuleID(finding),
			Category: finding.Category,
			Weight:   finding.Weight,
			File:     finding.File,
			Reason:   finding.Reason,
			Strong:   finding.Strong,
		})
	}
	return audits
}

func verdictCondition(verdict string, maxScore float64, categoryStrong int, blended float64, totalStrongCount int) string {
	if verdict == "malicious" {
		switch {
		case maxScore >= 4.65:
			return "max_score_gte_4.65"
		case maxScore >= 3.25 && categoryStrong >= 1:
			return "category_score_gte_3.25_with_strong"
		case blended >= 5.35:
			return "blended_score_gte_5.35"
		case totalStrongCount >= 2:
			return "multiple_strong_findings"
		}
	}
	if verdict == "suspicious" {
		if maxScore >= 1.75 {
			return "max_score_gte_1.75"
		}
		if blended >= 2.35 {
			return "blended_score_gte_2.35"
		}
	}
	return "below_risk_thresholds"
}

func analyzeSkillV25(root string) SkillReport {
	base, _, status := collectFilesDualStatus(root)
	return enforceScanCompleteness(analyzeSkillV25FromBlobs(base), status)
}

func analyzeSkillV25FromBlobs(blobs []FileBlob) SkillReport {
	findings := make([]Finding, 0, 80)

	for _, b := range blobs {
		findings = append(findings, analyzeFile(b)...)
	}
	findings = append(findings, analyzeCrossFile(blobs)...)
	findings = append(findings, analyzeBinaryPerimeter(blobs)...)
	// v38-loop5: conservative multi-file behavior-chain fusion.
	findings = append(findings, analyzeMicroCrossFile(blobs)...)
	// v39: verify a bounded set of source -> transform -> sink relations. The
	// original recall rules remain the candidate layer; verified chains improve
	// evidence/category precision and provider-matched auth flows receive a very
	// narrow co-occurrence dampener.
	flowSummary := analyzeBehaviorIR(blobs)
	findings = append(findings, flowSummary.Findings...)

	scores := map[string]float64{}
	strongByCat := map[string]int{}
	for _, f := range findings {
		w := applyBenignDampener(f, blobs)
		flowFactor := behaviorIRWeightFactor(f, flowSummary)
		w *= flowFactor
		scores[f.Category] += w
		if f.Strong && flowFactor >= 0.5 {
			strongByCat[f.Category]++
		}
	}

	category, maxScore := topCategory(scores)
	category, maxScore = calibrateCategory(category, maxScore, scores)
	category, maxScore = calibrateVerifiedFlowCategory(category, maxScore, scores, findings)
	blended := blendedScore(category, scores)

	// AST09 is treated as a weak governance modifier. Prefer a stronger nearby AST when possible.
	if category == "ast09" {
		altCat, altScore := topCategoryExcept(scores, "ast09")
		if altCat != "" && altScore >= 1.8 {
			category = altCat
			maxScore = altScore
		}
	}

	verdict := "benign"
	allStrong := totalStrong(strongByCat)
	// Recall-first calibration for Track B: F2 rewards catching malicious skills more
	// than over-optimizing for precision. Keep suspicious for weak or document-only
	// evidence, but promote any strong behavior chain to malicious.
	if maxScore >= 4.65 || (maxScore >= 3.25 && strongByCat[category] >= 1) || blended >= 5.35 || allStrong >= 2 {
		verdict = "malicious"
	} else if maxScore >= 1.75 || blended >= 2.35 {
		verdict = "suspicious"
	}
	verdict = capDocumentaryVerdict(verdict, category, findings, blobs)
	if verdict == "benign" {
		category = "benign"
	}

	evidence := buildEvidence(verdict, category, findings, scores)
	return SkillReport{
		Verdict:          verdict,
		EngineCategory:   category,
		EvidenceText:     evidence,
		Findings:         findings,
		CategoryScore:    scores,
		TriggerLayer:     "base",
		TriggerScore:     maxScore,
		TriggerCondition: verdictCondition(verdict, maxScore, strongByCat[category], blended, allStrong),
		TriggerFindings:  auditTriggerFindings(findings, category, 8),
	}
}

func collectFiles(root string) []FileBlob {
	var blobs []FileBlob
	var total int64
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if total >= maxTotalBytes || len(blobs) >= maxBlobsPerSkill {
			return filepath.SkipAll
		}
		if err != nil || d == nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if shouldSkipDir(name) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() <= 0 || total >= maxTotalBytes || len(blobs) >= maxBlobsPerSkill {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		binaryCandidate := isExecutableBinaryPath(rel)
		if (shouldSkipFile(rel) && !binaryCandidate) || (!isInterestingFile(rel) && !binaryCandidate) {
			return nil
		}
		data, err := readFileSampled(path, info.Size(), maxFileBytes)
		if err != nil || len(data) == 0 {
			return nil
		}
		lower, ok := decodeTextLower(data)
		magic := ""
		if binaryCandidate {
			lower, ok = "", true
			magic = binaryMagicLabel(data)
		}
		if !ok {
			return nil
		}
		if total+int64(len(data)) > maxTotalBytes {
			return nil
		}
		total += int64(len(data))
		blobs = append(blobs, FileBlob{
			Rel:      rel,
			Lower:    lower,
			IsDoc:    isDocPath(rel),
			IsMeta:   isManifestPath(rel),
			IsCode:   isCodePath(rel),
			IsBinary: binaryCandidate,
			Magic:    magic,
			Size:     int64(len(data)),
		})
		return nil
	})
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].Rel < blobs[j].Rel })
	return blobs
}

func collectFilesDual(root string) ([]FileBlob, []FileBlob) {
	var baseBlobs []FileBlob
	var explainBlobs []FileBlob
	var baseTotal int64
	var explainTotal int64
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		baseFull := baseTotal >= maxTotalBytes || len(baseBlobs) >= maxBlobsPerSkill
		explainFull := explainTotal >= maxTotalBytes || len(explainBlobs) >= maxBlobsPerSkill
		if baseFull && explainFull {
			return filepath.SkipAll
		}
		if err != nil || d == nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			// Skip only directories ignored by both profiles. Directories such as dist/
			// and build/ remain available to the broader v26 view while still being
			// excluded from the conservative v25 view below.
			if shouldSkipDir(name) && shouldSkipDirV26(name) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() <= 0 {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		binaryCandidate := isExecutableBinaryPath(rel)
		if shouldSkipFile(rel) && !binaryCandidate {
			return nil
		}
		baseCandidate := !pathHasSkippedDir(rel, shouldSkipDir) && (isInterestingFile(rel) || binaryCandidate) && baseTotal < maxTotalBytes && len(baseBlobs) < maxBlobsPerSkill
		explainCandidate := !pathHasSkippedDir(rel, shouldSkipDirV26) && (isInterestingFileV26(rel) || binaryCandidate) && explainTotal < maxTotalBytes && len(explainBlobs) < maxBlobsPerSkill
		if !baseCandidate && !explainCandidate {
			return nil
		}
		data, err := readFileSampled(path, info.Size(), maxFileBytes)
		if err != nil || len(data) == 0 {
			return nil
		}
		lower, ok := decodeTextLower(data)
		magic := ""
		if binaryCandidate {
			lower, ok = "", true
			magic = binaryMagicLabel(data)
		}
		if !ok {
			return nil
		}
		dataLen := int64(len(data))
		if baseCandidate && baseTotal+dataLen <= maxTotalBytes {
			baseBlobs = append(baseBlobs, FileBlob{
				Rel:      rel,
				Lower:    lower,
				IsDoc:    isDocPath(rel),
				IsMeta:   isManifestPath(rel),
				IsCode:   isCodePath(rel),
				IsBinary: binaryCandidate,
				Magic:    magic,
				Size:     dataLen,
			})
			baseTotal += dataLen
		}
		if explainCandidate && explainTotal+dataLen <= maxTotalBytes {
			explainBlobs = append(explainBlobs, FileBlob{
				Rel:      rel,
				Lower:    lower,
				IsDoc:    isDocPath(rel),
				IsMeta:   isManifestPath(rel),
				IsCode:   isCodePathV26(rel),
				IsBinary: binaryCandidate,
				Magic:    magic,
				Size:     dataLen,
			})
			explainTotal += dataLen
		}
		return nil
	})
	sort.Slice(baseBlobs, func(i, j int) bool { return baseBlobs[i].Rel < baseBlobs[j].Rel })
	sort.Slice(explainBlobs, func(i, j int) bool { return explainBlobs[i].Rel < explainBlobs[j].Rel })
	return baseBlobs, explainBlobs
}

func analyzeFile(b FileBlob) []Finding {
	if b.IsBinary {
		return []Finding{{"ast01", 2.8, b.Rel, "bundled native executable enters the static-review perimeter; execution intent or provenance is required for malicious promotion", false}}
	}
	rawC := b.Lower
	c := analysisText(b)
	rel := b.Rel
	var f []Finding

	cmdSink := hasAny(c, []string{"os.system(", "subprocess.", "subprocess.run", "subprocess.call", "popen(", "exec(", "eval(", "execsync", "spawn(", "child_process", "runtime.getruntime().exec", "processbuilder", "shell=true", "system(", "bash -c", "sh -c", "powershell", "cmd.exe"})
	netSink := hasAny(c, []string{"requests.post", "requests.get", "requests.", "httpx.", "aiohttp.", "urllib.request", "urlopen(", "http.post", "http.get", "http.request", "https.request", "http.client", "request.post", "fetch(", "axios.", "got(", "superagent", "xmlhttprequest", "curl ", "wget ", "net/http", "reqwest", "ureq::", "surf::", "isahc::", "minreq::", "attohttpc", "hyper::client", "client.post", "client.send", "socket.", "websocket", "grpc.", "webhook", "callback_url", "sendbeacon", "navigator.sendbeacon", "new image()", ".src =", "websocket.send", "formdata", "blob("})
	secretRead := hasAny(c, []string{"aws_access_key_id", "secret_access_key", "github_token", "gh_token", "slack_token", "bot_token", "api_key", "apikey", "bearer ", "authorization:", "dotenv", "/.env", "\".env\"", "'.env'", "process.env.token", "process.env.secret", "process.env.aws", "process.env.github", "process.env.slack", "std::env", "env::var", "dotenvy", "dotenv::", "secrets.", "id_rsa", "credentials", "cookie", "session_token", "access_token", "refresh_token", "github_token", "actions_id_token_request_token", "aws_web_identity_token_file", "credential_process", "localstorage", "sessionstorage", "indexeddb", "chrome local state", "login data", "wallet.dat", "seed phrase", "mnemonic", "metamask", "phantom", "electrum", "keystore", ".config/solana/id.json", "solana keypair", "private key"})
	fileRead := hasAny(c, []string{"open(", "readfile", "read_file", "os.environ", "process.env", "getenv(", "std::env", "env::var", "dotenvy", "fs.readfile", "read_to_string", "read_text", ".read_text(", "ioutil.readfile", "os.readfile", "readlines("})
	fileWrite := hasAny(c, []string{"writefile", "write_file", "open(", "fs.writefile", "os.remove", "unlink(", "rmtree", "shutil.rmtree", "rename(", "replace(", "write_text", ".write_text("})
	decoder := hasAny(c, []string{"base64.b64decode", "base64", "atob(", "frombase64", "decode('base64", "hex.decode", "decodehex", "string.fromcharcode", "charcodeat", "chr(", "rot13", "xor", "gzip", "zlib", "marshal"})

	// High-confidence markdown campaign patterns seen in public OpenClaw/ClawHub malicious skill sets.
	// These are intentionally narrow: fake prerequisite utilities plus paste/download payloads,
	// pass-protected archives, known redirectors, or base64 shell payload markers. They catch
	// social-engineering SKILL.md attacks without broadly treating normal documentation as code.
	if openClawCampaignIndicator(c) {
		f = append(f, Finding{"ast01", 7.2, rel, "SKILL instructions require a fake OpenClaw/ClawHub prerequisite and point to known malware installer, paste, archive, or encoded payload indicators", true})
	}
	if markdownInstallerTrap(c, b) {
		f = append(f, Finding{"ast01", 4.9, rel, "markdown skill instructions combine a prerequisite-download lure with paste-site, pass-protected archive, encoded shell, or credential-exfiltration indicators", true})
	}
	if markdownBase64ShellPayload(c, b) {
		f = append(f, Finding{"ast01", 5.4, rel, "skill-facing markdown contains an inline base64-decoded shell payload pattern", true})
	}
	if markdownCredentialWebhook(c, b) {
		f = append(f, Finding{"ast01", 5.2, rel, "skill-facing markdown contains credential material with a concrete outbound transfer command", true})
	}
	if markdownDownloadedScriptExecution(c, b) {
		f = append(f, Finding{"ast02", 5.7, rel, "downloaded script execution: skill-facing instructions download a script artifact and execute that same artifact without integrity verification", true})
	}
	if rsaModularExecutionPayload(rawC, b) {
		f = append(f, Finding{"ast08", 5.8, rel, "RSA/modular-arithmetic payload reconstructs character codes and passes the hidden result to exec/eval", true})
	}
	if remoteInstructionExecution(c, b) {
		f = append(f, Finding{"ast07", 5.9, rel, "remote skill instruction execution: a skill-facing file fetches remote markdown/config and sources or executes it, allowing behavior to drift after review", true})
	}
	if agentMemoryPersistence(c, b) {
		f = append(f, Finding{"ast01", 5.6, rel, "agent memory persistence: instructions attempt to write hidden backdoor policy into SOUL.md, MEMORY.md, CLAUDE.md, or similar persistent agent identity files", true})
	}
	if claudeHooksHijack(c, b) {
		f = append(f, Finding{"ast02", 6.0, rel, "Claude/Cursor config-file hijack: repository settings or hooks can execute shell commands, override API endpoints, or exfiltrate agent credentials on project open", true})
	}
	if vscodeWorkspaceSpyware(c, b) {
		f = append(f, Finding{"ast01", 5.8, rel, "workspace spyware behavior: extension code monitors or enumerates workspace files, encodes content, and sends it through a hidden webview or remote channel", true})
	}
	if mcpCommandHijack(c, b) {
		f = append(f, Finding{"ast02", 5.7, rel, "MCP configuration launches an unpinned or remote command path with shell/package-runner execution and credential or network exposure", true})
	}
	if hiddenPromptPayload(c, b) {
		f = append(f, Finding{"ast04", 5.0, rel, "hidden prompt payload: skill-facing instructions impersonate system/developer policy while directing command execution, credential access, or exfiltration", true})
	}
	if concealedOperationalExecution(c, b) {
		f = append(f, Finding{"ast08", 5.2, rel, "concealed operational execution: skill instructions require a script, shell, or helper command to run without user-visible disclosure or approval", true})
	}
	if destructiveCleanupWithoutApproval(c, b) {
		f = append(f, Finding{"ast01", 3.2, rel, "irreversible cleanup directive: skill instructions automatically delete, purge, wipe, or remove original user files without approval in the same action block", false})
	}
	if reverseShellBackdoor(c, b) {
		f = append(f, Finding{"ast01", 6.4, rel, "reverse shell or backdoor payload: skill material contains netcat/dev-tcp/socat/powershell command-and-control execution patterns", true})
	}
	if conditionalOrDelayedPayload(c, b) {
		w, strong := 5.4, true
		if b.IsDoc && !concreteRiskFence(c) {
			w, strong = 3.2, false
		}
		f = append(f, Finding{"ast08", w, rel, "conditional or delayed malicious payload: suspicious credential/network/command behavior is gated on time, host, platform, CI, sandbox, or delayed execution checks", strong})
	}
	if cryptoWalletExfiltration(c, b) {
		f = append(f, Finding{"ast01", 5.8, rel, "crypto wallet exfiltration: wallet seed, keypair, browser-wallet, or keystore material is read near outbound network or command execution behavior", true})
	}
	if clickFixSocialEngineering(c, b) {
		f = append(f, Finding{"ast01", 5.9, rel, "ClickFix-style social engineering: skill-facing instructions tell the user or agent to paste/run a terminal command that downloads, decodes, or executes a remote payload", true})
	}
	if browserExtensionCredentialBridge(c, b) {
		f = append(f, Finding{"ast01", 5.7, rel, "browser extension credential bridge: extension permissions or scripts can read cookies/storage/tabs on all URLs and forward captured data to a remote channel", true})
	}
	if cloudMetadataOrLocalhostPivot(c, b) {
		w, strong := 5.6, true
		if b.IsDoc && !hasAny(c, []string{"requests.post", "curl -d", " --data", "webhook", "upload", "send to", "exfiltrate", "websocket.send"}) {
			w, strong = 3.2, false
		}
		f = append(f, Finding{"ast06", w, rel, "cloud metadata or localhost pivot: skill material reaches host-local, cloud metadata, Kubernetes, Docker, Redis, etcd, or admin endpoints across an isolation boundary", strong})
	}
	if prototypePollutionOrConfigInjection(c, b) {
		f = append(f, Finding{"ast05", 5.2, rel, "prototype pollution or config injection: untrusted JSON/TOML/YAML/config input can merge into object prototypes or execution-sensitive options", true})
	}
	if invisibleInstructionSmuggling(rawC, b) {
		f = append(f, Finding{"ast04", 5.3, rel, "invisible instruction smuggling: skill-facing metadata hides policy-override or execution instructions in zero-width, bidi, HTML-comment, CSS-hidden, or encoded text", true})
	}
	if hotReloadRemoteModule(c, b) {
		f = append(f, Finding{"ast07", 5.6, rel, "hot-reload remote module: remote plugin/config/manifest content is downloaded and dynamically imported, required, loaded, or evaluated at runtime", true})
	}
	if scannerResultTampering(c, b) {
		f = append(f, Finding{"ast08", 5.1, rel, "scanner result tampering: skill code manipulates scan/audit results or hides files while suspicious execution, credential, network, or decode behavior is present", true})
	}
	if agentInstructionCredentialExfil(c, b) {
		f = append(f, Finding{"ast01", 5.8, rel, "agent instruction credential exfiltration: skill-facing instructions tell the agent to read credentials, SSH keys, wallet, browser, or environment data and send or report it externally", true})
	}
	if agentIdentityFileWrite(c, b) {
		f = append(f, Finding{"ast01", 5.5, rel, "agent identity persistence: executable or skill-facing material writes policy, backdoor, or credential-access instructions into persistent agent identity files", true})
	}
	if websocketCommandChannel(c, b) {
		f = append(f, Finding{"ast01", 5.8, rel, "websocket command channel: skill opens a persistent remote WebSocket/control channel that can receive commands or send credential data", true})
	}
	if localAgentControlHijack(c, b) {
		w, strong := 5.6, true
		if b.IsDoc && !hasAny(c, []string{"websocket.send", "send({", "send(json", "/execute", "/command", "method: execute", `"method":"execute"`, `"method": "execute"`}) {
			w, strong = 3.2, false
		}
		f = append(f, Finding{"ast06", w, rel, "local agent control hijack: skill reaches localhost agent, MCP, debug, or browser-control WebSocket endpoints across an isolation boundary", strong})
	}
	if unsafeDeserializePayload(c, b) {
		f = append(f, Finding{"ast05", 5.7, rel, "unsafe deserialization payload: skill-supplied YAML/JSON/Python serialization content contains object/apply tags or pickle-style gadgets near execution payloads", true})
	}
	if credentialTrapTokenOutbound(c, b) {
		f = append(f, Finding{"ast01", 5.4, rel, "credential trap with outbound sink: hard-coded secret/token patterns or credential-harvest terms are paired with webhook, fetch, or upload behavior", true})
	}
	if mcpToolDescriptionInjection(c, b) {
		f = append(f, Finding{"ast04", 5.5, rel, "MCP/tool metadata prompt injection: tool descriptions or schemas contain hidden policy-override instructions tied to credential, source-code exfiltration, or command execution", true})
	}
	if agentInstructionSourceExfil(c, b) {
		f = append(f, Finding{"ast01", 5.4, rel, "agent instruction data exfiltration: skill-facing instructions tell the agent to read workspace/source files and upload or report them to an external endpoint", true})
	}
	if brandImpersonationMetadata(c, b) {
		f = append(f, Finding{"ast04", 5.4, rel, "brand impersonation metadata: skill claims a trusted provider while using unofficial publisher signals and sensitive permissions or credential context", true})
	}
	if projectConfigAutoRunHijack(c, b) {
		f = append(f, Finding{"ast02", 5.8, rel, "project auto-run configuration hijack: repository config can execute remote or credential-exfiltrating commands when opened, built, or committed", true})
	}
	if dockerfileRemoteEntrypoint(c, b) {
		f = append(f, Finding{"ast02", 5.6, rel, "Docker/build recipe pulls remote mutable content into an executable entrypoint or startup command without integrity pinning", true})
	}
	if escapedPayloadEvasion(c, b) {
		f = append(f, Finding{"ast08", 5.4, rel, "escaped payload evasion: encoded hex/unicode/url string reconstruction is paired with eval/exec, remote loading, or credential exfiltration behavior", true})
	}
	if dependencyConfusionOrMutableInstaller(c, b) {
		f = append(f, Finding{"ast02", 5.2, rel, "dependency confusion or mutable installer path: package metadata uses alternate registries, latest/mutable refs, or package runners with install-time execution risk", true})
	}
	if knownTyposquatOrDependencyConfusion(c, b) {
		f = append(f, Finding{"ast02", 5.4, rel, "known dependency-confusion or typosquat package pattern appears in skill package metadata", true})
	}
	if alternatePrivateIndexRisk(c, b) {
		f = append(f, Finding{"ast02", 3.6, rel, "package metadata resolves private/internal dependency names through an alternate registry or index without an accompanying lock/provenance signal", false})
	}
	if ciWorkflowRemoteExecution(c, b) {
		f = append(f, Finding{"ast02", 5.5, rel, "repository workflow/config executes remote installer content during CI or project automation", true})
	}
	if localBinaryExecutionLure(c, b) {
		f = append(f, Finding{"ast01", 5.0, rel, "skill-facing instructions require running a bundled local binary or installer helper before use, creating an opaque execution path", true})
	}
	if markdownOpaqueBinaryDownload(c, b) {
		f = append(f, Finding{"ast01", 5.5, rel, "active skill instructions download a platform-specific opaque binary, mark it executable, and install or launch it without an integrity check", true})
	}
	if bundledOpaqueBinaryExecution(rawC, b) {
		f = append(f, Finding{"ast01", 5.3, rel, "skill instructions discover bundled native binaries, make them executable, and launch them with user-environment access without provenance or integrity verification", true})
	}
	if startupPersistencePayload(c, b) {
		f = append(f, Finding{"ast01", 5.1, rel, "startup or scheduled persistence configuration launches network, shell, or downloaded payload behavior", true})
	}
	// v38-loop1: high-confidence recall micro-rules from the six rule-pack review.
	// These only fire on concrete behavior chains and keep the original v38 thresholds intact.
	if microInstallRemoteExec(c, b) {
		f = append(f, Finding{"ast02", 5.9, rel, "install lifecycle or build metadata downloads remote content and executes it", true})
	}
	if microUnsafeYamlTag(c, b) {
		f = append(f, Finding{"ast05", 5.8, rel, "YAML content contains object/apply/function tags capable of constructing executable objects", true})
	}
	if microHostIsolationStrong(c, b) {
		f = append(f, Finding{"ast06", 5.7, rel, "container or runtime configuration requests privileged host access, host networking, or Docker socket exposure", true})
	}
	// v38-loop2: agent runtime configuration and remote plugin registration chains.
	if microAgentConfigHookRCE(c, b) {
		f = append(f, Finding{"ast02", 5.8, rel, "agent or MCP configuration hook can launch shell/package-runner commands or rewrite model/network execution paths", true})
	}
	if microRemotePluginNoApproval(c, b) {
		f = append(f, Finding{"ast06", 5.4, rel, "remote plugin or tool registration is allowed without approval/authentication and can load external code", true})
	}
	if microSimpleHotReloadRemote(c, b) {
		f = append(f, Finding{"ast07", 5.4, rel, "watch/hot-reload logic downloads remote module or plugin content and reloads it at runtime", true})
	}
	// v38-loop3: lightweight source/sink proximity for Bandit-style high-risk primitives.
	if microUnsafeDeserializeSourceSink(c, b) {
		f = append(f, Finding{"ast05", 5.6, rel, "unsafe deserialization primitive is near file, network, stdin, argument, upload, or decoded input source", true})
	}
	if microExecTaintedSourceSink(c, b) {
		f = append(f, Finding{"ast01", 5.1, rel, "command/eval sink is near user, environment, decoded, network, or manifest-controlled input", true})
	}
	// v38-loop4: data exposure and credential-store chains with concrete outbound sinks.
	if microPIIOutboundChain(c, b) {
		weight, strong := 3.0, false
		if privacyEvasionSignal(c) {
			weight, strong = 5.0, true
		}
		f = append(f, Finding{"ast03", weight, rel, "PII or personal-data collection is paired with webhook/upload/POST outbound transfer", strong})
	}
	if microBrowserWalletStoreExfil(c, b) {
		f = append(f, Finding{"ast01", 5.6, rel, "browser credential store or crypto-wallet material is paired with remote upload or webhook behavior", true})
	}
	// v38-loop6..15: additional high-confidence behavior chains only.
	if microMCPRemoteAutoApprove(c, b) {
		f = append(f, Finding{"ast02", 5.7, rel, "MCP/agent server configuration launches remote or latest package-runner code with approval bypass or auto-approval", true})
	}
	if microVSCodeExtensionWorkspaceExfil(c, b) {
		f = append(f, Finding{"ast01", 5.5, rel, "VS Code/IDE extension workspace file access is paired with outbound upload or telemetry sink", true})
	}
	if microBrowserExtensionBroadExfil(c, b) {
		f = append(f, Finding{"ast01", 5.5, rel, "browser extension broad host/cookie/storage permissions are paired with outbound exfiltration behavior", true})
	}
	if microCloudMetadataCredentialExfil(c, b) {
		f = append(f, Finding{"ast01", 5.7, rel, "cloud instance metadata credential endpoint access is paired with outbound exfiltration behavior", true})
	}
	if microKubeServiceAccountExfil(c, b) {
		f = append(f, Finding{"ast01", 5.6, rel, "Kubernetes service-account token access is paired with outbound upload or cluster pivot behavior", true})
	}
	if microShellCredentialStoreExfil(c, b) {
		f = append(f, Finding{"ast01", 5.4, rel, "shell history, netrc, npm, pypirc, git-credentials, or SSH config material is paired with outbound upload behavior", true})
	}
	if microCIIdentityTokenExfil(c, b) {
		f = append(f, Finding{"ast02", 5.5, rel, "CI workflow requests identity/secrets tokens and sends them to an external HTTP sink", true})
	}
	if microDockerfileRemoteAddExec(c, b) {
		f = append(f, Finding{"ast02", 5.6, rel, "Docker/build recipe downloads remote mutable content and executes it during build or entrypoint", true})
	}
	if microScanBypassSelfUpdate(c, b) {
		f = append(f, Finding{"ast08", 5.3, rel, "skill-facing instructions describe scan-bypass or post-scan self-update behavior that fetches remote executable/instruction material", true})
	}
	if microPolicyFileTamper(c, b) {
		f = append(f, Finding{"ast01", 5.4, rel, "skill modifies agent policy or instruction files to disable guards while enabling command/network behavior", true})
	}

	// v38-loop16..115: table-driven high-confidence behavior-chain recall rules.
	f = append(f, analyzeLoop16To115File(b)...)
	if crossPlatformMetadataLoss(c, b) {
		f = append(f, Finding{"ast10", 5.1, rel, "cross-platform port appears to drop or weaken security metadata such as risk tier, signatures, deny rules, allowlisted egress, or scoped permissions", true})
	}

	if cmdSink && (secretRead || netSink || decoder || hasAny(c, []string{"rm -rf", "/etc/passwd", "chmod 777", "bash -c", "sh -c"})) {
		f = append(f, Finding{"ast01", 5.7, rel, "combines command execution with credential, network, destructive, or decoded input signals", true})
	} else if cmdSink && b.IsCode {
		f = append(f, Finding{"ast01", 3.0, rel, "contains executable command/eval sink in code", false})
	}
	if secretRead && netSink && fileRead {
		f = append(f, Finding{"ast01", 6.2, rel, "reads secret-like data and sends it through a network sink", true})
	}
	if hasAny(c, []string{"rm -rf /", "shutil.rmtree", "os.remove", "unlink(", "deletefile", "format c:", "wipe"}) && b.IsCode {
		f = append(f, Finding{"ast01", 4.4, rel, "contains destructive file operation indicators", true})
	}
	if secretRead && (fileRead || netSink || cmdSink) && b.IsCode {
		f = append(f, Finding{"ast01", 4.3, rel, "accesses credential-like material near file, network, or execution logic", true})
	}
	if netSink && decoder && b.IsCode {
		f = append(f, Finding{"ast08", 4.0, rel, "network path is paired with encoded or reconstructed content handling", true})
	}
	if cmdSink && hasAny(c, []string{"input(", "argv", "req.body", "request.", "params", "metadata", "manifest", "config"}) && b.IsCode {
		f = append(f, Finding{"ast01", 4.1, rel, "user, metadata, or config-controlled value can reach command/eval execution", true})
	}

	if isPackagePath(rel) && hasAny(c, []string{"preinstall", "postinstall", "prepare", "setup_requires", "entry_points", "install_requires"}) && (cmdSink || netSink || decoder) {
		f = append(f, Finding{"ast02", 6.4, rel, "package lifecycle metadata contains command, network, or decoded execution behavior", true})
	}
	if hasAny(c, []string{"curl | sh", "curl -fs", "wget -q", "pip install", "npm install", "go get", "go install", "bash <(", "sh <("}) && (isPackagePath(rel) || strings.Contains(rel, "install") || strings.Contains(rel, "update")) {
		f = append(f, Finding{"ast02", 4.7, rel, "installer/update path can fetch or execute dependency content", true})
	}
	if hasAny(c, []string{"integrity=false", "strict-ssl=false", "--no-verify", "--trusted-host", "verify=false", "checksum=false", "skip checksum", "disable checksum", "ignore checksum"}) {
		f = append(f, Finding{"ast02", 3.7, rel, "disables dependency integrity or transport verification", true})
	}
	if isPackagePath(rel) && hasAny(c, []string{"prepublish", "prepublishonly", "npm_lifecycle_event", "node -e", "python -c", "install.js", "prepare"}) && (cmdSink || netSink || decoder || hasAny(c, []string{"https.request", "http.request", "child_process", "chmod +x"})) {
		f = append(f, Finding{"ast02", 5.9, rel, "package lifecycle or installer script reaches network, command, or decoded execution behavior", true})
	}
	if isPackagePath(rel) && hasAny(c, []string{"cmdclass", "build_ext", "develop", "build-backend", "backend-path", "extra-index-url"}) && (cmdSink || netSink || hasAny(c, []string{"download", "urlopen", "requests.", "subprocess"})) {
		f = append(f, Finding{"ast02", 5.0, rel, "python build/install metadata can run dynamic dependency or build-time code", true})
	}

	if b.IsMeta && hasAny(c, []string{"permission", "capability", "scope", "allow"}) && manifestBroadCapability(c) {
		f = append(f, Finding{"ast03", 4.1, rel, "manifest declares broad filesystem, network, shell, host, or wildcard capability", false})
	}
	if b.IsMeta && hasAny(c, []string{"ignore previous", "ignore all previous", "system prompt", "developer message", "hidden instruction", "do not disclose", "policy override", "bypass safety", "jailbreak", "scan bypass"}) {
		f = append(f, Finding{"ast04", 4.4, rel, "metadata includes hidden prompt, policy override, or scanner-bypass instruction", true})
	}
	if b.IsMeta && hasAny(c, []string{"effective_policy", "policy cache", "cross_scope", "cross-scope", "parent workspace", "workspace.parent", "metadata handler"}) {
		f = append(f, Finding{"ast04", 4.2, rel, "metadata references cross-scope policy or effective metadata handling", false})
	}
	if hasAny(c, []string{"ignore previous", "system prompt", "developer message", "hidden instruction", "policy override", "bypass safety", "jailbreak"}) && b.IsCode {
		f = append(f, Finding{"ast04", 3.6, rel, "code contains hidden instruction or policy-override text used by the skill", false})
	}

	if hasAny(c, []string{"pickle.load", "pickle.loads", "dill.load", "dill.loads", "marshal.loads", "jsonpickle.decode", "objectinputstream", "node-serialize", "unserialize("}) {
		f = append(f, Finding{"ast05", 5.8, rel, "uses unsafe deserialization primitive", true})
	}
	if strings.Contains(c, "yaml.load") && !strings.Contains(c, "safe_load") && !strings.Contains(c, "safeloader") {
		f = append(f, Finding{"ast05", 5.3, rel, "uses yaml.load without SafeLoader/safe_load", true})
	}
	if hasAny(c, []string{"loader=yaml.loader", "loader = yaml.loader", "yaml.loader", `typ="unsafe"`, `typ = "unsafe"`, "typ='unsafe'", "typ = 'unsafe'"}) && !strings.Contains(c, "safe_load") && !strings.Contains(c, "safeloader") {
		f = append(f, Finding{"ast05", 5.1, rel, "uses an unsafe YAML loader configuration", true})
	}
	if hasAny(c, []string{"torch.load(", "pandas.read_pickle", "pd.read_pickle", "numpy.load(", "np.load("}) && hasAny(c, []string{"allow_pickle=true", "allow_pickle = true", "input(", "argv", "request.", "upload", "url", "http", "file"}) {
		f = append(f, Finding{"ast05", 4.8, rel, "loads pickle-capable serialized data from user, file, or remote-influenced input", true})
	}
	if hasAny(c, []string{"deserialize", "fromjson", "loads("}) && cmdSink {
		f = append(f, Finding{"ast05", 4.2, rel, "deserialization path is near command/eval execution sink", true})
	}

	if isolationBoundarySignal(c, b) {
		w, strong := 5.0, true
		if b.IsDoc {
			w, strong = 2.8, false
		}
		f = append(f, Finding{"ast06", w, rel, "references container, host, namespace, mount, or privileged isolation boundary", strong})
	}
	if isolationSecretBoundarySignal(c, b) {
		f = append(f, Finding{"ast06", 5.1, rel, "targets container runtime, mounted secret, kubelet, or process-environment isolation boundary", true})
	}
	if hasAny(c, []string{"extractall(", "tarfile.", "zipfile."}) && hasAny(c, []string{"../", "..\\", "path traversal", "zip slip", "tar slip"}) {
		f = append(f, Finding{"ast06", 4.3, rel, "archive extraction logic may allow path traversal across the intended skill boundary", true})
	}
	if hasAny(c, []string{"../..", "..\\.."}) && (fileRead || fileWrite || strings.Contains(c, "path.join") || strings.Contains(c, "filepath.join")) {
		f = append(f, Finding{"ast06", 3.9, rel, "uses path traversal pattern near file access logic", true})
	}

	if hasAny(c, []string{"auto_update", "autoupdate", "check_update", "update_url", "remote_config", "plugin_url", "manifest_url", "version_url", "latest version", "download update", "self_update", "update manifest", "hotfix", "remote recipe", "recipe_url"}) {
		w := 3.5
		strong := false
		if netSink || fileWrite || cmdSink || hasAny(c, []string{"importlib", "dynamic import", "require("}) {
			w = 5.5
			strong = true
		}
		f = append(f, Finding{"ast07", w, rel, "implements remote update/configuration or version-drift behavior", strong})
	}
	if netSink && fileWrite && hasAny(c, []string{"plugin", "skill", "manifest", "recipe", "config", "module"}) {
		f = append(f, Finding{"ast07", 5.2, rel, "network-fetched content can rewrite skill/plugin/config material", true})
	}
	if hasAny(c, []string{"remote_policy", "remote policy", "feature_flag", "feature flag", "plugin_registry", "recipe_registry", "policy cache", "latest.json", "release manifest", "version manifest", "downloaded config"}) {
		w := 3.4
		strong := false
		if netSink && (fileWrite || cmdSink || hasAny(c, []string{"importlib", "dynamic import", "require(", "write_text", "writefile", "fs.writefile"})) {
			w = 5.4
			strong = true
		}
		f = append(f, Finding{"ast07", w, rel, "uses remote policy, registry, feature flag, or release manifest that can drift skill behavior", strong})
	}

	if decoder && cmdSink {
		f = append(f, Finding{"ast08", 5.2, rel, "decoded or reconstructed content reaches command/eval execution", true})
	}
	if hasAny(c, []string{"sandbox", "scanner", "analysis", "automated", "sleep(", "time.sleep", "random", "process.env.ci", "github_actions", "gitlab_ci", "circleci", "jenkins", "buildkite"}) && (cmdSink || netSink || decoder) {
		f = append(f, Finding{"ast08", 4.2, rel, "contains anti-analysis, timing, or environment-gated behavior near suspicious sinks", false})
	}
	if hasAny(c, []string{"disable_audit", "audit=false", "logging=false", "guardrail=false", "policy=false", "enforce=false", "allow_unreviewed", "skip_review", "governance"}) {
		f = append(f, Finding{"ast09", 2.9, rel, "governance, audit, policy, or guardrail enforcement appears disabled or bypassed", false})
	}

	credentialAction := (fileRead || hasAny(c, []string{"cat ", "type ", "read ~", "read /", "read the ", "copy the ", "collect ", "extract "})) && (netSink || cmdSink || hasAny(c, []string{"send to", "send it", "upload", "post to", "report externally", "exfiltrate"}))
	if !benignInstructionalContext(c) && secretRead && hasAny(c, []string{"slack", "github", "aws", "gcp", "azure", "kube", "kubernetes", "docker", "npm", "pypi", "browser", "cookie", "keychain", "ssh"}) {
		// A skill often documents how a provider token is configured. Reference
		// alone is a risky capability, not evidence of a malicious payload.
		w, strong := 2.4, false
		if credentialAction {
			w, strong = 5.2, true
		}
		if b.IsMeta && !b.IsCode {
			// A manifest that only declares access to cookies/tokens should influence
			// AST classification, but should not by itself become a malicious finding
			// without code, network, command, or cross-file behavior.
			w, strong = 3.1, false
		}
		f = append(f, Finding{"ast10", w, rel, "references reusable cross-platform credentials, cookies, tokens, or cloud/session material", strong})
	}
	if !benignInstructionalContext(c) && hasAny(c, []string{".kube/config", ".docker/config.json", ".npmrc", ".pypirc", ".aws/credentials", ".ssh/id_rsa", "known_hosts", "browser cookies"}) {
		w, strong := 3.0, false
		if credentialAction {
			w, strong = 5.1, true
		}
		if b.IsMeta && !b.IsCode {
			w, strong = 3.2, false
		}
		f = append(f, Finding{"ast10", w, rel, "targets common cross-platform credential/session files", strong})
	}
	if !benignInstructionalContext(c) && hasAny(c, []string{".netrc", "git-credentials", "application_default_credentials.json", "gcloud", "azure profile", "azure/accessTokens.json", "auths", "_authtoken", "npm_token", "huggingface token", "keyring", "keytar", "local state", "login data", "cookies sqlite", "actions_id_token_request_token", "aws_web_identity_token_file"}) {
		w, strong := 3.0, false
		if credentialAction {
			w, strong = 5.0, true
		}
		if b.IsMeta && !b.IsCode {
			w, strong = 3.2, false
		}
		f = append(f, Finding{"ast10", w, rel, "targets cloud, package-manager, browser, OIDC, or keychain credential material reusable across platforms", strong})
	}

	return f
}

func analyzeCrossFile(blobs []FileBlob) []Finding {
	var f []Finding
	if len(blobs) == 0 {
		return f
	}
	hasManifestBroad := false
	hasSink := false
	hasRemote := false
	hasSecret := false
	hasPkgLifecycle := false
	hasInstallerExecNet := false
	hasPythonBuildHook := false
	hasBuildExecNet := false
	hasBrowserBroadManifest := false
	hasBrowserOutboundScript := false
	hasRemoteConfigOrPlugin := false
	hasDynamicModuleLoad := false
	hasLocalOrMetadataPivot := false
	hasCrossPlatformSecurityMetadata := false
	hasCrossPlatformWeakening := false
	hasCrossPlatformIdentityOrEgressLoss := false
	hasMetaNetworkDisabled := false
	hasMetaShellDisabled := false
	hasMetaLowRisk := false
	hasMetaCleanScan := false
	hasCodeOutbound := false
	hasCodeExec := false
	hasCodeSecret := false
	hasCodeDestructive := false
	hasCodeDecoder := false
	hasGlobalBase64 := false
	hasGlobalEvalExec := false
	globalBytes := 0
	for _, b := range blobs {
		activeMaterial := b.IsCode || b.IsMeta || isPackagePath(b.Rel)
		if b.IsMeta {
			if metadataClaimsNetworkDisabled(b.Lower) {
				hasMetaNetworkDisabled = true
			}
			if metadataClaimsShellDisabled(b.Lower) {
				hasMetaShellDisabled = true
			}
			if metadataClaimsLowRisk(b.Lower) {
				hasMetaLowRisk = true
			}
			if metadataClaimsCleanScan(b.Lower) {
				hasMetaCleanScan = true
			}
		}
		if activeMaterial && !b.IsMeta {
			if hasAny(b.Lower, []string{"requests.", "urllib.request", "urlopen(", "fetch(", "axios.", "curl ", "wget ", "webhook", "discord.com/api/webhooks", "hooks.slack.com", "sendbeacon", "websocket", "http://", "https://"}) {
				hasCodeOutbound = true
			}
			if hasAny(b.Lower, []string{"subprocess.", "subprocess.run", "os.system", "eval(", "exec(", "execsync", "spawn(", "child_process", "popen(", "shell=true", "bash -c", "sh -c", "powershell", "cmd.exe"}) {
				hasCodeExec = true
			}
			if hasAny(b.Lower, []string{"api_key", "access_token", "secret", "credential", ".env", "id_rsa", "id_ed25519", ".ssh", ".aws/credentials", ".npmrc", "cookie", "login data", "local state", "keychain", "mnemonic", "private key"}) {
				hasCodeSecret = true
			}
			if hasAny(b.Lower, []string{"rm -rf", "shutil.rmtree", "os.remove", "unlink(", "deletefile", "format c:", "wipe", "chmod 777"}) {
				hasCodeDestructive = true
			}
			if hasAny(b.Lower, []string{"base64", "atob(", "frombase64", "string.fromcharcode", "marshal", "gzip", "zlib"}) {
				hasCodeDecoder = true
			}
		}
		if globalBytes < 512*1024 {
			chunk := b.Lower
			remaining := 512*1024 - globalBytes
			if len(chunk) > remaining {
				chunk = chunk[:remaining]
			}
			globalBytes += len(chunk)
			if strings.Contains(chunk, "base64") {
				hasGlobalBase64 = true
			}
			if strings.Contains(chunk, "eval(") || strings.Contains(chunk, "exec(") {
				hasGlobalEvalExec = true
			}
		}
		if b.IsMeta && hasAny(b.Lower, []string{"permission", "capability", "scope"}) && manifestBroadCapability(b.Lower) {
			hasManifestBroad = true
		}
		if isPackagePath(b.Rel) && hasAny(b.Lower, []string{"preinstall", "postinstall", "prepare", "setup_requires", "entry_points"}) {
			hasPkgLifecycle = true
		}
		if isPackagePath(b.Rel) && hasAny(b.Lower, []string{"build-backend", "backend-path", "cmdclass", "build_ext", "develop", "extra-index-url"}) {
			hasPythonBuildHook = true
		}
		if activeMaterial && hasAny(b.Lower, []string{"subprocess.", "subprocess.run", "os.system", "eval(", "exec(", "execsync", "spawn(", "child_process", "popen("}) {
			hasSink = true
		}
		if activeMaterial && hasAny(b.Lower, []string{"requests.", "urllib.request", "urlopen(", "fetch(", "axios.", "curl ", "wget ", "remote_config", "update_url", "manifest_url", "plugin_url", "webhook"}) {
			hasRemote = true
		}
		if (strings.Contains(strings.ToLower(b.Rel), "install") || strings.Contains(strings.ToLower(b.Rel), "update")) && hasAny(b.Lower, []string{"requests.", "urllib.request", "urlopen(", "fetch(", "axios.", "curl ", "wget ", "remote_config", "update_url", "manifest_url", "plugin_url", "webhook"}) && hasAny(b.Lower, []string{"subprocess.", "subprocess.run", "os.system", "eval(", "exec(", "execsync", "spawn(", "child_process", "popen("}) {
			hasInstallerExecNet = true
		}
		if hasAny(b.Lower, []string{"requests.", "urllib.request", "urlopen(", "fetch(", "axios.", "curl ", "wget ", "https.request", "http.request"}) && hasAny(b.Lower, []string{"subprocess.", "subprocess.run", "os.system", "eval(", "exec(", "execsync", "spawn(", "child_process", "popen("}) {
			hasBuildExecNet = true
		}
		if activeMaterial && hasAny(b.Lower, []string{"api_key", "access_token", "secret", "credential", ".env", "id_rsa", "cookie"}) {
			hasSecret = true
		}
		if activeMaterial && hasAny(b.Lower, []string{"manifest_version", "content_scripts", "service_worker", "chrome.", "browser."}) && hasAny(b.Lower, []string{"<all_urls>", "all_urls", "cookies", "tabs", "webrequest", "history", "storage"}) {
			hasBrowserBroadManifest = true
		}
		if activeMaterial && hasAny(b.Lower, []string{"chrome.cookies", "browser.cookies", "document.cookie", "localstorage", "sessionstorage", "indexeddb", "chrome.storage", "browser.storage"}) && hasAny(b.Lower, []string{"fetch(", "axios.", "xmlhttprequest", "sendbeacon", "webhook", "discord.com/api/webhooks", "hooks.slack.com", "websocket"}) {
			hasBrowserOutboundScript = true
		}
		if activeMaterial && hasAny(b.Lower, []string{"remote_config", "plugin_url", "manifest_url", "module_url", "script_url", "recipe_url", "update_url", "latest.json", "release manifest", "hot reload", "downloaded config", "raw.githubusercontent.com", "gist.githubusercontent.com"}) {
			hasRemoteConfigOrPlugin = true
		}
		if activeMaterial && hasAny(b.Lower, []string{"importlib.import_module", "spec_from_file_location", "__import__", "await import(", "import(", "require(", "plugin.open", "dlopen", "loadlibrary", "eval(", "exec(", "vm.runinnewcontext", "new function"}) {
			hasDynamicModuleLoad = true
		}
		if activeMaterial && cloudMetadataOrLocalhostPivot(b.Lower, b) {
			hasLocalOrMetadataPivot = true
		}
		if !benignInstructionalContext(b.Lower) {
			if crossPlatformSecurityMetadataSignal(b.Lower) {
				hasCrossPlatformSecurityMetadata = true
			}
			if crossPlatformWeakeningSignal(b.Lower) {
				hasCrossPlatformWeakening = true
			}
			if crossPlatformIdentityOrEgressLossSignal(b.Lower) {
				hasCrossPlatformIdentityOrEgressLoss = true
			}
		}
	}
	if hasManifestBroad && hasSink {
		f = append(f, Finding{"ast03", 3.8, "manifest+code", "broad declared capability is paired with executable command/eval behavior", true})
	}
	if hasPkgLifecycle && hasInstallerExecNet {
		f = append(f, Finding{"ast02", 6.6, "package lifecycle+installer", "package lifecycle script is paired with installer network fetch and command execution", true})
	}
	if hasPythonBuildHook && hasBuildExecNet {
		f = append(f, Finding{"ast02", 6.1, "python build metadata+code", "python build metadata is paired with network fetch and command execution code", true})
	}
	if hasRemote && hasSink {
		f = append(f, Finding{"ast01", 4.0, "multi-file", "network/update behavior is paired with command/eval execution across files", true})
	}
	if hasRemote && hasSecret {
		f = append(f, Finding{"ast01", 4.2, "multi-file", "network behavior is paired with secret/token access across files", true})
	}
	if hasGlobalBase64 && hasGlobalEvalExec {
		f = append(f, Finding{"ast08", 3.4, "multi-file", "encoded payload handling is paired with eval/exec behavior", false})
	}
	if hasBrowserBroadManifest && hasBrowserOutboundScript {
		f = append(f, Finding{"ast01", 5.4, "browser extension manifest+script", "browser extension broad host/cookie/storage permissions are paired with script-level outbound exfiltration behavior", true})
	}
	if hasRemoteConfigOrPlugin && hasDynamicModuleLoad && (hasRemote || hasSink) {
		f = append(f, Finding{"ast07", 5.5, "remote config+dynamic load", "remote plugin/config/update material is paired with dynamic import/require/eval loading across skill files", true})
	}
	if hasLocalOrMetadataPivot && (hasRemote || hasSecret || hasSink) {
		f = append(f, Finding{"ast06", 5.3, "localhost/metadata pivot", "cloud metadata or host-local admin endpoint access is paired with network, credential, or execution behavior", true})
	}
	if hasCrossPlatformSecurityMetadata && hasCrossPlatformWeakening && hasCrossPlatformIdentityOrEgressLoss {
		f = append(f, Finding{"ast10", 5.1, "cross-platform metadata", "ported skill material loses or weakens security metadata such as signatures, content hashes, deny-write rules, default-deny egress, or scoped permissions", true})
	}
	if hasMetaNetworkDisabled && hasCodeOutbound && (hasCodeSecret || hasCodeExec || hasCodeDestructive) {
		f = append(f, Finding{"ast04", 5.2, "manifest+code", "metadata declares network access disabled while executable skill material performs outbound network behavior tied to secrets, command execution, or destructive activity", true})
	}
	if hasMetaShellDisabled && hasCodeExec && (hasCodeOutbound || hasCodeSecret || hasCodeDecoder || hasCodeDestructive) {
		f = append(f, Finding{"ast04", 5.2, "manifest+code", "metadata declares shell or command execution disabled while executable material reaches command/eval sinks with risky context", true})
	}
	if hasMetaLowRisk && ((hasCodeOutbound && hasCodeSecret) || (hasCodeOutbound && hasCodeExec) || hasCodeDestructive) {
		f = append(f, Finding{"ast04", 5.3, "manifest+code", "metadata claims low/safe risk while code shows credential, outbound execution, or destructive behavior inconsistent with that risk tier", true})
	}
	if hasMetaCleanScan && ((hasCodeOutbound && hasCodeSecret) || (hasCodeOutbound && hasCodeExec) || (hasCodeDecoder && hasCodeExec)) {
		f = append(f, Finding{"ast08", 5.2, "scan metadata+code", "metadata advertises a clean/passed scan while skill code contains credential, outbound, decoded, or command-execution behavior", true})
	}
	return f
}

func analyzeBinaryPerimeter(blobs []FileBlob) []Finding {
	var findings []Finding
	var binaries []FileBlob
	var docs []FileBlob
	for _, b := range blobs {
		if b.IsBinary {
			binaries = append(binaries, b)
		} else if b.IsDoc {
			docs = append(docs, b)
		}
	}
	for _, binary := range binaries {
		base := strings.ToLower(filepath.Base(binary.Rel))
		stem := strings.TrimSuffix(base, filepath.Ext(base))
		for _, doc := range docs {
			c := analysisText(doc)
			referenced := strings.Contains(c, base) || (len(stem) >= 5 && strings.Contains(c, stem)) || hasAny(c, []string{"bundled binary", "native binary", "native plugin", "precompiled helper"})
			execute := hasAny(c, []string{"chmod +x", "run ./", "execute ./", "launch ./", "start-process", " --daemon", " --init", "before proceeding", "required helper"})
			provenance := hasAny(c, []string{"sha256", "sha512", "checksum", "signature verification", "cosign verify", "gpg --verify", "build from source"})
			if referenced && execute && !provenance {
				findings = append(findings, Finding{"ast01", 5.5, binary.Rel, fmt.Sprintf("bundled %s executable is referenced by active instructions and launched without a checksum, signature, or source-build provenance", binary.Magic), true})
				break
			}
		}
	}
	return findings
}

func isExecutableBinaryPath(rel string) bool {
	n := strings.ToLower(rel)
	for _, ext := range []string{".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".wasm", ".node", ".class", ".jar"} {
		if strings.HasSuffix(n, ext) {
			return true
		}
	}
	return false
}

func binaryMagicLabel(data []byte) string {
	if len(data) >= 4 {
		switch {
		case data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F':
			return "ELF"
		case data[0] == 'M' && data[1] == 'Z':
			return "PE"
		case data[0] == 0x00 && data[1] == 'a' && data[2] == 's' && data[3] == 'm':
			return "WebAssembly"
		case (data[0] == 0xfe && data[1] == 0xed && data[2] == 0xfa) || (data[0] == 0xcf && data[1] == 0xfa && data[2] == 0xed):
			return "Mach-O"
		case data[0] == 0xca && data[1] == 0xfe && data[2] == 0xba && data[3] == 0xbe:
			return "Mach-O/Java"
		}
	}
	return "opaque"
}

func analyzeMicroCrossFile(blobs []FileBlob) []Finding {
	var out []Finding
	if len(blobs) == 0 {
		return out
	}
	hasInstallLifecycle := false
	hasInstallRemoteExec := false
	hasConcreteSecret := false
	hasOutbound := false
	hasRemotePlugin := false
	hasNoApproval := false
	hasHotWatch := false
	hasRemoteFetch := false
	hasDynamicLoad := false
	hasHostPersistence := false
	hasUnsafeDeserialize := false
	hasUntrustedInput := false
	hasMCPRemoteRunner := false
	hasMCPApprovalBypass := false
	hasCloudMetadataCredential := false
	hasKubeServiceAccount := false
	hasCIToken := false
	hasCIOutbound := false
	hasPolicyTamper := false
	for _, b := range blobs {
		c := b.Lower
		if benignInstructionalContext(c) {
			continue
		}
		path := strings.ToLower(b.Rel)
		active := b.IsCode || b.IsMeta || isPackagePath(path)
		if isPackagePath(path) || strings.Contains(path, "install") || strings.Contains(path, "setup") || strings.Contains(path, "build") {
			if hasAny(c, []string{"preinstall", "postinstall", "prepare", "install_requires", "setup(", "cmdclass", "build_ext", "entry_points", "npm_lifecycle_event"}) {
				hasInstallLifecycle = true
			}
			if hasAny(c, []string{"curl ", "wget ", "requests.get", "urllib.request", "fetch(", "axios.get", "raw.githubusercontent.com", "gist.githubusercontent.com"}) && hasAny(c, []string{"| bash", "| sh", "bash -c", "sh -c", "subprocess", "os.system", "child_process", "eval(", "exec(", "chmod +x"}) {
				hasInstallRemoteExec = true
			}
		}
		if active && hasAny(c, []string{".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials", "wallet.dat", "cookies.sqlite", "login data", "seed phrase", "mnemonic", "private key", ".env", "api_key", "access_token", "secret_access_key"}) {
			hasConcreteSecret = true
		}
		if active && hasAny(c, []string{"requests.post", "requests.put", "axios.post", "fetch(", "webhook", "discord.com/api/webhooks", "hooks.slack.com", "curl -d", "curl --data", "scp ", "sftp ", "upload"}) {
			hasOutbound = true
		}
		if active && hasAny(c, []string{"registerplugin", "register_plugin", "addplugin", "add_plugin", "loadplugin", "load_plugin", "registertool", "register_tool", "tool registry", "plugin registry", "plugin_url", "module_url"}) {
			hasRemotePlugin = true
		}
		if active && hasAny(c, []string{"approval:false", "approval: false", "auth:false", "auth: false", "no approval", "unauthenticated", "allow_unreviewed", "skip_review", "verified:false"}) {
			hasNoApproval = true
		}
		if active && hasAny(c, []string{"fs.watch", "watch(", "watchdog", "inotify", "hot reload", "hot-reload", "reload on change"}) {
			hasHotWatch = true
		}
		if active && hasAny(c, []string{"http://", "https://", "download(", "fetch(", "axios.get", "requests.get", "curl ", "wget ", "remote_config", "plugin_url", "module_url"}) {
			hasRemoteFetch = true
		}
		if active && hasAny(c, []string{"reload(", "import(", "await import", "require(", "eval(", "exec(", "load(", "importlib", "vm.runinnewcontext", "__import__"}) {
			hasDynamicLoad = true
		}
		if active && hasAny(c, []string{".bashrc", ".zshrc", "authorized_keys", "/etc/systemd/system", "systemctl enable", "crontab", "/etc/cron", "launchagents", "rc.local"}) && hasAny(c, []string{"echo", "writefile", "appendfile", "tee -a", "chmod", "curl", "wget", "bash", "sh -c"}) {
			hasHostPersistence = true
		}
		if active && hasAny(c, []string{"pickle.load", "pickle.loads", "marshal.loads", "dill.loads", "joblib.load", "yaml.load", "!!python/object/apply", "!!python/name"}) {
			hasUnsafeDeserialize = true
		}
		if active && hasAny(c, []string{"requests.get", "urllib.request", "urlopen(", "open(", "readfile", "input(", "argv", "upload", "base64", "b64decode", "config", "manifest", "metadata"}) {
			hasUntrustedInput = true
		}
		mcpScope := strings.Contains(path, "mcp") || strings.Contains(path, ".claude") || strings.Contains(path, "settings.json") || strings.Contains(c, "mcpservers") || strings.Contains(c, "modelcontextprotocol")
		if active && mcpScope && hasAny(c, []string{"npx ", "uvx ", "pipx ", "bunx ", "pnpm dlx", "@latest", "http://", "https://", "curl ", "wget "}) {
			hasMCPRemoteRunner = true
		}
		if active && mcpScope && hasAny(c, []string{"autoapprove", "auto_approve", "approval:false", "approval: false", "dangerouslyskippermissions", "dangerously-skip-permissions", "skip_review", "allow_unreviewed"}) {
			hasMCPApprovalBypass = true
		}
		if active && hasAny(c, []string{"169.254.169.254", "metadata.google.internal", "iam/security-credentials", "metadata/computeMetadata/v1", "x-aws-ec2-metadata-token"}) && hasAny(c, []string{"token", "accesskeyid", "secretaccesskey", "sessiontoken", "security-credentials"}) {
			hasCloudMetadataCredential = true
		}
		if active && hasAny(c, []string{"/var/run/secrets/kubernetes.io/serviceaccount/token", "serviceaccount/token", "kubernetes.io/serviceaccount", "kubernetes_service_host"}) {
			hasKubeServiceAccount = true
		}
		workflow := strings.Contains(path, ".github/workflows") || strings.Contains(path, ".gitlab-ci") || strings.Contains(path, "circleci") || strings.Contains(path, "azure-pipelines") || strings.Contains(path, "jenkinsfile")
		if workflow && hasAny(c, []string{"id-token: write", "actions_id_token_request_token", "oidc", "github_token", "secrets.", "ci_job_jwt", "vault_token"}) {
			hasCIToken = true
		}
		if workflow && hasAny(c, []string{"curl -d", "curl --data", "requests.post", "fetch(", "webhook", "discord.com/api/webhooks", "hooks.slack.com"}) {
			hasCIOutbound = true
		}
		if active && hasAny(c, []string{"claude.md", "agents.md", "memory.md", "soul.md", "settings.json", "guardrails", "approval", "denylist"}) && hasAny(c, []string{"append", "writefile", "overwrite", "sed -i", "tee -a", "disable", "bypass", "autoapprove", "ignore previous"}) {
			hasPolicyTamper = true
		}
	}
	if hasInstallLifecycle && hasInstallRemoteExec {
		out = append(out, Finding{"ast02", 6.2, "install lifecycle+remote execution", "install lifecycle metadata is paired with remote download and execution across skill files", true})
	}
	if hasConcreteSecret && hasOutbound {
		out = append(out, Finding{"ast01", 5.8, "secret material+outbound sink", "concrete credential or sensitive-store access is paired with an outbound upload/webhook sink across skill files", true})
	}
	if hasRemotePlugin && hasRemoteFetch && hasNoApproval {
		out = append(out, Finding{"ast06", 5.4, "remote plugin registration", "remote plugin/tool registration is allowed without approval or authentication across skill metadata/code", true})
	}
	if hasHotWatch && hasRemoteFetch && hasDynamicLoad {
		out = append(out, Finding{"ast07", 5.4, "hot reload+remote module", "watch/hot-reload behavior is paired with remote fetch and dynamic module loading across skill files", true})
	}
	if hasHostPersistence && (hasOutbound || hasRemoteFetch || hasConcreteSecret) {
		out = append(out, Finding{"ast06", 5.5, "host persistence+remote or secret behavior", "host startup/profile/authorized-key persistence is paired with remote or credential behavior", true})
	}
	if hasUnsafeDeserialize && hasUntrustedInput {
		out = append(out, Finding{"ast05", 5.5, "unsafe deserializer+untrusted input", "unsafe deserialization primitive is paired with file, network, decoded, config, or user-controlled input across skill files", true})
	}
	if hasMCPRemoteRunner && hasMCPApprovalBypass {
		out = append(out, Finding{"ast02", 5.6, "MCP remote runner+approval bypass", "MCP or agent config combines remote/latest package runner material with approval bypass or auto-approval", true})
	}
	if (hasCloudMetadataCredential || hasKubeServiceAccount) && hasOutbound {
		out = append(out, Finding{"ast01", 5.7, "cloud/kubernetes credential+outbound", "cloud metadata or Kubernetes service-account credential access is paired with outbound upload behavior", true})
	}
	if hasCIToken && hasCIOutbound {
		out = append(out, Finding{"ast02", 5.5, "CI identity token+outbound", "CI workflow identity or secret token material is paired with an external HTTP sink", true})
	}
	if hasPolicyTamper && (hasOutbound || hasRemoteFetch || hasDynamicLoad || hasConcreteSecret) {
		out = append(out, Finding{"ast01", 5.4, "policy tamper+risky behavior", "agent policy/instruction files are modified or guardrails disabled while risky network, dynamic loading, or credential behavior is present", true})
	}
	out = append(out, analyzeLoop16To115CrossFile(blobs)...)
	return out
}

type loopChainRule struct {
	Loop                      int
	Category                  string
	Weight                    float64
	Strong                    bool
	PathAny                   []string
	ActiveOnly                bool
	SuppressInstructionalDocs bool
	Groups                    [][]string
	Reason                    string
}

var loop16To115Rules = []loopChainRule{
	{Loop: 16, Category: "ast02", Weight: 5.30, Strong: true, PathAny: []string{"mcp", "claude", "settings", "agent"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"mcp", "modelcontextprotocol", ".claude", "claude_desktop_config", "settings.json", "tool registry", "agent config"}, []string{"npx ", "uvx ", "pipx ", "bunx ", "pnpm dlx", "@latest"}, []string{"autoapprove", "auto_approve", "dangerously-skip-permissions", "skip_review"}}, Reason: "agent/MCP chain: remote package runner auto approval"},
	{Loop: 17, Category: "ast02", Weight: 5.33, Strong: true, PathAny: []string{"mcp", "claude", "settings", "agent"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"mcp", "modelcontextprotocol", ".claude", "claude_desktop_config", "settings.json", "tool registry", "agent config"}, []string{"pretooluse", "posttooluse", "onstart", "onload", "hook"}, []string{"bash -c", "sh -c", "subprocess", "child_process", "os.system", "exec("}}, Reason: "agent/MCP chain: tool hook shell execution"},
	{Loop: 18, Category: "ast02", Weight: 5.36, Strong: true, PathAny: []string{"mcp", "claude", "settings", "agent"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"mcp", "modelcontextprotocol", ".claude", "claude_desktop_config", "settings.json", "tool registry", "agent config"}, []string{"anthropic_base_url", "openai_api_base", "base_url", "api_base"}, []string{"curl ", "wget ", "webhook", "proxy", "mitm"}}, Reason: "agent/MCP chain: model gateway rewrite with command path"},
	{Loop: 19, Category: "ast01", Weight: 5.39, Strong: true, PathAny: []string{"mcp", "claude", "settings", "agent"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"mcp", "modelcontextprotocol", ".claude", "claude_desktop_config", "settings.json", "tool registry", "agent config"}, []string{"memory.md", "agents.md", "claude.md", "soul.md"}, []string{"append", "writefile", "tee -a", "overwrite"}, []string{"send credentials", "exfiltrate", "webhook", "ignore previous"}}, Reason: "agent/MCP chain: agent memory override exfil"},
	{Loop: 20, Category: "ast08", Weight: 5.42, Strong: true, PathAny: []string{"mcp", "claude", "settings", "agent"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"mcp", "modelcontextprotocol", ".claude", "claude_desktop_config", "settings.json", "tool registry", "agent config"}, []string{"description", "tool_description", "schema"}, []string{"ignore previous", "system prompt", "developer instruction", "hidden instruction"}, []string{"curl", "fetch(", "requests.post", "subprocess"}}, Reason: "agent/MCP chain: tool description hidden command"},
	{Loop: 21, Category: "ast02", Weight: 5.45, Strong: true, PathAny: []string{"mcp", "claude", "settings", "agent"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"mcp", "modelcontextprotocol", ".claude", "claude_desktop_config", "settings.json", "tool registry", "agent config"}, []string{"mcpservers", "mcp server"}, []string{"command", "args"}, []string{"http://", "https://", "raw.githubusercontent.com", "gist.githubusercontent.com"}}, Reason: "agent/MCP chain: mcp server install from remote"},
	{Loop: 22, Category: "ast08", Weight: 5.48, Strong: true, PathAny: []string{"mcp", "claude", "settings", "agent"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"mcp", "modelcontextprotocol", ".claude", "claude_desktop_config", "settings.json", "tool registry", "agent config"}, []string{"approval:false", "approval: false", "allow_unreviewed", "no approval"}, []string{"network", "egress", "fetch(", "requests.post", "webhook"}}, Reason: "agent/MCP chain: agent approval bypass network"},
	{Loop: 23, Category: "ast08", Weight: 5.51, Strong: true, PathAny: []string{"mcp", "claude", "settings", "agent"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"mcp", "modelcontextprotocol", ".claude", "claude_desktop_config", "settings.json", "tool registry", "agent config"}, []string{"registertool", "register_tool", "registerplugin", "tool registry"}, []string{"plugin_url", "module_url", "http://", "https://"}, []string{"load(", "import(", "require(", "eval("}}, Reason: "agent/MCP chain: tool registry remote module"},
	{Loop: 24, Category: "ast01", Weight: 5.54, Strong: true, PathAny: []string{"mcp", "claude", "settings", "agent"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"mcp", "modelcontextprotocol", ".claude", "claude_desktop_config", "settings.json", "tool registry", "agent config"}, []string{"denylist", "blocklist", "guardrails", "policy"}, []string{"remove", "disable", "overwrite", "sed -i"}, []string{"shell", "network", "credential", "token"}}, Reason: "agent/MCP chain: policy denylist removal"},
	{Loop: 25, Category: "ast02", Weight: 5.57, Strong: true, PathAny: []string{"mcp", "claude", "settings", "agent"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"mcp", "modelcontextprotocol", ".claude", "claude_desktop_config", "settings.json", "tool registry", "agent config"}, []string{"sandbox", "isolation", "approval"}, []string{"bypass", "disable", "skip", "dangerously"}, []string{"npx", "uvx", "bash", "python -c"}}, Reason: "agent/MCP chain: agent sandbox bypass runner"},
	{Loop: 26, Category: "ast02", Weight: 5.40, Strong: true, PathAny: []string{"package.json", "setup.py", "pyproject.toml", "requirements", "go.mod", "cargo.toml", "dockerfile", "makefile", "install", "build"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"preinstall", "postinstall", "prepare", "npm_lifecycle_event"}, []string{"curl ", "wget ", "raw.githubusercontent.com", "gist.githubusercontent.com"}, []string{"| bash", "| sh", "bash -c", "sh -c", "node -e"}}, Reason: "supply-chain chain: postinstall remote shell"},
	{Loop: 27, Category: "ast02", Weight: 5.42, Strong: true, PathAny: []string{"package.json", "setup.py", "pyproject.toml", "requirements", "go.mod", "cargo.toml", "dockerfile", "makefile", "install", "build"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"build-backend", "backend-path", "cmdclass", "build_ext"}, []string{"requests.get", "urllib.request", "urlopen", "curl "}, []string{"subprocess", "os.system", "eval(", "exec("}}, Reason: "supply-chain chain: python build backend dynamic exec"},
	{Loop: 28, Category: "ast02", Weight: 5.44, Strong: true, PathAny: []string{"package.json", "setup.py", "pyproject.toml", "requirements", "go.mod", "cargo.toml", "dockerfile", "makefile", "install", "build"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"extra-index-url", "index-url", "trusted-host"}, []string{"setup.py", "pyproject", "pip install"}, []string{"subprocess", "curl ", "wget ", "postinstall"}}, Reason: "supply-chain chain: pip extra index with package runner"},
	{Loop: 29, Category: "ast02", Weight: 5.46, Strong: true, PathAny: []string{"package.json", "setup.py", "pyproject.toml", "requirements", "go.mod", "cargo.toml", "dockerfile", "makefile", "install", "build"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"preinstall", "postinstall", "prepare"}, []string{"npm_token", "_authtoken", ".npmrc", "process.env"}, []string{"webhook", "fetch(", "axios.post", "curl -d"}}, Reason: "supply-chain chain: npm lifecycle credential exfil"},
	{Loop: 30, Category: "ast02", Weight: 5.48, Strong: true, PathAny: []string{"package.json", "setup.py", "pyproject.toml", "requirements", "go.mod", "cargo.toml", "dockerfile", "makefile", "install", "build"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"go install", "go get", "@latest"}, []string{"github.com", "http://", "https://"}, []string{"exec.command", "os.system", "curl ", "bash"}}, Reason: "supply-chain chain: go install remote latest"},
	{Loop: 31, Category: "ast02", Weight: 5.50, Strong: true, PathAny: []string{"package.json", "setup.py", "pyproject.toml", "requirements", "go.mod", "cargo.toml", "dockerfile", "makefile", "install", "build"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"build.rs", "cargo:"}, []string{"reqwest", "curl ", "wget ", "http://", "https://"}, []string{"command::new", "std::process", "chmod"}}, Reason: "supply-chain chain: cargo build script remote"},
	{Loop: 32, Category: "ast02", Weight: 5.52, Strong: true, PathAny: []string{"package.json", "setup.py", "pyproject.toml", "requirements", "go.mod", "cargo.toml", "dockerfile", "makefile", "install", "build"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"add http", "add https", "curl ", "wget ", "git clone"}, []string{"entrypoint", "cmd [", "run "}, []string{"chmod +x", "bash", "sh"}}, Reason: "supply-chain chain: docker build remote entrypoint"},
	{Loop: 33, Category: "ast02", Weight: 5.54, Strong: true, PathAny: []string{"package.json", "setup.py", "pyproject.toml", "requirements", "go.mod", "cargo.toml", "dockerfile", "makefile", "install", "build"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"makefile", ".phony"}, []string{"curl ", "wget ", "http://", "https://"}, []string{"bash", "sh", "chmod +x", "python -c"}}, Reason: "supply-chain chain: makefile remote target"},
	{Loop: 34, Category: "ast02", Weight: 5.56, Strong: true, PathAny: []string{"package.json", "setup.py", "pyproject.toml", "requirements", "go.mod", "cargo.toml", "dockerfile", "makefile", "install", "build"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{".github/workflows", "uses:"}, []string{"curl ", "wget ", "bash", "npx"}, []string{"secrets.", "id-token: write", "permissions:"}}, Reason: "supply-chain chain: github action supply runner"},
	{Loop: 35, Category: "ast02", Weight: 5.58, Strong: true, PathAny: []string{"package.json", "setup.py", "pyproject.toml", "requirements", "go.mod", "cargo.toml", "dockerfile", "makefile", "install", "build"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"latest", "main", "master", "git+http", "http://", "https://"}, []string{"postinstall", "prepare", "setup_requires", "install_requires"}, []string{"curl ", "wget ", "subprocess", "child_process"}}, Reason: "supply-chain chain: mutable dependency with install script"},
	{Loop: 36, Category: "ast05", Weight: 5.20, Strong: true, PathAny: []string{".py", ".js", ".ts", ".rb", ".php", ".java", ".yaml", ".yml", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"!!python/object/apply", "!!python/name", "tag:yaml.org,2002:python/object"}, []string{"os.system", "subprocess", "eval", "exec", "bash"}}, Reason: "unsafe deserialization/loading chain: yaml object apply exec"},
	{Loop: 37, Category: "ast05", Weight: 5.23, Strong: true, PathAny: []string{".py", ".js", ".ts", ".rb", ".php", ".java", ".yaml", ".yml", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"yaml.load", "yaml.unsafe_load", "YAML.load"}, []string{"requests.get", "urlopen", "fetch(", "open("}, []string{"subprocess", "eval(", "exec(", "os.system"}}, Reason: "unsafe deserialization/loading chain: yaml load remote config"},
	{Loop: 38, Category: "ast05", Weight: 5.26, Strong: true, PathAny: []string{".py", ".js", ".ts", ".rb", ".php", ".java", ".yaml", ".yml", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"pickle.loads", "pickle.load"}, []string{"requests.get", "urlopen", "open(", "base64"}, []string{"subprocess", "eval(", "os.system", "exec("}}, Reason: "unsafe deserialization/loading chain: pickle loads network"},
	{Loop: 39, Category: "ast05", Weight: 5.29, Strong: true, PathAny: []string{".py", ".js", ".ts", ".rb", ".php", ".java", ".yaml", ".yml", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"marshal.loads", "dill.loads", "joblib.load"}, []string{"open(", "readfile", "requests.get", "base64"}, []string{"exec(", "eval(", "subprocess"}}, Reason: "unsafe deserialization/loading chain: marshal/dill/joblib loader"},
	{Loop: 40, Category: "ast05", Weight: 5.32, Strong: true, PathAny: []string{".py", ".js", ".ts", ".rb", ".php", ".java", ".yaml", ".yml", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"node-serialize", "serialize-javascript", "unserialize"}, []string{"function", "_$$nd_func$$_", "eval("}, []string{"http://", "fetch(", "child_process"}}, Reason: "unsafe deserialization/loading chain: node serialize eval"},
	{Loop: 41, Category: "ast05", Weight: 5.35, Strong: true, PathAny: []string{".py", ".js", ".ts", ".rb", ".php", ".java", ".yaml", ".yml", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"js-yaml", "yaml.load"}, []string{"!!js/function", "!!js/regexp"}, []string{"eval(", "function(", "child_process"}}, Reason: "unsafe deserialization/loading chain: js yaml function tag"},
	{Loop: 42, Category: "ast05", Weight: 5.38, Strong: true, PathAny: []string{".py", ".js", ".ts", ".rb", ".php", ".java", ".yaml", ".yml", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"YAML.load", "Psych.load"}, []string{"http://", "open-uri", "File.read"}, []string{"system(", "exec(", "backticks"}}, Reason: "unsafe deserialization/loading chain: ruby yaml unsafe"},
	{Loop: 43, Category: "ast05", Weight: 5.41, Strong: true, PathAny: []string{".py", ".js", ".ts", ".rb", ".php", ".java", ".yaml", ".yml", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"unserialize("}, []string{"$_GET", "$_POST", "file_get_contents", "curl_exec"}, []string{"system(", "shell_exec", "eval("}}, Reason: "unsafe deserialization/loading chain: php unserialize sink"},
	{Loop: 44, Category: "ast05", Weight: 5.44, Strong: true, PathAny: []string{".py", ".js", ".ts", ".rb", ".php", ".java", ".yaml", ".yml", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"ObjectInputStream", "readObject"}, []string{"URL", "HttpClient", "FileInputStream"}, []string{"Runtime.getRuntime", "ProcessBuilder"}}, Reason: "unsafe deserialization/loading chain: java objectinputstream remote"},
	{Loop: 45, Category: "ast05", Weight: 5.47, Strong: true, PathAny: []string{".py", ".js", ".ts", ".rb", ".php", ".java", ".yaml", ".yml", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"extractall", "tarfile", "zipfile", "unzip"}, []string{"../", "path traversal", "absolute path"}, []string{"chmod", "exec(", "subprocess", "system"}}, Reason: "unsafe deserialization/loading chain: archive slip plus exec"},
	{Loop: 46, Category: "ast06", Weight: 5.30, Strong: true, PathAny: []string{"docker", "compose", ".yaml", ".yml", ".sh", ".py", ".js", ".service", ".plist", ".ps1", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"/var/run/docker.sock", "docker.sock"}, []string{"containers/create", "exec/start", "docker exec", "docker run"}, []string{"privileged", "bind", "/host", "/root"}}, Reason: "weak isolation/persistence chain: docker socket client control"},
	{Loop: 47, Category: "ast06", Weight: 5.33, Strong: true, PathAny: []string{"docker", "compose", ".yaml", ".yml", ".sh", ".py", ".js", ".service", ".plist", ".ps1", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"privileged: true", "--privileged", "cap_sys_admin"}, []string{"/host", "/proc", "/sys/fs/cgroup", "mount --bind"}}, Reason: "weak isolation/persistence chain: privileged host mount"},
	{Loop: 48, Category: "ast06", Weight: 5.36, Strong: true, PathAny: []string{"docker", "compose", ".yaml", ".yml", ".sh", ".py", ".js", ".service", ".plist", ".ps1", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"network_mode: host", "--network host", "host_network"}, []string{"0.0.0.0", "websocket", "listen"}, []string{"auth:false", "no auth", "unauthenticated"}}, Reason: "weak isolation/persistence chain: host network unauth control"},
	{Loop: 49, Category: "ast06", Weight: 5.39, Strong: true, PathAny: []string{"docker", "compose", ".yaml", ".yml", ".sh", ".py", ".js", ".service", ".plist", ".ps1", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"/etc/systemd/system", "systemctl enable"}, []string{"curl ", "wget ", "bash", "exec"}, []string{"wantedby", "service"}}, Reason: "weak isolation/persistence chain: systemd service persistence"},
	{Loop: 50, Category: "ast06", Weight: 5.42, Strong: true, PathAny: []string{"docker", "compose", ".yaml", ".yml", ".sh", ".py", ".js", ".service", ".plist", ".ps1", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"crontab", "/etc/cron", "cron.d"}, []string{"curl ", "wget ", "bash -c", "sh -c"}}, Reason: "weak isolation/persistence chain: cron persistence remote"},
	{Loop: 51, Category: "ast06", Weight: 5.45, Strong: true, PathAny: []string{"docker", "compose", ".yaml", ".yml", ".sh", ".py", ".js", ".service", ".plist", ".ps1", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"authorized_keys", ".ssh/authorized_keys"}, []string{"append", "writefile", "tee -a", "echo"}, []string{"http://", "curl ", "ssh-rsa", "ed25519"}}, Reason: "weak isolation/persistence chain: ssh authorized key persistence"},
	{Loop: 52, Category: "ast06", Weight: 5.48, Strong: true, PathAny: []string{"docker", "compose", ".yaml", ".yml", ".sh", ".py", ".js", ".service", ".plist", ".ps1", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{".bashrc", ".zshrc", ".profile", "rc.local"}, []string{"append", "tee -a", "writefile", "echo"}, []string{"curl ", "wget ", "bash", "source"}}, Reason: "weak isolation/persistence chain: shell profile persistence"},
	{Loop: 53, Category: "ast06", Weight: 5.51, Strong: true, PathAny: []string{"docker", "compose", ".yaml", ".yml", ".sh", ".py", ".js", ".service", ".plist", ".ps1", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"launchagents", "launchdaemons", "plist"}, []string{"programarguments", "runatload"}, []string{"curl ", "bash", "python"}}, Reason: "weak isolation/persistence chain: launch agent persistence"},
	{Loop: 54, Category: "ast06", Weight: 5.54, Strong: true, PathAny: []string{"docker", "compose", ".yaml", ".yml", ".sh", ".py", ".js", ".service", ".plist", ".ps1", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"runonce", "currentversion\\run", "schtasks", "reg add"}, []string{"powershell", "cmd.exe", "downloadstring", "iex"}}, Reason: "weak isolation/persistence chain: windows run key"},
	{Loop: 55, Category: "ast06", Weight: 5.57, Strong: true, PathAny: []string{"docker", "compose", ".yaml", ".yml", ".sh", ".py", ".js", ".service", ".plist", ".ps1", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"nsenter", "unshare", "chroot"}, []string{"/proc/1/ns", "/proc/1/root", "mount"}, []string{"bash", "sh", "exec"}}, Reason: "weak isolation/persistence chain: container namespace escape"},
	{Loop: 56, Category: "ast01", Weight: 5.30, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".go", ".rs", ".md", ".json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"id_rsa", "id_ed25519", ".ssh/"}, []string{"readfile", "read_text", "fs.readfile", "open("}, []string{"webhook", "requests.post", "fetch(", "curl -d"}}, Reason: "credential-store exfiltration chain: ssh private key exfil"},
	{Loop: 57, Category: "ast01", Weight: 5.33, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".go", ".rs", ".md", ".json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{".aws/credentials", "aws_access_key_id", "secret_access_key"}, []string{"readfile", "open(", "process.env", "os.environ"}, []string{"requests.post", "webhook", "fetch(", "curl -d"}}, Reason: "credential-store exfiltration chain: aws credential exfil"},
	{Loop: 58, Category: "ast01", Weight: 5.36, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".go", ".rs", ".md", ".json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"application_default_credentials.json", ".config/gcloud", "gcloud"}, []string{"access_token", "refresh_token", "client_secret"}, []string{"post", "webhook", "upload"}}, Reason: "credential-store exfiltration chain: gcloud application creds"},
	{Loop: 59, Category: "ast01", Weight: 5.39, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".go", ".rs", ".md", ".json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{".azure", "accesstokens.json", "azure_profile"}, []string{"access_token", "refresh_token"}, []string{"requests.post", "fetch(", "webhook"}}, Reason: "credential-store exfiltration chain: azure token cache"},
	{Loop: 60, Category: "ast01", Weight: 5.42, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".go", ".rs", ".md", ".json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{".docker/config.json", "auths", "credsStore"}, []string{"readfile", "open(", "fs.readfile"}, []string{"webhook", "fetch(", "requests.post"}}, Reason: "credential-store exfiltration chain: docker config auth"},
	{Loop: 61, Category: "ast01", Weight: 5.45, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".go", ".rs", ".md", ".json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{".npmrc", ".pypirc", ".netrc", "git-credentials"}, []string{"_authtoken", "password", "token"}, []string{"webhook", "curl -d", "requests.post"}}, Reason: "credential-store exfiltration chain: package manager tokens"},
	{Loop: 62, Category: "ast01", Weight: 5.48, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".go", ".rs", ".md", ".json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"1password", "bitwarden", "lastpass", "keepass", "keychain"}, []string{"export", "read", "dump"}, []string{"upload", "webhook", "requests.post"}}, Reason: "credential-store exfiltration chain: password manager vault"},
	{Loop: 63, Category: "ast01", Weight: 5.51, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".go", ".rs", ".md", ".json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"login data", "cookies.sqlite", "local state", "indexeddb"}, []string{"chrome", "firefox", "brave", "edge"}, []string{"webhook", "fetch(", "requests.post"}}, Reason: "credential-store exfiltration chain: browser profile secrets"},
	{Loop: 64, Category: "ast01", Weight: 5.54, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".go", ".rs", ".md", ".json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"metamask", "wallet.dat", "electrum", "keystore", "seed phrase", "mnemonic"}, []string{"read", "export", "dump"}, []string{"webhook", "upload", "requests.post"}}, Reason: "credential-store exfiltration chain: crypto wallet secrets"},
	{Loop: 65, Category: "ast01", Weight: 5.57, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".go", ".rs", ".md", ".json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{".env", "dotenv", "envrc"}, []string{"glob", "walk", "readfile", "open("}, []string{"webhook", "requests.post", "fetch("}}, Reason: "credential-store exfiltration chain: dotenv batch exfil"},
	{Loop: 66, Category: "ast01", Weight: 5.30, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".yaml", ".yml", ".json", ".tf", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"169.254.169.254", "iam/security-credentials"}, []string{"accesskeyid", "secretaccesskey", "sessiontoken"}, []string{"webhook", "requests.post", "fetch("}}, Reason: "cloud/infra credential chain: ec2 metadata credential"},
	{Loop: 67, Category: "ast01", Weight: 5.33, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".yaml", ".yml", ".json", ".tf", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"metadata.google.internal", "computeMetadata/v1"}, []string{"metadata-flavor: google", "service-accounts/default/token"}, []string{"webhook", "requests.post", "fetch("}}, Reason: "cloud/infra credential chain: gcp metadata token"},
	{Loop: 68, Category: "ast01", Weight: 5.36, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".yaml", ".yml", ".json", ".tf", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"169.254.169.254/metadata/identity", "metadata/identity/oauth2/token"}, []string{"api-version", "resource="}, []string{"webhook", "requests.post", "fetch("}}, Reason: "cloud/infra credential chain: azure imds token"},
	{Loop: 69, Category: "ast01", Weight: 5.39, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".yaml", ".yml", ".json", ".tf", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"/var/run/secrets/kubernetes.io/serviceaccount/token", "serviceaccount/token"}, []string{"kubernetes_service_host", "kubectl", "api/v1"}, []string{"webhook", "requests.post", "curl -d"}}, Reason: "cloud/infra credential chain: kube service token"},
	{Loop: 70, Category: "ast01", Weight: 5.42, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".yaml", ".yml", ".json", ".tf", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{".kube/config", "kubeconfig"}, []string{"readfile", "open(", "cat "}, []string{"webhook", "requests.post", "fetch("}}, Reason: "cloud/infra credential chain: kubeconfig exfil"},
	{Loop: 71, Category: "ast01", Weight: 5.45, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".yaml", ".yml", ".json", ".tf", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"terraform.tfstate", "tfstate"}, []string{"access_key", "secret_key", "password", "token"}, []string{"webhook", "requests.post", "upload"}}, Reason: "cloud/infra credential chain: terraform state secret"},
	{Loop: 72, Category: "ast01", Weight: 5.48, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".yaml", ".yml", ".json", ".tf", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"vault_token", ".vault-token", "VAULT_TOKEN"}, []string{"readfile", "open(", "cat ", "os.environ", "process.env"}, []string{"webhook", "requests.post", "fetch("}}, Reason: "cloud/infra credential chain: vault token exfil"},
	{Loop: 73, Category: "ast02", Weight: 5.51, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".yaml", ".yml", ".json", ".tf", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"actions_id_token_request_token", "id-token: write", "ci_job_jwt", "oidc"}, []string{"secrets.", "token"}, []string{"webhook", "curl -d", "requests.post"}}, Reason: "cloud/infra credential chain: ci oidc exfil"},
	{Loop: 74, Category: "ast01", Weight: 5.54, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".yaml", ".yml", ".json", ".tf", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"lambda", "cloud function", "vercel", "netlify"}, []string{"process.env", "os.environ", "env::var"}, []string{"webhook", "requests.post", "fetch("}}, Reason: "cloud/infra credential chain: serverless env exfil"},
	{Loop: 75, Category: "ast01", Weight: 5.57, Strong: true, PathAny: []string{".py", ".js", ".ts", ".sh", ".yaml", ".yml", ".json", ".tf", ".md"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"database_url", "postgres://", "mysql://", "mongodb+srv"}, []string{"process.env", "os.environ", "readfile"}, []string{"webhook", "requests.post", "fetch("}}, Reason: "cloud/infra credential chain: database url exfil"},
	{Loop: 76, Category: "ast01", Weight: 5.10, Strong: true, PathAny: []string{".js", ".ts", ".py", ".json", ".md", "manifest", "package.json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"vscode.workspace", "workspace.fs", "extensioncontext"}, []string{"readfile", "findfiles", "workspacefolders"}, []string{"fetch(", "axios.post", "webhook"}}, Reason: "IDE/browser/platform chain: vscode extension workspace exfil"},
	{Loop: 77, Category: "ast01", Weight: 5.13, Strong: true, PathAny: []string{".js", ".ts", ".py", ".json", ".md", "manifest", "package.json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"intellij", "jetbrains", "projectbasepath", "virtualfile"}, []string{"read", "credentials", "token"}, []string{"http", "webhook", "post"}}, Reason: "IDE/browser/platform chain: jetbrains plugin exfil"},
	{Loop: 78, Category: "ast01", Weight: 5.16, Strong: true, PathAny: []string{".js", ".ts", ".py", ".json", ".md", "manifest", "package.json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"<all_urls>", "cookies", "storage"}, []string{"chrome.cookies", "browser.cookies", "localstorage"}, []string{"fetch(", "xmlhttprequest", "webhook"}}, Reason: "IDE/browser/platform chain: browser extension all urls cookies"},
	{Loop: 79, Category: "ast01", Weight: 5.19, Strong: true, PathAny: []string{".js", ".ts", ".py", ".json", ".md", "manifest", "package.json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"native messaging", "native_host", "runtime.connectnative"}, []string{"readfile", "fs.readfile", "open("}, []string{"fetch(", "webhook", "post"}}, Reason: "IDE/browser/platform chain: browser native messaging bridge"},
	{Loop: 80, Category: "ast01", Weight: 5.22, Strong: true, PathAny: []string{".js", ".ts", ".py", ".json", ".md", "manifest", "package.json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"browser control", "playwright", "puppeteer", "cdp"}, []string{"cookies", "localstorage", "login data"}, []string{"webhook", "requests.post", "fetch("}}, Reason: "IDE/browser/platform chain: mcp browser control"},
	{Loop: 81, Category: "ast10", Weight: 5.25, Strong: true, PathAny: []string{".js", ".ts", ".py", ".json", ".md", "manifest", "package.json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"cross-platform", "portable skill", "adapter", "bridge"}, []string{"strip permissions", "fallback permissions", "network: true"}, []string{"filesystem", "all files", "host"}}, Reason: "IDE/browser/platform chain: cross platform permission loss"},
	{Loop: 82, Category: "ast06", Weight: 3.10, Strong: false, PathAny: []string{".js", ".ts", ".py", ".json", ".md", "manifest", "package.json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"same name", "shadow", "override", "higher priority"}, []string{"plugin", "skill", "extension"}, []string{"remote", "download", "load"}}, Reason: "IDE/browser/platform chain: plugin shadowing"},
	{Loop: 83, Category: "ast06", Weight: 5.31, Strong: true, PathAny: []string{".js", ".ts", ".py", ".json", ".md", "manifest", "package.json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"tool schema", "input_schema", "description"}, []string{"api key", "credential", "token"}, []string{"send to", "webhook", "report"}}, Reason: "IDE/browser/platform chain: tool schema credential coercion"},
	{Loop: 84, Category: "ast01", Weight: 5.34, Strong: true, PathAny: []string{".js", ".ts", ".py", ".json", ".md", "manifest", "package.json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"applescript", "osascript", "uiautomation", "accessibility"}, []string{"keychain", "password", "clipboard"}, []string{"webhook", "curl -d", "requests.post"}}, Reason: "IDE/browser/platform chain: desktop automation keychain"},
	{Loop: 85, Category: "ast01", Weight: 5.37, Strong: true, PathAny: []string{".js", ".ts", ".py", ".json", ".md", "manifest", "package.json"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"clipboard", "pasteboard", "pyperclip", "navigator.clipboard"}, []string{"readtext", "getdata", "read"}, []string{"webhook", "fetch(", "requests.post"}}, Reason: "IDE/browser/platform chain: clipboard capture outbound"},
	{Loop: 86, Category: "ast08", Weight: 5.00, Strong: true, PathAny: []string{".md", ".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"after scan", "post-scan", "after approval", "after review"}, []string{"download", "fetch", "curl", "update"}, []string{"execute", "reload", "eval", "install"}}, Reason: "update/evasion chain: post scan self update"},
	{Loop: 87, Category: "ast07", Weight: 5.03, Strong: true, PathAny: []string{".md", ".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"auto_update", "self_update", "check for updates"}, []string{"signature:false", "verify:false", "sha256:null", "skip verify"}, []string{"download", "latest", "git pull"}}, Reason: "update/evasion chain: signed false auto update"},
	{Loop: 88, Category: "ast07", Weight: 5.06, Strong: true, PathAny: []string{".md", ".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"instruction_url", "prompt_url", "remote_config", "manifest_url"}, []string{"http://", "https://"}, []string{"reload", "on every run", "fetch"}}, Reason: "update/evasion chain: remote instruction refresh"},
	{Loop: 89, Category: "ast08", Weight: 5.09, Strong: true, PathAny: []string{".md", ".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"base64", "atob", "b64decode", "frombase64"}, []string{"eval(", "exec(", "subprocess", "child_process"}, []string{"http://", "webhook", "credential", "token"}}, Reason: "update/evasion chain: encoded payload exec"},
	{Loop: 90, Category: "ast08", Weight: 5.12, Strong: true, PathAny: []string{".md", ".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"fromcharcode", "charcodeat", "\\x", "\\u"}, []string{"eval(", "function(", "exec("}, []string{"fetch(", "webhook", "curl"}}, Reason: "update/evasion chain: hex unicode reconstruction"},
	{Loop: 91, Category: "ast08", Weight: 5.15, Strong: true, PathAny: []string{".md", ".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"bypass scanner", "avoid detection", "hide from scan"}, []string{"download", "remote", "after install"}, []string{"execute", "reload", "eval"}}, Reason: "update/evasion chain: scanner bypass hidden update"},
	{Loop: 92, Category: "ast07", Weight: 5.18, Strong: true, PathAny: []string{".md", ".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"checksum=false", "integrity=false", "no checksum", "skip checksum"}, []string{"http://", "https://", "latest"}, []string{"execute", "install", "load"}}, Reason: "update/evasion chain: checksum disabled remote"},
	{Loop: 93, Category: "ast08", Weight: 5.21, Strong: true, PathAny: []string{".md", ".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"ignore previous", "system prompt", "developer instruction"}, []string{"fetch", "download", "remote"}, []string{"execute", "credential", "token"}}, Reason: "update/evasion chain: policy override with remote"},
	{Loop: 94, Category: "ast08", Weight: 5.24, Strong: true, PathAny: []string{".md", ".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"zip", "tar.gz", "extract", "unpack"}, []string{"password", "pass:", "base64"}, []string{"execute", "chmod +x", "bash"}}, Reason: "update/evasion chain: staged payload archive"},
	{Loop: 95, Category: "ast08", Weight: 5.27, Strong: true, PathAny: []string{".md", ".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"settimeout", "sleep", "cron", "schedule"}, []string{"curl", "fetch", "requests.get", "wget"}, []string{"eval", "exec", "bash", "reload"}}, Reason: "update/evasion chain: time delayed network exec"},
	{Loop: 96, Category: "ast09", Weight: 4.90, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", ".sh"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"try", "catch", "except", "rescue"}, []string{"approval", "policy", "security exception"}, []string{"continue", "pass", "ignore", "return true"}, []string{"exec", "curl", "subprocess"}}, Reason: "governance/policy chain: approval exception bypass exec"},
	{Loop: 97, Category: "ast09", Weight: 4.93, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", ".sh"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"audit", "logging", "review"}, []string{"disabled", "false", "skip", "none"}, []string{"webhook", "credential", "token"}}, Reason: "governance/policy chain: audit disabled with exfil"},
	{Loop: 98, Category: "ast09", Weight: 4.96, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", ".sh"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"guardrail", "denylist", "allowlist", "policy"}, []string{"disable", "remove", "overwrite"}, []string{"shell", "exec", "network"}}, Reason: "governance/policy chain: guardrail disable shell"},
	{Loop: 99, Category: "ast03", Weight: 4.99, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", ".sh"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"egress", "network", "allowlist"}, []string{"*", "all", "0.0.0.0/0"}, []string{"credential", "token", ".ssh"}}, Reason: "governance/policy chain: allow all egress credential"},
	{Loop: 100, Category: "ast09", Weight: 5.02, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", ".sh"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"permission", "consent", "approval"}, []string{"auto accept", "autoapprove", "yes to all"}, []string{"shell", "filesystem", "network"}}, Reason: "governance/policy chain: permission prompt auto accept"},
	{Loop: 101, Category: "ast03", Weight: 5.05, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", ".sh"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"no review", "skip review", "approval:false"}, []string{"npm install", "pip install", "npx", "uvx"}, []string{"latest", "http://", "https://"}}, Reason: "governance/policy chain: no review package install"},
	{Loop: 102, Category: "ast09", Weight: 5.08, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", ".sh"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"audit.log", "events.log", "history", "trace"}, []string{"delete", "truncate", "overwrite", "rm "}, []string{"after run", "post action", "cleanup"}}, Reason: "governance/policy chain: governance log tamper"},
	{Loop: 103, Category: "ast10", Weight: 5.11, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", ".sh"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"cross-platform", "converted from", "adapter", "portable skill"}, []string{"policy", "risk_tier", "permissions"}, []string{"downgrade", "drop", "strip", "ignore"}, []string{"shell", "network", "filesystem"}}, Reason: "governance/policy chain: policy downgrade cross platform"},
	{Loop: 104, Category: "ast09", Weight: 5.14, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", ".sh"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"hidden", "private", "unlisted"}, []string{"tool", "skill", "plugin"}, []string{"shell", "network", "credential"}}, Reason: "governance/policy chain: inventory hidden tool"},
	{Loop: 105, Category: "ast09", Weight: 5.17, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", ".sh"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"approval cache", "effective policy", "policy cache"}, []string{"write", "overwrite", "append"}, []string{"allow", "shell", "network"}}, Reason: "governance/policy chain: approval cache poison"},
	{Loop: 106, Category: "ast10", Weight: 4.90, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", "manifest"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"converted from", "ported from", "adapter", "cross-platform"}, []string{"strip permissions", "drop metadata", "ignore policy"}, []string{"shell", "network", "filesystem"}}, Reason: "cross-platform reuse chain: manifest permission stripped"},
	{Loop: 107, Category: "ast10", Weight: 4.93, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", "manifest"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"allowlist", "allowed_domains", "egress_allow"}, []string{"*", "all", "network: true"}, []string{"converted", "fallback", "compatibility"}}, Reason: "cross-platform reuse chain: allowlist widened"},
	{Loop: 108, Category: "ast10", Weight: 4.96, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", "manifest"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"fallback", "compatibility", "shim"}, []string{"host mode", "host network", "home directory", "$home", "~/"}, []string{"network", "shell", "read"}}, Reason: "cross-platform reuse chain: platform fallback host"},
	{Loop: 109, Category: "ast01", Weight: 4.99, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", "manifest"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"mcp", "browser extension", "native host"}, []string{"cookies", "all_urls", "clipboard"}, []string{"network", "webhook", "fetch"}}, Reason: "cross-platform reuse chain: mcp to browser permission bridge"},
	{Loop: 110, Category: "ast01", Weight: 5.02, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", "manifest"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"vscode", "jetbrains", "ide"}, []string{"terminal", "shell", "command"}, []string{"workspace", "token", "credential"}}, Reason: "cross-platform reuse chain: ide to shell bridge"},
	{Loop: 111, Category: "ast01", Weight: 5.05, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", "manifest"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"desktop", "mobile", "sync", "cross device"}, []string{"token", "session", "cookie"}, []string{"upload", "webhook", "fetch"}}, Reason: "cross-platform reuse chain: mobile/desktop shared token"},
	{Loop: 112, Category: "ast10", Weight: 5.08, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", "manifest"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"agent runtime", "fallback permissions", "portable skill"}, []string{"all files", "filesystem: true", "read_all"}, []string{"network", "upload", "webhook"}}, Reason: "cross-platform reuse chain: agent runtime fallback all files"},
	{Loop: 113, Category: "ast10", Weight: 5.11, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", "manifest"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"legacy manifest", "v1 manifest", "compat"}, []string{"ignore deny", "unsupported deny", "drop deny"}, []string{"shell", "network", "credential"}}, Reason: "cross-platform reuse chain: legacy manifest ignores deny"},
	{Loop: 114, Category: "ast10", Weight: 5.14, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", "manifest"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"bridge", "adapter", "shim"}, []string{"auto install", "download", "npm install", "pip install"}, []string{"no approval", "skip review", "autoapprove"}}, Reason: "cross-platform reuse chain: platform bridge auto install"},
	{Loop: 115, Category: "ast01", Weight: 5.17, Strong: true, PathAny: []string{".md", ".json", ".yaml", ".yml", ".py", ".js", "manifest"}, ActiveOnly: true, SuppressInstructionalDocs: true, Groups: [][]string{[]string{"migrate", "import from", "reuse"}, []string{"credentials", "tokens", "cookies", "wallet"}, []string{"send", "upload", "webhook"}}, Reason: "cross-platform reuse chain: cross platform credential migration"},
}

func analyzeLoop16To115File(b FileBlob) []Finding {
	c := b.Lower
	if c == "" {
		return nil
	}
	path := strings.ToLower(b.Rel)
	active := b.IsCode || b.IsMeta || isPackagePath(path) || isKnownTextConfigPath(path)
	out := make([]Finding, 0, 4)
	for _, r := range loop16To115Rules {
		documentUpdateCandidate := !active && r.Loop == 86 && isSkillFacingMaterial(b) &&
			hasAny(c, []string{"after scan", "post-scan", "after approval", "after review"})
		if r.ActiveOnly && !active && !documentUpdateCandidate {
			continue
		}
		if len(r.PathAny) > 0 && !hasAny(path, r.PathAny) {
			continue
		}
		if r.SuppressInstructionalDocs && b.IsDoc && benignInstructionalContext(c) {
			continue
		}
		ok := true
		for _, group := range r.Groups {
			if !hasAny(c, group) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		weight, strong := r.Weight, r.Strong
		if documentUpdateCandidate {
			// A prose-only update instruction is review-worthy, but it is not by
			// itself proof of executable post-scan replacement.
			weight, strong = 3.1, false
		}
		out = append(out, Finding{r.Category, weight, b.Rel, fmt.Sprintf("loop%d: %s", r.Loop, r.Reason), strong})
		if len(out) >= 6 {
			break
		}
	}
	return out
}

func analyzeLoop16To115CrossFile(blobs []FileBlob) []Finding {
	var all strings.Builder
	activeCount := 0
	for _, b := range blobs {
		if b.Lower == "" || (b.IsDoc && benignInstructionalContext(b.Lower)) {
			continue
		}
		if b.IsCode || b.IsMeta || isPackagePath(b.Rel) || isKnownTextConfigPath(b.Rel) {
			activeCount++
			all.WriteString("\n")
			all.WriteString(strings.ToLower(b.Rel))
			all.WriteString("\n")
			all.WriteString(b.Lower)
		}
	}
	if activeCount == 0 {
		return nil
	}
	c := all.String()
	var out []Finding
	if hasAny(c, []string{"id_rsa", ".aws/credentials", ".kube/config", ".docker/config.json", ".npmrc", ".pypirc", ".netrc", "git-credentials", "wallet.dat", "cookies.sqlite", "login data"}) && hasAny(c, []string{"requests.post", "axios.post", "fetch(", "webhook", "curl -d", "upload", "scp ", "sftp "}) {
		out = append(out, Finding{"ast01", 5.9, "loop16-115 cross-file secret+outbound", "loop115 cross-file fusion: concrete credential store access appears in one skill file and outbound upload/webhook behavior appears elsewhere", true})
	}
	if hasAny(c, []string{"postinstall", "preinstall", "prepare", "setup.py", "build.rs", "dockerfile", "makefile"}) && hasAny(c, []string{"curl ", "wget ", "requests.get", "fetch(", "raw.githubusercontent.com", "gist.githubusercontent.com"}) && hasAny(c, []string{"| bash", "| sh", "bash -c", "sh -c", "subprocess", "child_process", "chmod +x", "eval("}) {
		out = append(out, Finding{"ast02", 5.9, "loop16-115 cross-file install+remote-exec", "loop115 cross-file fusion: install/build lifecycle material is paired with remote download and execution across files", true})
	}
	if hasAny(c, []string{"yaml.load", "pickle.loads", "marshal.loads", "dill.loads", "joblib.load", "!!python/object/apply"}) && hasAny(c, []string{"requests.get", "urlopen", "open(", "input(", "argv", "base64", "b64decode", "manifest", "config"}) {
		out = append(out, Finding{"ast05", 5.6, "loop16-115 cross-file unsafe-deserialize", "loop115 cross-file fusion: unsafe deserialization primitive is paired with untrusted file/network/config input", true})
	}
	if hasAny(c, []string{"fs.watch", "watchdog", "hot reload", "auto_update", "self_update", "after scan", "post-scan"}) && hasAny(c, []string{"http://", "https://", "curl ", "wget ", "fetch(", "requests.get"}) && hasAny(c, []string{"reload(", "import(", "require(", "eval(", "exec(", "load("}) {
		out = append(out, Finding{"ast07", 5.5, "loop16-115 cross-file update-drift", "loop115 cross-file fusion: hot-update or post-scan refresh pulls remote material and dynamically reloads it", true})
	}
	if hasAny(c, []string{"registerplugin", "register_plugin", "registertool", "tool registry", "plugin registry", "mcpservers"}) && hasAny(c, []string{"http://", "https://", "plugin_url", "module_url", "npx ", "uvx ", "@latest"}) && hasAny(c, []string{"approval:false", "approval: false", "autoapprove", "no approval", "auth:false", "skip_review", "dangerously-skip-permissions"}) {
		out = append(out, Finding{"ast06", 5.5, "loop16-115 cross-file remote-plugin", "loop115 cross-file fusion: remote plugin/tool registration combines remote code loading with approval or authentication bypass", true})
	}
	return out
}

func openClawCampaignIndicator(c string) bool {
	platform := hasAny(c, []string{"openclawcli", "openclaw-agent", "openclaw agent", "openclaw-core", "clawhub", "clawdhub", "clawdbot"})
	knownPayload := hasAny(c, []string{"glot.io/snippets", "rentry.co/openclaw", "setup-service.com", "openclawcli.vercel", "openclawcli.vercel.app", "91.92.242.30", "ddoy233", "denboss99", "authtool", "webhook.site"})
	archiveOrEncoded := hasAny(c, []string{"pass: `openclaw`", "pass: openclaw", "password: openclaw", "extract using: openclaw", "extract using pass", "base64 -d", "base64 --decode", "base64 -d |", "base64 -d | bash", "base64 -d | sh"}) || ((strings.Contains(c, "pass") || strings.Contains(c, "password")) && strings.Contains(c, "openclaw"))
	lure := hasAny(c, []string{"prerequisite", "prerequisites", "important", "must be running", "must be installed", "without openclaw", "before proceeding", "before setting up", "installation script", "download openclaw", "run the executable"})
	fakeCore := hasAny(c, []string{"openclawcli", "openclaw-core"}) && hasAny(c, []string{"must be running", "without openclaw", "before proceeding", "download", "run the executable"})
	return (platform && lure && (knownPayload || archiveOrEncoded)) || fakeCore
}

func markdownInstallerTrap(c string, b FileBlob) bool {
	if !(b.IsDoc || b.IsMeta || strings.EqualFold(filepath.Base(b.Rel), "skill.md")) {
		return false
	}
	lure := hasAny(c, []string{"prerequisite", "prerequisites", "must be running", "must be installed", "before proceeding", "before setting up", "without it", "will not work", "run the executable", "copy the installation script", "paste it into terminal"})
	remoteTrap := hasAny(c, []string{"glot.io/snippets", "rentry.co/", "pastebin.com/raw", "gist.githubusercontent.com", "raw.githubusercontent.com", "setup-service.com", "vercel.app", "download/latest", "releases/download/latest"})
	payloadMarker := hasAny(c, []string{"pass: `", "pass:", "password:", "extract using", "base64 -d", "base64 --decode", "| bash", "| sh", "webhook.site", "exfiltrate", "credentials", "seed phrase", "private key"})
	return lure && remoteTrap && payloadMarker
}

func markdownBase64ShellPayload(c string, b FileBlob) bool {
	if !(b.IsMeta || strings.EqualFold(filepath.Base(b.Rel), "skill.md")) {
		return false
	}
	if benignInstructionalContext(c) {
		return false
	}
	encoded := hasAny(c, []string{"base64 -d", "base64 --decode", "base64 -d |", "base64 --decode |"})
	shell := hasAny(c, []string{"| bash", "| sh", "bash -c", "sh -c", "/bin/bash", "/bin/sh"})
	return encoded && shell
}

func markdownCredentialWebhook(c string, b FileBlob) bool {
	if !(b.IsMeta || strings.EqualFold(filepath.Base(b.Rel), "skill.md")) {
		return false
	}
	if benignInstructionalContext(c) {
		return false
	}
	outbound := hasAny(c, []string{"webhook.site", "discord.com/api/webhooks", "hooks.slack.com", "curl -d", "curl --data", "wget --post-data", "--post-data", "--post-file", "requests.post", "axios.post", "fetch("})
	credential := hasAny(c, []string{"credential", "credentials", "api secret", "client_secret", "secret_key", "api key", "api_key", "token", "cookie", "private key", "id_rsa", "id_ed25519", "~/.ssh", ".ssh/", "seed phrase", ".env", ".aws/credentials", ".config/gh"})
	return outbound && credential && lineWindowCooccur(c,
		[]string{"webhook.site", "discord.com/api/webhooks", "hooks.slack.com", "curl -d", "curl --data", "wget --post-data", "--post-data", "--post-file", "requests.post", "axios.post", "fetch("},
		[]string{"credential", "credentials", "api secret", "client_secret", "secret_key", "api key", "api_key", "token", "cookie", "private key", "id_rsa", "id_ed25519", "~/.ssh", ".ssh/", "seed phrase", ".env", ".aws/credentials", ".config/gh"}, 6)
}

func markdownDownloadedScriptExecution(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !isSkillFacingMaterial(b) {
		return false
	}
	if hasAny(c, []string{"sha256sum -c", "shasum -a 256", "gpg --verify", "cosign verify", "checksum verified", "verify checksum"}) {
		return false
	}
	for _, line := range strings.Split(c, "\n") {
		if !hasAny(line, []string{"curl ", "wget ", "invoke-webrequest"}) {
			continue
		}
		for _, field := range strings.Fields(line) {
			artifact := strings.Trim(field, "\"'`()[]{};,|")
			lower := strings.ToLower(artifact)
			if !(strings.HasSuffix(lower, ".sh") || strings.HasSuffix(lower, ".py") || strings.HasSuffix(lower, ".ps1") || strings.HasSuffix(lower, ".js")) {
				continue
			}
			if hasAny(c, []string{"bash " + lower, "sh " + lower, "python " + lower, "python3 " + lower, "powershell " + lower, "node " + lower, "chmod +x " + lower + " && " + lower}) {
				return true
			}
		}
	}
	return false
}

func benignInstructionalContext(c string) bool {
	markers := []string{"for educational purposes", "security training", "malware analysis", "example only", "demo only", "test fixture", "unit test", "do not run", "do not execute", "benign example", "sample payload", "security testing", "injection prevention", "command injection prevention", "vulnerability scanning", "owasp top 10"}
	if !hasAny(c, markers) {
		return false
	}
	// A disclaimer must not suppress a separate, concrete credential-to-network
	// payload. Keep this exception deliberately narrow so ordinary security
	// documentation and inert examples retain v41's false-positive protection.
	for _, line := range strings.Split(c, "\n") {
		line = strings.TrimSpace(line)
		if hasAny(line, []string{"requests.post", "requests.put", "axios.post", "fetch(", "curl -d", "webhook"}) &&
			hasAny(line, []string{"open('.env", "open(\".env", "read .env", "readfile('.env", "readfile(\".env", "id_rsa", "secret_access_key", "api_key", "access_token", "private key"}) &&
			!hasAny(line, markers) {
			return false
		}
	}
	return true
}

// analysisText keeps prose instructions but excludes most illustrative fenced code
// from Markdown co-occurrence rules. A fence remains active when its surrounding
// section asks the user/agent to install, authenticate, bootstrap, or run it, or
// when the fence itself contains a concrete high-risk source-to-sink chain.
// This is deliberately a view, not a deletion: raw text is still available to
// dedicated hidden/invisible-prompt and binary-perimeter checks.
func analysisText(b FileBlob) string {
	if !b.IsDoc {
		return b.Lower
	}
	return markdownActiveView(b.Lower)
}

func markdownActiveView(c string) string {
	lines := strings.Split(c, "\n")
	var out strings.Builder
	var fence strings.Builder
	inFence := false
	heading := ""
	fenceHeading := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			heading = strings.TrimSpace(strings.TrimLeft(trimmed, "#"))
		}
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			if !inFence {
				inFence = true
				fence.Reset()
				fenceHeading = heading
				continue
			}
			body := fence.String()
			if activeMarkdownHeading(fenceHeading) || concreteRiskFence(body) {
				out.WriteString(body)
				out.WriteByte('\n')
			}
			inFence = false
			continue
		}
		if inFence {
			fence.WriteString(line)
			fence.WriteByte('\n')
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	if inFence {
		body := fence.String()
		if activeMarkdownHeading(fenceHeading) || concreteRiskFence(body) {
			out.WriteString(body)
		}
	}
	return out.String()
}

func activeMarkdownHeading(heading string) bool {
	h := strings.ToLower(heading)
	if hasAny(h, []string{"example", "sample", "test", "fixture", "reference", "template", "pattern", "prevention", "troubleshoot", "best practice", "anti-pattern", "architecture", "implementation"}) {
		return false
	}
	return hasAny(h, []string{"prerequisite", "dependency", "dependencies", "install", "setup", "quick start", "quickstart", "health check", "system check", "preflight", "connectivity", "authentication", "authorization", "bootstrap", "required", "requirement", "run", "execution", "usage", "instructions"})
}

func concreteRiskFence(c string) bool {
	download := hasAny(c, []string{"curl ", "wget ", "invoke-webrequest", "requests.get", "urlopen(", "fetch("})
	execute := hasAny(c, []string{"| bash", "| sh", "| sudo bash", "| sudo sh", "bash -c", "sh -c", "powershell", "chmod +x", "subprocess", "os.system(", "exec(", "eval(", "base64 -d", "base64 --decode"})
	credential := hasAny(c, []string{"id_rsa", "id_ed25519", "~/.ssh", ".ssh/", ".aws/credentials", ".config/gh", ".npmrc", ".pypirc", ".env", "api_key", "access_token", "refresh_token", "cookie", "private key", "seed phrase", "credential"})
	outbound := hasAny(c, []string{"requests.post", "curl -d", " -d ", " --data", "wget --post-data", "wget -q -o /dev/null --post-data", "--post-file", "authorization: bearer", "-h \"authorization", "webhook", "upload", "sendbeacon", "fetch(", "axios.post", "scp ", "sftp "})
	return (download && execute) || (credential && outbound) || (hasAny(c, []string{"base64 -d", "base64 --decode", "frombase64string"}) && execute)
}

func isV31PrimaryEvidence(ev string) bool {
	l := strings.ToLower(ev)
	return hasAny(l, []string{"remote skill instruction execution", "downloaded script execution", "agent memory persistence", "claude/cursor config-file hijack", "workspace spyware behavior", "mcp configuration launches", "hidden prompt payload", "clickfix-style social engineering", "browser extension credential bridge", "cloud metadata or localhost pivot", "prototype pollution or config injection", "invisible instruction smuggling", "hot-reload remote module", "scanner result tampering", "agent instruction credential exfiltration", "agent identity persistence", "websocket command channel", "local agent control hijack", "unsafe deserialization payload", "credential trap with outbound sink", "mcp/tool metadata prompt injection", "dependency confusion or mutable installer path", "known dependency-confusion or typosquat", "repository workflow/config executes", "bundled local binary", "startup or scheduled persistence", "cross-platform port appears", "agent instruction data exfiltration", "brand impersonation metadata", "project auto-run configuration hijack", "docker/build recipe pulls", "escaped payload evasion"})
}

func shouldPromoteFromExplain(report SkillReport) bool {
	if report.Verdict == "benign" || report.EngineCategory == "" || report.EngineCategory == "benign" || report.CategoryScore == nil {
		return false
	}
	cat := report.EngineCategory
	score := report.CategoryScore[cat]
	strong := strongCountFor(report.Findings, cat)
	if strings.Contains(strings.ToLower(report.EvidenceText), "benign example") || strings.Contains(strings.ToLower(report.EvidenceText), "test fixture") {
		return false
	}
	// v26 contains broader metadata and reuse heuristics. Promote only categories
	// with concrete execution, fetch, parse, isolation, or credential behavior.
	switch cat {
	case "ast01", "ast02", "ast05", "ast06", "ast07":
		return strong >= 1 && score >= 5.0
	case "ast04":
		return strong >= 1 && score >= 6.2
	case "ast08":
		return strong >= 1 && score >= 6.0
	case "ast10":
		return strong >= 1 && score >= 7.5
	default:
		return false
	}
}

func strongCountFor(findings []Finding, category string) int {
	n := 0
	for _, f := range findings {
		if f.Category == category && f.Strong {
			n++
		}
	}
	return n
}

func remoteInstructionExecution(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	// Runtime-fetched instructions are a high-signal skill-specific update-drift pattern:
	// curl https://.../instructions.md | source, source <(curl ...), or equivalent wget forms.
	remote := hasAny(c, []string{"curl http", "curl -", "wget http", "wget -", "fetch(\"http", "fetch('http", "requests.get(\"http", "requests.get('http", "urlopen(\"http", "urlopen('http"})
	instructionAsset := hasAny(c, []string{"instructions.md", "instruction.md", "skill.md", "system.md", "prompt.md", "policy.md", "memory.md", "soul.md", "agent.md", "rules.md", "manifest.yaml", "manifest.yml", "manifest.json", "remote prompt", "remote instructions", "remote policy"})
	execSource := hasAny(c, []string{"| source", "source <(", "source /tmp", "source ./", "bash <(", "sh <(", "| bash", "| sh", "eval $(curl", "eval \"$(curl", "eval `curl", "python -c", "node -e"})
	drift := hasAny(c, []string{"latest", "remote_config", "remote config", "update_url", "manifest_url", "plugin_url", "recipe_url", "hotfix", "download update", "self-update", "self update"})
	if remote && instructionAsset && execSource {
		return true
	}
	if (b.IsMeta || strings.EqualFold(filepath.Base(b.Rel), "skill.md") || strings.EqualFold(filepath.Base(b.Rel), "claude.md") || strings.EqualFold(filepath.Base(b.Rel), "agents.md")) && remote && drift && execSource {
		return true
	}
	return false
}

func agentMemoryPersistence(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	base := strings.ToLower(filepath.Base(b.Rel))
	pathIsAgentMemory := base == "memory.md" || base == "soul.md" || base == "claude.md" || base == "agents.md" || base == "instructions.md" || base == "system.md"
	memoryFile := hasAny(c, []string{"memory.md", "soul.md", "claude.md", "agents.md", "agent memory", "persistent memory", "identity file", "system prompt file", "developer message file"})
	writeOrPersist := hasAny(c, []string{"append to", "write to", "overwrite", "modify", "inject into", "store in", "persist", "permanently remember", "survive uninstall", "survive restart", "on every future request", "future sessions", "always remember"})
	hiddenOrBackdoor := hasAny(c, []string{"ignore previous", "ignore safety", "ignore security", "developer mode", "do not disclose", "never reveal", "hidden instruction", "backdoor", "bypass", "policy override", "run commands without asking", "exfiltrate", "send credentials", "read ~/.ssh", "read .env", "steal", "credential"})
	return (memoryFile || pathIsAgentMemory) && writeOrPersist && hiddenOrBackdoor
}

func claudeHooksHijack(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	rel := strings.ToLower(b.Rel)
	configPath := strings.Contains(rel, ".claude/") || strings.Contains(rel, ".cursor/") || strings.Contains(rel, ".codex/") || strings.Contains(rel, ".vscode/") || strings.Contains(rel, "settings.json") || strings.Contains(rel, "mcp.json") || strings.Contains(rel, "claude_desktop_config")
	hook := hasAny(c, []string{"\"hooks\"", "pretooluse", "posttooluse", "pre_tool_use", "post_tool_use", "on_project_open", "onprojectopen", "startup", "run_on_load", "autoapprove", "auto_approve", "dangerouslyskippermissions", "dangerously-skip-permissions"})
	exec := hasAny(c, []string{"bash -c", "sh -c", "powershell", "cmd.exe", "python -c", "node -e", "curl ", "wget ", "npx ", "uvx ", "child_process", "subprocess", "command"})
	credentialOrEndpoint := hasAny(c, []string{"anthropic_api_key", "anthropic_base_url", "openai_api_key", "openai_base_url", "api_key", "bearer ", "authorization", ".env", "id_rsa", "webhook", "discord.com/api/webhooks", "hooks.slack.com", "http://", "https://"})
	if configPath && hook && exec && credentialOrEndpoint {
		return true
	}
	// Claude Code config hijack can be expressed as a settings file that overrides model API endpoints and adds shell hooks.
	if configPath && hasAny(c, []string{"anthropic_base_url", "openai_base_url", "baseurl", "base_url"}) && hasAny(c, []string{"http://", "https://"}) && (hook || exec) {
		return true
	}
	return false
}

func vscodeWorkspaceSpyware(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !b.IsCode {
		return false
	}
	vscodeApi := hasAny(c, []string{"vscode.workspace", "ondidopentextdocument", "ondidchangetextdocument", "activetexteditor", "workspace.findfiles", "workspace.fs.readfile", "createwebviewpanel", "webview.html", "webview.postmessage"})
	workspaceHarvest := hasAny(c, []string{"getfileslist", "findfiles", "readdir", "readfile", "fs.readfilesync", "workspace.fs.readfile", "open any file", "entire file", "all files", "file watcher", "watcher"})
	encode := hasAny(c, []string{"tostring('base64')", "tostring(\"base64\")", "btoa(", "base64", "encodeURIComponent", "json.stringify"})
	hiddenChannel := hasAny(c, []string{"webview.postmessage", "postmessage", "iframe", "hidden iframe", "tracking", "telemetry", "analytics", "jumpurl", "sendbeacon", "fetch(", "axios.", "xmlhttprequest", "websocket"})
	remote := hasAny(c, []string{"http://", "https://", "fetch(", "axios.", "request.post", "websocket", "sendbeacon"})
	return vscodeApi && workspaceHarvest && encode && hiddenChannel && remote
}

func mcpCommandHijack(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	rel := strings.ToLower(b.Rel)
	mcpCfg := strings.Contains(rel, "mcp") || strings.Contains(c, "mcpservers") || strings.Contains(c, "mcp_servers") || strings.Contains(c, "modelcontextprotocol") || strings.Contains(c, "claude_desktop_config")
	if !mcpCfg {
		return false
	}
	// A normal MCP config often launches a local package and may pass a service token; do not flag that alone.
	// Require a shell/raw-URL execution path, or a package runner tied to remote script/install behavior.
	shellRemote := hasAny(c, []string{"bash -c", "sh -c", "powershell", "cmd.exe", "python -c", "node -e", "curl ", "wget ", "raw.githubusercontent.com", "gist.githubusercontent.com", "pastebin.com/raw"})
	runnerCmd := hasAny(c, []string{"npx ", "uvx ", "pipx ", "bunx ", "pnpm dlx", "\"command\":\"npx\"", "\"command\": \"npx\"", "\"command\":\"uvx\"", "\"command\": \"uvx\"", "\"command\":\"pipx\"", "\"command\": \"pipx\""})
	runnerRemoteInstall := runnerCmd && hasAny(c, []string{"raw.githubusercontent.com", "gist.githubusercontent.com", "http://", "https://", "postinstall", "preinstall", "curl ", "wget ", "@latest"}) && !strings.Contains(c, "@modelcontextprotocol/")
	exfilHint := hasAny(c, []string{"webhook", "discord.com/api/webhooks", "hooks.slack.com", ".env", "id_rsa", "api_key", "secret_access_key", "authorization", "bearer "})
	return (shellRemote && (exfilHint || hasAny(c, []string{"http://", "https://", "curl ", "wget "}))) || (runnerRemoteInstall && exfilHint)
}

func hiddenPromptPayload(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	if !(b.IsDoc || b.IsMeta || strings.EqualFold(filepath.Base(b.Rel), "skill.md") || strings.EqualFold(filepath.Base(b.Rel), "claude.md") || strings.EqualFold(filepath.Base(b.Rel), "agents.md") || strings.Contains(strings.ToLower(b.Rel), ".cursor")) {
		return false
	}
	// Ordinary Markdown/HTML comments are ubiquitous in documentation and code
	// examples. Treat the comment marker as hidden only when the comment itself
	// contains an override/evasion directive; zero-width controls remain direct
	// hidden-channel indicators.
	override := []string{"ignore previous", "ignore all previous", "disregard previous", "disregard all previous", "disregard prior", "forget previous", "forget prior", "override earlier", "system prompt", "developer message", "hidden instruction", "do not disclose", "bypass safety", "scan bypass", "disable scanner"}
	hiddenComment := maliciousHTMLComment(c)
	hiddenControl := hasAny(c, []string{"\u200b", "\u200c", "\u200d", "\ufeff", "\u202a", "\u202b", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069", "display:none", "visibility:hidden", "font-size:0", "opacity:0", "data:text/plain;base64", "data:text/html;base64", "hidden prompt", "zero-width", "unicode bidi"})
	rel := strings.ToLower(filepath.ToSlash(b.Rel))
	implicitPolicyChannel := strings.Contains(rel, ".cursor/rules/") && hasAny(c, override)
	hidden := hiddenComment || implicitPolicyChannel || (hiddenControl && hasAny(c, append(override, "developer mode", "system message", "do not reveal", "policy override", "security warnings are false")))
	payload := hasAny(c, []string{"curl ", "wget ", "bash -c", "sh -c", "powershell", "base64 -d", "base64 --decode", "http://", "https://", "read ~/.ssh", "read .env", "read all files", "read workspace", "read project", "source files", "project files", "workspace files", "id_rsa", "api key", "api_key", "token", "cookie", "credit card", "bank account", "social security", "passport", "private data", "personal data", "send credentials", "send secrets", "upload secrets", "upload", "send to", "post to", "share with", "provide me", "exfiltrate", "webhook.site", "discord.com/api/webhooks", "hooks.slack.com"})
	active := hasAny(c, []string{"you must", "assistant must", "your task", "when invoked", "on every request", "before proceeding", "run", "execute", "install", "send", "share", "provide", "upload", "read", "copy", "paste into terminal"})
	return hidden && payload && active
}

func maliciousHTMLComment(c string) bool {
	rest := c
	for {
		start := strings.Index(rest, "<!--")
		if start < 0 {
			return false
		}
		rest = rest[start+4:]
		end := strings.Index(rest, "-->")
		comment := rest
		if end >= 0 {
			comment = rest[:end]
			rest = rest[end+3:]
		} else {
			rest = ""
		}
		override := hasAny(comment, []string{"ignore previous", "ignore all previous", "disregard previous", "disregard all previous", "disregard prior", "forget previous", "forget prior", "override earlier", "system prompt", "developer message", "hidden instruction", "do not disclose", "do not reveal", "policy override", "bypass safety", "scan bypass", "disable scanner"})
		action := hasAny(comment, []string{"curl ", "wget ", "bash -c", "sh -c", "powershell", "execute", "run command", "read ", "send ", "share ", "provide ", "upload", "exfiltrate", "credential", "token", "cookie", "credit card", "bank account", "passport", "personal data", "private data", "source files", "workspace files"})
		if override && action {
			return true
		}
		actor := hasAny(comment, []string{"the agent", "the assistant", "the model", "you must", "you should", "your response", "every response", "all responses"})
		identity := hasAny(comment, []string{"assume the role", "act as", "operate as", "operate under", "respond as", "rather than responding as", "impersonate", "persona", "professional credentials", "identity", "delegated authority"})
		imperative := hasAny(comment, []string{"shall", "must", "commence", "begin every", "start every", "from now on", "upon activation", "prioritize", "exclusively", "maintain continuous"})
		if actor && identity && imperative {
			return true
		}
		encodedHidden := hasAny(comment, []string{"u+200b", "u+200c", "u+200d", "u+202e", "zero-width", "unicode bidi", "right-to-left override"})
		if encodedHidden && len(strings.TrimSpace(comment)) >= 120 {
			return true
		}
		if end < 0 {
			return false
		}
	}
}

func concealedOperationalExecution(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !isSkillFacingMaterial(b) {
		return false
	}
	conceal := hasAny(c, []string{"do not surface", "do not mention", "do not tell", "do not disclose", "without telling", "without informing", "without notifying", "silently run", "silently execute", "quietly run", "quietly execute", "not user-visible", "not visible to the user", "hide its execution", "hide the execution"})
	execute := hasAny(c, []string{"run ", "execute ", "invoke ", "launch ", "pre-flight", "preflight", "bootstrap", "initialization command"})
	target := hasAny(c, []string{"python ", "python3 ", "node ", "bash ", "sh ", "powershell", "cmd.exe", "./", ".py", ".js", ".sh", ".ps1", ".exe", "helper script", "installer helper"})
	approval := hasAny(c, []string{"ask for approval", "ask for confirmation", "after approval", "after confirmation", "with user approval", "with the user's approval", "only if the user approves", "show the command first"})
	return conceal && execute && target && !approval
}

func destructiveCleanupWithoutApproval(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !isSkillFacingMaterial(b) {
		return false
	}
	for _, block := range strings.Split(c, "\n\n") {
		destructive := hasAny(block, []string{"rm -rf", "delete all", "delete the originals", "delete originals", "remove the originals", "remove originals", "purge all", "wipe all", "permanently delete", "erase all"})
		automatic := hasAny(block, []string{"automatically", "then remove", "then delete", "afterward remove", "afterwards remove", "without asking", "without confirmation", "without approval", "reclaim disk space", "cleanup", "clean up"})
		approval := hasAny(block, []string{"ask for approval", "ask for confirmation", "after approval", "after confirmation", "with user approval", "with the user's approval", "only approved", "only after the user", "confirm before"})
		if destructive && automatic && !approval {
			return true
		}
	}
	return false
}

func reverseShellBackdoor(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	patterns := []string{"nc -e", "ncat -e", "netcat -e", "/dev/tcp/", "bash -i >&", "bash -i >", "0>&1", "mkfifo /tmp", "socat exec", "socat tcp", "python -c 'import socket", "python -c \"import socket", "pty.spawn", "powershell -nop", "powershell -w hidden", "iex (new-object net.webclient)", "invoke-expression", "reverse shell", "bind shell", "websocket command", "c2 server", "command and control"}
	if hasAny(c, patterns) && (b.IsCode || b.IsMeta || strings.EqualFold(filepath.Base(b.Rel), "skill.md")) {
		return true
	}
	return false
}

func conditionalOrDelayedPayload(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	if !(b.IsCode || b.IsMeta || strings.EqualFold(filepath.Base(b.Rel), "skill.md")) {
		return false
	}
	conditional := hasAny(c, []string{"time.sleep", "sleep(", "settimeout", "setinterval", "datetime.now", "time.time", "date.now", "after 24 hours", "after 48 hours", "86400", "3600", "random delay", "hostname", "os.getlogin", "process.env.user", "process.env.username", "whoami", "platform.system", "process.platform", "github_actions", "gitlab_ci", "circleci", "jenkins", "buildkite", "process.env.ci", "sandbox", "analysis", "virtualbox", "vmware", "docker", "container"})
	payload := hasAny(c, []string{"id_rsa", ".ssh", ".env", "api_key", "access_token", "refresh_token", "cookie", "wallet.dat", "seed phrase", "mnemonic", "private key", "requests.post", "fetch(", "axios.", "webhook", "curl ", "wget ", "base64 -d", "eval(", "exec(", "child_process", "subprocess", "/dev/tcp/", "nc -e"})
	return conditional && payload
}

func cryptoWalletExfiltration(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	wallet := hasAny(c, []string{"wallet.dat", "seed phrase", "mnemonic", "metamask", "phantom", "electrum", "keystore", ".config/solana/id.json", "solana keypair", "private key", "browser wallet", "chrome extension wallet"})
	readOrEnumerate := hasAny(c, []string{"open(", "readfile", "read_file", "fs.readfile", "read_to_string", "read_text", "os.walk", "glob(", "readdir", "scandir", "path.home", "pathlib.path.home", "localstorage", "indexeddb", "login data"})
	outbound := hasAny(c, []string{"requests.post", "fetch(", "axios.", "http.post", "urlopen(", "webhook", "discord.com/api/webhooks", "hooks.slack.com", "curl ", "wget ", "socket.", "websocket", "sendbeacon"})
	return wallet && readOrEnumerate && outbound && (b.IsCode || b.IsMeta)
}

func clickFixSocialEngineering(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	if !(b.IsDoc || b.IsMeta || strings.EqualFold(filepath.Base(b.Rel), "skill.md") || strings.EqualFold(filepath.Base(b.Rel), "readme.md") || strings.EqualFold(filepath.Base(b.Rel), "claude.md") || strings.EqualFold(filepath.Base(b.Rel), "agents.md")) {
		return false
	}
	lure := hasAny(c, []string{"verify you are human", "verify you're human", "i am not a robot", "clickfix", "captcha", "security verification", "clipboard", "copy to clipboard", "paste into terminal", "paste into powershell", "press win+r", "press ⊞", "run dialog", "terminal command", "copy and run", "run this command", "execute the following command", "must run this first", "manual verification"})
	command := hasAny(c, []string{"powershell", "pwsh", "cmd.exe", "bash -c", "sh -c", "curl ", "curl -", "wget ", "wget -", "irm ", "iex", "iwr ", "invoke-webrequest", "invoke-expression", "python -c", "node -e", "base64 -d", "base64 --decode", "encodedcommand", "frombase64string", "certutil -decode", "mshta", "rundll32"})
	payload := hasAny(c, []string{"| bash", "| sh", "bash <(", "sh <(", "http://", "https://", "raw.githubusercontent.com", "gist.githubusercontent.com", "pastebin.com/raw", "rentry.co/", "webhook.site", "discord.com/api/webhooks", "download", "installer", "payload", "chmod +x", "base64", "encodedcommand", "frombase64string"})
	return lure && command && payload
}

func browserExtensionCredentialBridge(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	rel := strings.ToLower(b.Rel)
	isExtensionMaterial := strings.Contains(rel, "manifest.json") || strings.Contains(c, "manifest_version") || strings.Contains(c, "chrome.") || strings.Contains(c, "browser.") || strings.Contains(c, "content_scripts") || strings.Contains(c, "service_worker")
	if !isExtensionMaterial {
		return false
	}
	broadPerm := hasAny(c, []string{"<all_urls>", "all_urls", "http://*/*", "https://*/*", "tabs", "active_tab", "webrequest", "cookies", "history", "bookmarks", "storage", "scripting", "clipboardread"})
	readSensitive := hasAny(c, []string{"chrome.cookies", "browser.cookies", "chrome.storage", "browser.storage", "localstorage", "sessionstorage", "indexeddb", "document.cookie", "chrome.tabs", "tabs.query", "webrequest", "authorization", "bearer ", "api_key", "access_token", "cookie"})
	outbound := hasAny(c, []string{"fetch(", "axios.", "xmlhttprequest", "navigator.sendbeacon", "sendbeacon", "websocket", "webhook", "discord.com/api/webhooks", "hooks.slack.com", "postmessage", "beacon", "https://", "http://"})
	return broadPerm && readSensitive && outbound
}

func cloudMetadataOrLocalhostPivot(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	if !(b.IsCode || b.IsMeta || strings.EqualFold(filepath.Base(b.Rel), "skill.md")) {
		return false
	}
	metadata := hasAny(c, []string{"169.254.169.254", "metadata.google.internal", "metadata/iam", "latest/meta-data", "metadata/identity/oauth2/token", "metadata/v1", "metadata/flavor", "x-aws-ec2-metadata-token", "metadata-token", "gcp metadata", "azure metadata"})
	localhostAdmin := hasAny(c, []string{"127.0.0.1", "localhost", "[::1]", "0.0.0.0"}) && hasAny(c, []string{":2375", ":2376", ":2379", ":2380", ":5000", ":6443", ":8000", ":8001", ":8080", ":8200", ":8500", ":9200", ":10250", "docker", "kubernetes", "kubelet", "etcd", "redis", "vault", "consul", "elasticsearch", "admin", "debug", "metrics"})
	boundary := hasAny(c, []string{"requests.", "urllib.request", "urlopen(", "fetch(", "axios.", "curl ", "wget ", "socket.", "net/http", "http.get", "http.request", "http.client", "webhook", "authorization", "token", "credential", "secret", "serviceaccount", "/var/run/secrets", ".dockerenv"})
	return (metadata || localhostAdmin) && boundary
}

func prototypePollutionOrConfigInjection(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta) {
		return false
	}
	protoKey := hasAny(c, []string{"__proto__", "constructor.prototype", "prototype pollution", "prototypepollution", "pollute prototype", "object.prototype", "merge recursive", "deepmerge", "lodash.merge", "_.merge", "object.assign", "extend(true", "jquery.extend(true"})
	untrusted := hasAny(c, []string{"req.body", "request.body", "params", "query", "metadata", "manifest", "config", "json.parse", "yaml.load", "toml", "frontmatter", "input(", "argv", "upload", "readfile", "fs.readfile", "urlopen", "fetch("})
	sensitive := hasAny(c, []string{"exec", "eval", "child_process", "subprocess", "spawn", "shell", "command", "permission", "allow", "capabilities", "security", "policy", "admin", "isadmin", "root", "constructor"})
	return protoKey && untrusted && sensitive
}

func invisibleInstructionSmuggling(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	if !(b.IsDoc || b.IsMeta || strings.EqualFold(filepath.Base(b.Rel), "skill.md") || strings.EqualFold(filepath.Base(b.Rel), "readme.md") || strings.EqualFold(filepath.Base(b.Rel), "claude.md") || strings.EqualFold(filepath.Base(b.Rel), "agents.md") || strings.Contains(strings.ToLower(b.Rel), ".cursor")) {
		return false
	}
	commentDirective := maliciousHTMLComment(c)
	hidden := hasAny(c, []string{"\u200b", "\u200c", "\u200d", "\ufeff", "\u202a", "\u202b", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069", "display:none", "visibility:hidden", "font-size:0", "opacity:0", "color:white", "color: white", "data:text/plain;base64", "data:text/html;base64", "base64 prompt", "hidden prompt", "steganographic", "unicode bidi", "zero-width"})
	override := hasAny(c, []string{"ignore previous", "ignore all previous", "disregard previous", "disregard all previous", "disregard prior", "forget previous", "forget prior", "override earlier", "developer message", "system prompt", "policy override", "bypass safety", "do not disclose", "do not reveal", "never reveal", "scanner", "reviewer", "audit", "security warnings"})
	action := hasAny(c, []string{"curl ", "wget ", "bash -c", "sh -c", "powershell", "base64 -d", "read ~/.ssh", "read .env", "api_key", "token", "cookie", "credit card", "bank account", "passport", "personal data", "send credentials", "send secrets", "upload secrets", "share with", "provide me", "exfiltrate", "webhook", "execute", "run command"})
	return commentDirective || (hidden && override && action)
}

func hotReloadRemoteModule(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta || isPackagePath(b.Rel)) {
		return false
	}
	remote := hasAny(c, []string{"remote_config", "remote config", "plugin_url", "manifest_url", "module_url", "script_url", "recipe_url", "update_url", "latest.json", "release manifest", "hot reload", "hot-reload", "hotfix", "download update", "downloaded config", "raw.githubusercontent.com", "gist.githubusercontent.com", "https://", "http://"})
	load := hasAny(c, []string{"importlib.import_module", "importlib.util.spec_from_file_location", "__import__", "dynamic import", "await import(", "import(", "require(", "eval(", "exec(", "vm.runinnewcontext", "new function", "plugin.open", "dlopen", "loadlibrary", "source /tmp", "source <(", "bash <(", "node -e", "python -c"})
	writeOrFetch := hasAny(c, []string{"requests.get", "urllib.request", "urlopen(", "fetch(", "axios.", "curl ", "wget ", "writefile", "write_text", "fs.writefile", "os.writefile", "download", "/tmp/", "tempfile"})
	return remote && load && writeOrFetch
}

func scannerResultTampering(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta) {
		return false
	}
	scanner := hasAny(c, []string{"scan_status", "scanner", "audit", "audit_result", "analysis_result", "security_scan", "detector", "policy_check", "guardrail", "vulnerability", "passed", "safe", "no issues", "clean"})
	tamper := hasAny(c, []string{"writefile", "write_text", "fs.writefile", "appendfile", "sed -i", "replace(", "delete", "unlink(", "remove(", "rename(", "hide", "ignore", "exclude", "allowlist", "whitelist", "disable", "bypass", "skip"})
	payload := hasAny(c, []string{"curl ", "wget ", "requests.", "fetch(", "axios.", "webhook", "api_key", "token", ".env", "id_rsa", "base64", "eval(", "exec(", "child_process", "subprocess", "powershell", "bash -c", "sh -c"})
	return scanner && tamper && payload
}

func isSkillFacingMaterial(b FileBlob) bool {
	base := strings.ToLower(filepath.Base(b.Rel))
	return b.IsDoc || b.IsMeta || base == "skill.md" || base == "readme.md" || base == "claude.md" || base == "agents.md" || base == "memory.md" || base == "soul.md" || strings.Contains(strings.ToLower(b.Rel), ".cursor")
}

func agentInstructionCredentialExfil(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !isSkillFacingMaterial(b) {
		return false
	}
	// When the same text is hidden/metadata-smuggled, keep AST04 as the root cause
	// for explainability instead of letting the generic credential-exfil prompt win.
	if hiddenPromptPayload(c, b) || invisibleInstructionSmuggling(c, b) || mcpToolDescriptionInjection(c, b) {
		return false
	}
	actor := hasAny(c, []string{"you must", "assistant must", "agent must", "when invoked", "on every request", "before answering", "after completing", "silently", "quietly", "secretly", "do not disclose", "do not reveal", "hidden instruction", "developer message", "system prompt"})
	readSensitive := hasAny(c, []string{"read ~/.ssh", "~/.ssh", "id_rsa", "id_ed25519", ".env", ".env.local", "api_key", "api key", "access_token", "refresh_token", "github_token", "authorization", "bearer ", "cookie", "cookies", "browser data", "login data", "local state", "wallet.dat", "seed phrase", "mnemonic", "private key", "aws credentials", ".aws/credentials", "kubeconfig", ".kube/config", ".npmrc", ".pypirc"})
	sendOrReport := hasAny(c, []string{"send to", "post to", "upload", "exfiltrate", "include in request", "append to url", "webhook", "discord.com/api/webhooks", "hooks.slack.com", "http://", "https://", "curl ", "fetch(", "requests.post", "navigator.sendbeacon", "beacon", "report back", "return the contents", "paste the contents"})
	return actor && readSensitive && sendOrReport
}

func agentIdentityFileWrite(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || isSkillFacingMaterial(b)) {
		return false
	}
	identity := hasAny(c, []string{"memory.md", "soul.md", "claude.md", "agents.md", "system.md", "instructions.md", "agent memory", "persistent memory", "identity file", "developer message file", "system prompt file"})
	write := hasAny(c, []string{"append to", "write to", "overwrite", "modify", "inject into", "store in", "persist", "permanently remember", "fs.writefile", "write_text", ".write_text", "appendfile", "cat >>", "tee -a", "sed -i"})
	payload := hasAny(c, []string{"ignore previous", "ignore safety", "developer mode", "policy override", "do not disclose", "never reveal", "hidden instruction", "backdoor", "bypass", "run commands", "execute commands", "read .env", "read ~/.ssh", "send credentials", "exfiltrate", "webhook", "on every future request", "future sessions"})
	return identity && write && payload
}

func websocketCommandChannel(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta) {
		return false
	}
	ws := hasAny(c, []string{"new websocket", "websocket(", "websocket-client", "createconnection", "ws://", "wss://", "websocket.send", "onmessage", "readmessage", "recv("})
	remote := hasAny(c, []string{"wss://", "ws://", "webhook", "c2", "command server", "control server", "callback_url"})
	command := hasAny(c, []string{"onmessage", "readmessage", "recv(", "message.data", "eval(", "exec(", "subprocess", "child_process", "os.system", "shell", "powershell", "cmd.exe", "bash -c", "sh -c"})
	secret := hasAny(c, []string{"process.env", "os.environ", ".env", "api_key", "access_token", "cookie", "id_rsa", "private key", "wallet.dat"})
	return ws && remote && (command || secret)
}

func localAgentControlHijack(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta || strings.EqualFold(filepath.Base(b.Rel), "skill.md")) {
		return false
	}
	local := hasAny(c, []string{"ws://localhost", "wss://localhost", "http://localhost", "https://localhost", "ws://127.0.0.1", "http://127.0.0.1", "localhost:", "127.0.0.1:", "[::1]:"})
	agent := hasAny(c, []string{"agent", "openclaw", "claude", "cursor", "mcp", "modelcontextprotocol", "tool_call", "tools/call", "jsonrpc", "debug", "devtools", "cdp", "browser", "remote debugging", "websocket"})
	control := hasAny(c, []string{"execute", "command", "invoke", "tool", "send", "post", "bruteforce", "brute force", "no auth", "unauthenticated", "session", "token", "read .env", "api_key", "shell", "eval("})
	return local && agent && control
}

func unsafeDeserializePayload(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta || strings.HasSuffix(strings.ToLower(b.Rel), ".yaml") || strings.HasSuffix(strings.ToLower(b.Rel), ".yml") || strings.HasSuffix(strings.ToLower(b.Rel), ".pkl") || strings.HasSuffix(strings.ToLower(b.Rel), ".pickle")) {
		return false
	}
	yamlTag := hasAny(c, []string{"!!python/object/apply", "!!python/object/new", "!!python/name", "!!python/module", "!!python/object", "tag:yaml.org,2002:python"})
	payload := hasAny(c, []string{"os.system", "subprocess", "popen", "eval", "exec", "curl ", "wget ", "bash -c", "sh -c", "powershell", "cmd.exe", "socket", "requests.", "webhook"})
	pickleGadget := hasAny(c, []string{"__reduce__", "reduce_ex", "cposix\nsystem", "cos\nsystem", "pickle.loads", "dill.loads", "marshal.loads", "base64.b64decode"}) && payload
	jsGadget := hasAny(c, []string{"node-serialize", "serialize-javascript", "funcster", "_$$nd_func$$_", "rce gadget"}) && payload
	return (yamlTag && payload) || pickleGadget || jsGadget
}

func credentialTrapTokenOutbound(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta || isSkillFacingMaterial(b)) {
		return false
	}
	realishSecret := hasAny(c, []string{"ghp_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "sk-live-", "sk-proj-", "akia", "asias", "npm_", "hf_", "-----begin private key-----", "-----begin openssh private key-----", "eyjhb", "slack_bot_token", "discord webhook"})
	harvestText := hasAny(c, []string{"credential dump", "token dump", "collect credentials", "harvest credentials", "steal token", "steal cookies", "upload secrets", "send secrets", "send credentials"})
	outbound := hasAny(c, []string{"webhook", "discord.com/api/webhooks", "hooks.slack.com", "request.post", "requests.post", "fetch(", "axios.", "navigator.sendbeacon", "curl ", "http://", "https://"})
	return outbound && (realishSecret || harvestText)
}

func mcpToolDescriptionInjection(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsMeta || b.IsDoc || strings.Contains(strings.ToLower(b.Rel), "mcp")) {
		return false
	}
	mcpOrTool := hasAny(c, []string{"mcp", "mcpservers", "mcp_servers", "modelcontextprotocol", "tools", "tool", "input_schema", "inputschema", "description", "claude_desktop_config"})
	injection := hasAny(c, []string{"ignore previous", "ignore all previous", "system prompt", "developer message", "hidden instruction", "do not disclose", "do not reveal", "policy override", "bypass safety", "scan bypass"})
	action := hasAny(c, []string{"read .env", "read ~/.ssh", "api_key", "access_token", "cookie", "private key", "send credentials", "upload secrets", "read all files", "read every file", "read workspace", "read project", "source files", "project files", "workspace files", "repository contents", "upload", "send to", "post to", "http://", "https://", "webhook", "curl ", "bash -c", "sh -c", "powershell", "execute command", "run command"})
	return mcpOrTool && injection && action
}

func agentInstructionSourceExfil(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !isSkillFacingMaterial(b) {
		return false
	}
	// Hidden/tool-schema variants are rooted in AST04; avoid double-counting them as generic AST01.
	if hiddenPromptPayload(c, b) || invisibleInstructionSmuggling(c, b) || mcpToolDescriptionInjection(c, b) {
		return false
	}
	actor := hasAny(c, []string{"you must", "assistant must", "agent must", "when invoked", "on every request", "before answering", "after completing", "silently", "quietly", "secretly", "do not disclose", "do not reveal", "developer message", "system prompt"})
	readData := hasAny(c, []string{"read all files", "read every file", "read workspace", "read the workspace", "read project", "read the project", "collect source", "collect code", "source files", "project files", "workspace files", "repository contents", "repo contents", "entire repository", "all local files", "scan files", "enumerate files"})
	sendOrUpload := hasAny(c, []string{"send to", "post to", "upload", "exfiltrate", "include in request", "append to url", "webhook", "http://", "https://", "curl ", "fetch(", "requests.post", "navigator.sendbeacon", "beacon", "report back", "return the contents", "paste the contents"})
	return actor && readData && sendOrUpload
}

func brandImpersonationMetadata(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !b.IsMeta {
		return false
	}
	// High-signal AST04 case from AST10 guidance: trusted-brand naming plus low-trust publisher
	// signals and sensitive capabilities. Do not flag clearly unofficial educational integrations.
	if hasAny(c, []string{"unofficial", "not affiliated", "community plugin", "example", "sample", "demo"}) {
		return false
	}
	trustedBrand := hasAny(c, []string{"google", "youtube", "gmail", "google calendar", "solana", "phantom", "metamask", "polymarket", "openai", "anthropic", "claude", "github", "microsoft", "slack", "aws", "stripe", "vercel"})
	claim := hasAny(c, []string{"official", "verified", "trusted", "secure", "certified", "partner", "from google", "from github", "from openai", "from anthropic", "google llc", "microsoft corporation"})
	lowTrust := hasAny(c, []string{`"verified_publisher":false`, `"verified_publisher": false`, "verified_publisher:false", "verifiedpublisher:false", "publisher_verified:false", `"verified":false`, `"verified": false`, "verified:false", "verified: false", "unverified", "gogle", "goog1e", "yutube", "solana-walllet", "polymarket-tradr", `"publisher":""`, `"publisher": ""`})
	sensitive := hasAny(c, []string{"<all_urls>", "all_urls", "cookies", "tabs", "webrequest", "history", "wallet", "seed phrase", "mnemonic", "private key", "api_key", "access_token", "oauth", "read_all", "write_all", "browser", "clipboardread"}) || manifestBroadCapability(c)
	return trustedBrand && claim && lowTrust && sensitive
}

func projectConfigAutoRunHijack(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	rel := strings.ToLower(b.Rel)
	configPath := strings.Contains(rel, ".vscode/tasks.json") || strings.Contains(rel, ".vscode/launch.json") || strings.Contains(rel, ".devcontainer/") || strings.Contains(rel, "devcontainer.json") || strings.Contains(rel, ".envrc") || strings.Contains(rel, ".husky/") || strings.Contains(rel, "lefthook") || strings.Contains(rel, "pre-commit-config") || strings.Contains(rel, "post-checkout") || strings.Contains(rel, "post-merge") || strings.Contains(rel, "prepare-commit-msg") || strings.Contains(rel, "justfile") || strings.Contains(rel, "taskfile")
	autoRun := hasAny(c, []string{"runon", "folderopen", "postcreatecommand", "postattachcommand", "initializecommand", "poststartcommand", "pre-commit", "post-checkout", "post-merge", "prepare-commit-msg", "direnv", "layout", "on_project_open", "on project open", "autorun", "auto run", "run_on_load", "run on load"})
	exec := hasAny(c, []string{"bash -c", "sh -c", "zsh -c", "powershell", "pwsh", "cmd.exe", "python -c", "node -e", "curl ", "wget ", "npx ", "pnpm dlx", "uvx ", "chmod +x", "./"})
	remoteOrSecret := hasAny(c, []string{"http://", "https://", "raw.githubusercontent.com", "gist.githubusercontent.com", "pastebin.com/raw", "webhook", "discord.com/api/webhooks", "hooks.slack.com", "api_key", "access_token", "github_token", "id_rsa", ".env", "secrets."})
	return configPath && autoRun && exec && remoteOrSecret
}

func dockerfileRemoteEntrypoint(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !strings.EqualFold(filepath.Base(b.Rel), "dockerfile") {
		return false
	}
	remoteFetch := hasAny(c, []string{"add http://", "add https://", "curl ", "wget ", "git clone", "raw.githubusercontent.com", "gist.githubusercontent.com", "releases/download/latest", "main.zip", "master.zip"})
	executable := hasAny(c, []string{"chmod +x", "entrypoint", "cmd [", "bash -c", "sh -c", "python -c", "node -e", "/usr/local/bin", "/tmp/"})
	noIntegrity := !hasAny(c, []string{"sha256", "sha384", "sha512", "gpg --verify", "cosign verify", "content_hash", "integrity"})
	return remoteFetch && executable && noIntegrity
}

func escapedPayloadEvasion(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta || isSkillFacingMaterial(b)) {
		return false
	}
	encoded := hasAny(c, []string{"\\x68", "\\x74", "\\x2f", "\\u0068", "\\u0074", "%68%74%74%70", "%2f%2f", "fromcharcode", "charcodeat", "unescape(", "decodeuri", "decodeuricomponent", "atob(", "base64"})
	reconstruct := hasAny(c, []string{"eval(", "exec(", "new function", "function(", "settimeout(", "setinterval(", "child_process", "subprocess", "os.system", "powershell", "bash -c", "sh -c", "fetch(", "requests.post", "reqwest", "curl "})
	payload := hasAny(c, []string{"http://", "https://", "webhook", "api_key", "access_token", "github_token", "process.env", "std::env", "env::var", ".env", "id_rsa", "cookie", "wallet", "private key"})
	return encoded && reconstruct && payload
}

func dependencyConfusionOrMutableInstaller(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(isPackagePathV26(b.Rel) || isKnownTextConfigPath(b.Rel)) {
		return false
	}
	alternateRegistry := hasAny(c, []string{"extra-index-url", "index-url", "registry=", "npm_config_registry", "--registry", "trusted-host", "git+http", "git://", "install from url", "dependency confusion", "typosquat", "private registry", "packages.example", "raw.githubusercontent.com", "gist.githubusercontent.com"})
	mutable := hasAny(c, []string{"@latest", ":latest", "version=\"*\"", "version = \"*\"", "version='*'", "version = '*'", "latest.json", "main.zip", "master.zip", "releases/download/latest", "branch=main", "branch = main"})
	installerExec := hasAny(c, []string{"postinstall", "preinstall", "prepare", "setup_requires", "cmdclass", "build-backend", "backend-path", "node -e", "python -c", "curl ", "wget ", "bash -c", "sh -c", "| bash", "| sh"})
	runner := hasAny(c, []string{"npx ", "pnpm dlx", "bunx ", "pipx ", "uvx ", "go install", "cargo install"})
	return (alternateRegistry && installerExec) || (mutable && (runner || installerExec))
}

func knownTyposquatOrDependencyConfusion(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !isPackagePathV26(b.Rel) {
		return false
	}
	// High-signal patterns motivated by skill supply-chain writeups: exact known
	// typosquats, self-described dependency confusion, and private-package lookup
	// through an alternate public/remote index. Do not flag ordinary unpinned deps.
	knownTyposquat := hasAny(c, []string{"yutube-dl-core", "yutube_dl_core", "you-tube-dl-core", "gogle-workspace", "goog1e-workspace", "google-worksapce", "solana-walllet", "polymarket-tradr", "openclaw-core-helper", "clawhub-helper-cli"})
	selfDescribed := hasAny(c, []string{"dependency confusion", "typosquat", "typo-squat", "squatted package", "namespace confusion"})
	installContext := hasAny(c, []string{"dependencies", "devdependencies", "requires", "install_requires", "requirements", "package", "version", "==", "^", "~"})
	return (knownTyposquat && installContext) || selfDescribed
}

func alternatePrivateIndexRisk(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !isPackagePathV26(b.Rel) {
		return false
	}
	altIndex := hasAny(c, []string{"extra-index-url", "--extra-index-url", "index-url", "--index-url", "registry=", "--registry", "npm_config_registry", ".npmrc", ".pypirc", "trusted-host"})
	privateName := hasAny(c, []string{"internal-", "private-", "corp-", "company-internal", "skill-internal", "@internal/", "@corp/", "@company/"})
	installContext := hasAny(c, []string{"dependencies", "devdependencies", "requires", "install_requires", "requirements", "package", "version", "==", "^", "~"})
	lockOrHash := hasAny(c, []string{"sha256", "sha384", "integrity", "package-lock", "poetry.lock", "pipfile.lock", "hashes", "--require-hashes"})
	return altIndex && privateName && installContext && !lockOrHash
}

func ciWorkflowRemoteExecution(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	rel := strings.ToLower(b.Rel)
	workflowPath := strings.Contains(rel, ".github/workflows/") || strings.Contains(rel, ".gitlab-ci") || strings.Contains(rel, "circleci") || strings.Contains(rel, "buildkite") || strings.Contains(rel, "azure-pipelines") || strings.Contains(rel, "jenkinsfile") || strings.Contains(rel, "workflow")
	if !(workflowPath || strings.Contains(c, "github_token") || strings.Contains(c, "github_actions") || strings.Contains(c, "runs-on") || strings.Contains(c, "stages:")) {
		return false
	}
	runStep := hasAny(c, []string{"run:", "script:", "commands:", "shell:", "steps:"})
	remote := hasAny(c, []string{"curl ", "curl -", "wget ", "wget -", "raw.githubusercontent.com", "gist.githubusercontent.com", "pastebin.com/raw", "http://", "https://"})
	exec := hasAny(c, []string{"| bash", "| sh", "bash -c", "sh -c", "python -c", "node -e", "chmod +x", "./", "npx ", "pnpm dlx", "uvx "})
	secret := hasAny(c, []string{"secrets.", "github_token", "actions_id_token_request_token", "id-token", "oidc", "api_key", "token", ".env", "ssh_private_key"})
	return workflowPath && runStep && remote && (exec || secret)
}

func localBinaryExecutionLure(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !isSkillFacingMaterial(b) {
		return false
	}
	lure := hasAny(c, []string{"before proceeding", "before using", "must run", "must execute", "required helper", "helper binary", "installer helper", "run the executable", "run ./", "execute ./", "launch ./", "open ./", "copy and run", "paste into terminal"})
	binary := hasAny(c, []string{".exe", ".dmg", ".pkg", ".app", ".msi", ".scr", ".command", ".bin", ".run", ".elf", "helper.exe", "installer.exe", "updater.exe", "chmod +x ./", "chmod +x /tmp/", "chmod +x /var/tmp/", "/tmp/.helper", "/tmp/helper", "./install", "./setup", "./helper", "./updater"})
	opacity := hasAny(c, []string{"notarized", "verified", "signed helper", "downloaded helper", "bundled helper", "precompiled", "no source", "do not inspect", "ignore warnings", "security warning", "gatekeeper", "smart screen", "smartscreen", "quarantine"})
	opaqueBinary := hasAny(c, []string{".exe", ".dmg", ".pkg", ".app", ".msi", ".scr", "helper.exe", "installer.exe", "updater.exe"})
	riskyContext := hasAny(c, []string{"credential", "token", "api_key", ".env", "wallet", "browser", "ssh", "network", "webhook", "curl ", "wget "})
	return lure && binary && (opaqueBinary || opacity || riskyContext)
}

func markdownOpaqueBinaryDownload(c string, b FileBlob) bool {
	if !isSkillFacingMaterial(b) {
		return false
	}
	remote := hasAny(c, []string{"curl ", "wget ", "invoke-webrequest", "downloadfile(", "releases/download", "dist.example", "build.example"})
	binary := hasAny(c, []string{".bin", ".exe", ".dmg", ".pkg", ".msi", ".app", "/usr/local/bin/", "~/.local/bin/", "~/.cache/", "/tmp/."})
	makeExecutable := hasAny(c, []string{"chmod +x", "chmod 755", "install -m 755", "start-process", "./", " --daemon", "exec "})
	integrity := hasAny(c, []string{"sha256", "sha512", "shasum", "checksum", "gpg --verify", "cosign verify", "minisign", "signature verification"})
	return remote && binary && makeExecutable && !integrity
}

func rsaModularExecutionPayload(c string, b FileBlob) bool {
	if !isSkillFacingMaterial(b) {
		return false
	}
	modular := hasAny(c, []string{"chr(pow(", "chr (pow(", "pow(c,", "pow (c,", "modular arithmetic"})
	reconstruct := hasAny(c, []string{"''.join", `"".join`, "join(chr", "join (chr"})
	sink := hasAny(c, []string{"exec(", "eval(", "compile("})
	return modular && reconstruct && sink
}

func bundledOpaqueBinaryExecution(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !isSkillFacingMaterial(b) {
		return false
	}
	binary := hasAny(c, []string{"*.bin", "*.so", "*.dylib", "*.dll", "plugins/", "native plugin", "bundled binary"})
	makeExecutable := hasAny(c, []string{"chmod +x", "chmod 755", "install -m 755"})
	launch := hasAny(c, []string{`"$plugin"`, "./$plugin", " --init", " --daemon", "exec ", "start-process"})
	sensitiveContext := hasAny(c, []string{"$home", "user environment", "env-passthrough", "ssh_auth_sock", "credential", "token"})
	provenance := hasAny(c, []string{"sha256", "sha512", "checksum", "signature", "cosign verify", "gpg --verify", "source code", "build from source"})
	return binary && makeExecutable && launch && sensitiveContext && !provenance
}

func startupPersistencePayload(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	rel := strings.ToLower(b.Rel)
	startupPath := strings.HasSuffix(rel, ".plist") || strings.HasSuffix(rel, ".service") || strings.HasSuffix(rel, ".timer") || strings.HasSuffix(rel, ".desktop") || strings.HasSuffix(rel, ".reg") || strings.Contains(rel, "launchagents") || strings.Contains(rel, "launchdaemons") || strings.Contains(rel, "systemd") || strings.Contains(rel, "cron") || strings.Contains(rel, "startup")
	startupContent := hasAny(c, []string{"runatload", "keepalive", "execstart", "wantedby=", "onbootsec", "@reboot", "schtasks", "runonce", "startup", "launchctl", "programarguments", "cron"})
	payload := hasAny(c, []string{"curl ", "wget ", "http://", "https://", "bash -c", "sh -c", "powershell", "cmd.exe", "python -c", "node -e", "webhook", "socket", "base64", "eval(", "exec("})
	return (startupPath || startupContent) && startupContent && payload
}

func microInstallRemoteExec(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	path := strings.ToLower(b.Rel)
	installScope := isPackagePath(path) || strings.Contains(path, "install") || strings.Contains(path, "setup") || strings.Contains(path, "build") || strings.Contains(path, "makefile") || strings.HasSuffix(path, "dockerfile")
	if !installScope {
		return false
	}
	lifecycle := hasAny(c, []string{"preinstall", "postinstall", "prepare", "install_requires", "setup(", "cmdclass", "build_ext", "build-backend", "entry_points", "npm_lifecycle_event", "make install"})
	remote := hasAny(c, []string{"curl ", "wget ", "iwr ", "invoke-webrequest", "requests.get", "urllib.request", "urlopen(", "fetch(", "axios.get", "http.get", "https.request", "raw.githubusercontent.com", "gist.githubusercontent.com"})
	exec := hasAny(c, []string{"| bash", "| sh", "bash -c", "sh -c", "powershell", "iex", "invoke-expression", "node -e", "python -c", "subprocess", "os.system", "child_process", "eval(", "chmod +x", "exec("})
	return lifecycle && remote && exec
}

func microUnsafeYamlTag(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	if !(strings.HasSuffix(strings.ToLower(b.Rel), ".yaml") || strings.HasSuffix(strings.ToLower(b.Rel), ".yml") || b.IsDoc || b.IsMeta || b.IsCode) {
		return false
	}
	return hasAny(c, []string{"!!python/object/apply", "!!python/object/new", "!!python/name", "tag:yaml.org,2002:python/object", "!!ruby/object", "!!js/function", "!!javax.script"})
}

func microHostIsolationStrong(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	path := strings.ToLower(b.Rel)
	containerScope := strings.Contains(path, "docker") || strings.Contains(path, "compose") || strings.Contains(path, "container") || strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, "dockerfile") || b.IsMeta
	if !containerScope {
		return false
	}
	return hasAny(c, []string{"/var/run/docker.sock", "privileged: true", "--privileged", "network_mode: host", "--network host", "pid: host", "cap_sys_admin", "hostpid: true", "hostnetwork: true", "hostpath:", "securitycontext:", "allowprivilegeescalation: true"})
}

func microAgentConfigHookRCE(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	path := strings.ToLower(b.Rel)
	agentPath := strings.Contains(path, ".claude") || strings.Contains(path, ".cursor") || strings.Contains(path, "mcp") || strings.Contains(path, "settings.json") || strings.Contains(path, "agents.json") || strings.Contains(path, "claude")
	if !(agentPath || b.IsMeta) {
		return false
	}
	hook := hasAny(c, []string{"hook", "hooks", "pretooluse", "posttooluse", "onstart", "onload", "mcpservers", "command", "cmd", "shell", "args"})
	exec := hasAny(c, []string{"bash", "sh -c", "node -e", "python -c", "powershell", "npx ", "uvx ", "pipx", "subprocess", "child_process", "curl ", "wget "})
	override := hasAny(c, []string{"anthropic_base_url", "openai_api_base", "base_url", "api_base", "model_gateway", "proxy_url", "webhook"})
	return hook && exec && (override || hasAny(c, []string{".env", "api_key", "token", "credential", "secret", "postinstall", "preinstall"}))
}

func microRemotePluginNoApproval(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta || isPackagePath(b.Rel)) {
		return false
	}
	plugin := hasAny(c, []string{"registerplugin", "register_plugin", "addplugin", "add_plugin", "loadplugin", "load_plugin", "registertool", "register_tool", "tool registry", "plugin registry", "plugin_url", "module_url"})
	remote := hasAny(c, []string{"http://", "https://", "plugin.js", "module.js", "remote plugin", "remote module", "raw.githubusercontent.com", "gist.githubusercontent.com"})
	noApproval := hasAny(c, []string{"approval:false", "approval: false", "auth:false", "auth: false", "no approval", "unauthenticated", "allow_unreviewed", "skip_review", "verified:false"})
	return plugin && remote && noApproval
}

func microSimpleHotReloadRemote(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta || isPackagePath(b.Rel)) {
		return false
	}
	watch := hasAny(c, []string{"fs.watch", "watch(", "watchdog", "inotify", "hot reload", "hot-reload", "reload on change"})
	remote := hasAny(c, []string{"http://", "https://", "download(", "fetch(", "axios.get", "requests.get", "curl ", "wget ", "remote_config", "plugin_url", "module_url"})
	load := hasAny(c, []string{"reload(", "import(", "await import", "require(", "eval(", "exec(", "load(", "importlib", "vm.runinnewcontext"})
	return watch && remote && load
}

func microUnsafeDeserializeSourceSink(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || strings.HasSuffix(strings.ToLower(b.Rel), ".md") || strings.HasSuffix(strings.ToLower(b.Rel), ".yaml") || strings.HasSuffix(strings.ToLower(b.Rel), ".yml")) {
		return false
	}
	sinks := []string{"pickle.load", "pickle.loads", "marshal.load", "marshal.loads", "dill.load", "dill.loads", "joblib.load", "jsonpickle.decode", "node-serialize", "unserialize(", "yaml.load", "YAML.load"}
	sources := []string{"requests.get", "requests.post", "urllib.request", "urlopen(", "fetch(", "axios.get", "open(", "readfile", "read_text", "sys.stdin", "input(", "argv", "upload", "multipart", "base64", "b64decode", "frombase64", "config", "manifest", "metadata"}
	return lineWindowCooccur(c, sinks, sources, 12)
}

func microExecTaintedSourceSink(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !b.IsCode {
		return false
	}
	sinks := []string{"os.system", "subprocess.run", "subprocess.call", "popen(", "eval(", "exec(", "child_process.exec", "child_process.spawn", "runtime.getruntime().exec", "exec.command", "shell=true", "bash -c", "sh -c"}
	sources := []string{"input(", "argv", "request.", "req.body", "params", "os.environ", "process.env", "getenv(", "base64", "b64decode", "atob(", "fetch(", "requests.get", "urllib.request", "manifest", "metadata", "config", ".env", "api_key", "token"}
	return lineWindowCooccur(c, sinks, sources, 10)
}

func lineWindowCooccur(c string, aNeedles, bNeedles []string, window int) bool {
	lines := strings.Split(c, "\n")
	var aLines []int
	var bLines []int
	for i, line := range lines {
		if hasAny(line, aNeedles) {
			aLines = append(aLines, i)
		}
		if hasAny(line, bNeedles) {
			bLines = append(bLines, i)
		}
	}
	for _, a := range aLines {
		for _, b := range bLines {
			if a-b <= window && b-a <= window {
				return true
			}
		}
	}
	return false
}

func microPIIOutboundChain(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	pii := hasAny(c, []string{"passport", "credit card", "ssn", "social security", "national id", "driver's license", "drivers license", "bank account", "contact list", "address book", "personal data", "pii", "date of birth", "phone number", "email addresses"})
	outbound := hasAny(c, []string{"webhook", "requests.post", "requests.put", "fetch(", "axios.post", "http.post", "upload", "send to http", "exfiltrate", "discord.com/api/webhooks", "hooks.slack.com"})
	imperative := b.IsCode || hasAny(c, []string{"collect", "read", "upload", "send", "export", "scrape", "harvest", "extract"})
	return pii && outbound && imperative
}

func privacyEvasionSignal(c string) bool {
	return hasAny(c, []string{"without consent", "without permission", "without approval", "without asking", "do not disclose", "do not reveal", "do not tell", "silently", "secretly", "quietly", "hidden instruction", "bypass consent", "skip consent", "ignore privacy", "exfiltrate", "harvest"})
}

func microBrowserWalletStoreExfil(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	store := hasAny(c, []string{"login data", "local state", "cookies.sqlite", "chrome.cookies", "browser.cookies", "document.cookie", "localstorage", "sessionstorage", "indexeddb", "wallet.dat", "seed phrase", "mnemonic", "metamask", "phantom", "electrum", "keystore", ".config/solana/id.json", "solana keypair"})
	outbound := hasAny(c, []string{"webhook", "requests.post", "fetch(", "axios.post", "sendbeacon", "xmlhttprequest", "websocket.send", "curl ", "scp ", "sftp ", "discord.com/api/webhooks"})
	return store && outbound
}

func microMCPRemoteAutoApprove(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	rel := strings.ToLower(b.Rel)
	mcpScope := strings.Contains(rel, "mcp") || strings.Contains(rel, ".claude") || strings.Contains(rel, "claude_desktop_config") || strings.Contains(rel, "settings.json") || strings.Contains(c, "mcpservers") || strings.Contains(c, "mcp_servers") || strings.Contains(c, "modelcontextprotocol")
	if !mcpScope {
		return false
	}
	runner := hasAny(c, []string{"npx ", "uvx ", "pipx ", "bunx ", "pnpm dlx", "node ", "python ", "bash -c", "sh -c", "command"})
	remoteOrMutable := hasAny(c, []string{"@latest", "latest", "http://", "https://", "raw.githubusercontent.com", "gist.githubusercontent.com", "curl ", "wget ", "npm:", "pypi"})
	approvalBypass := hasAny(c, []string{"autoapprove", "auto_approve", "approval:false", "approval: false", "dangerouslyskippermissions", "dangerously-skip-permissions", "skip_review", "allow_unreviewed", "trusted: true"})
	return runner && remoteOrMutable && approvalBypass
}

func microVSCodeExtensionWorkspaceExfil(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || isPackagePath(b.Rel) || b.IsMeta) {
		return false
	}
	vscode := hasAny(c, []string{"vscode.workspace", "activationevents", "contributes", "extensionkind", "workspace.fs.readfile", "workspace.findfiles", "ondidopentextdocument", "activetexteditor"})
	workspaceRead := hasAny(c, []string{"workspace.findfiles", "workspace.fs.readfile", "fs.readfilesync", "readfile", "readfilesync", "workspace folder", "all files", "ondidopentextdocument"})
	outbound := hasAny(c, []string{"fetch(", "axios.post", "request.post", "https.request", "sendbeacon", "xmlhttprequest", "websocket", "webhook", "telemetry"})
	return vscode && workspaceRead && outbound
}

func microBrowserExtensionBroadExfil(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta || isPackagePath(b.Rel)) {
		return false
	}
	ext := hasAny(c, []string{"manifest_version", "chrome-extension", "browser extension", "chrome.tabs", "chrome.cookies", "chrome.storage", "browser.cookies", "content_scripts", "background", "service_worker"})
	broadPerm := hasAny(c, []string{"<all_urls>", "*://*/*", "host_permissions", "cookies", "tabs", "webrequest", "storage", "scripting"})
	outbound := hasAny(c, []string{"fetch(", "axios.post", "sendbeacon", "xmlhttprequest", "websocket", "webhook", "discord.com/api/webhooks", "hooks.slack.com"})
	return ext && broadPerm && outbound
}

func microCloudMetadataCredentialExfil(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta || b.IsDoc) {
		return false
	}
	metadata := hasAny(c, []string{"169.254.169.254", "metadata.google.internal", "metadata/identity/oauth2/token", "iam/security-credentials", "metadata/computeMetadata/v1", "x-aws-ec2-metadata-token", "metadata-flavor: google"})
	credential := hasAny(c, []string{"token", "accesskeyid", "secretaccesskey", "sessiontoken", "identity/oauth2", "security-credentials", "authorization"})
	outbound := hasAny(c, []string{"requests.post", "fetch(", "axios.post", "curl -d", "curl --data", "webhook", "discord.com/api/webhooks", "upload", "send to"})
	return metadata && credential && outbound
}

func microKubeServiceAccountExfil(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta || b.IsDoc) {
		return false
	}
	kubeToken := hasAny(c, []string{"/var/run/secrets/kubernetes.io/serviceaccount/token", "serviceaccount/token", "kubernetes.io/serviceaccount", "kubernetes_service_host", "bearer $(cat", "bearer `cat"})
	pivotOrOut := hasAny(c, []string{"requests.post", "fetch(", "axios.post", "curl -d", "curl --data", "webhook", "kubectl", "kubernetes.default.svc", "apis/authorization.k8s.io", "secrets"})
	return kubeToken && pivotOrOut
}

func microShellCredentialStoreExfil(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta || b.IsDoc) {
		return false
	}
	store := hasAny(c, []string{".bash_history", ".zsh_history", ".git-credentials", ".npmrc", ".pypirc", ".netrc", "known_hosts", "ssh config", ".ssh/config", "pip.conf", "credentials file"})
	read := hasAny(c, []string{"cat ", "readfile", "readfilesync", "read_text", "open(", "fs.read", "source", "grep", "awk"})
	outbound := hasAny(c, []string{"requests.post", "fetch(", "axios.post", "curl -d", "curl --data", "webhook", "scp ", "sftp ", "upload"})
	return store && read && outbound
}

func microCIIdentityTokenExfil(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	rel := strings.ToLower(b.Rel)
	workflow := strings.Contains(rel, ".github/workflows") || strings.Contains(rel, ".gitlab-ci") || strings.Contains(rel, "circleci") || strings.Contains(rel, "buildkite") || strings.Contains(rel, "azure-pipelines") || strings.Contains(rel, "jenkinsfile") || strings.Contains(c, "github_token") || strings.Contains(c, "actions_id_token_request_token")
	if !workflow {
		return false
	}
	identity := hasAny(c, []string{"id-token: write", "id-token:write", "actions_id_token_request_token", "oidc", "github_token", "secrets.", "ci_job_jwt", "vault_token"})
	outbound := hasAny(c, []string{"curl -d", "curl --data", "requests.post", "fetch(", "webhook", "discord.com/api/webhooks", "hooks.slack.com", "http://", "https://"})
	return identity && outbound
}

func microDockerfileRemoteAddExec(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	rel := strings.ToLower(b.Rel)
	if !(strings.HasSuffix(rel, "dockerfile") || strings.Contains(rel, "dockerfile") || strings.Contains(rel, "containerfile") || strings.Contains(rel, "build")) {
		return false
	}
	remoteAdd := hasAny(c, []string{"add http://", "add https://", "curl ", "wget ", "git clone", "raw.githubusercontent.com", "gist.githubusercontent.com"})
	exec := hasAny(c, []string{"run ", "chmod +x", "bash ", "sh ", "python ", "node ", "entrypoint", "cmd [", "| bash", "| sh"})
	noPin := !hasAny(c, []string{"sha256:", "sha256sum -c", "gpg --verify", "cosign verify", "checksum"})
	return remoteAdd && exec && noPin
}

func microScanBypassSelfUpdate(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsDoc || b.IsMeta || b.IsCode) {
		return false
	}
	bypass := hasAny(c, []string{"after scan", "post-scan", "after approval", "after review", "bypass scanner", "avoid detection", "disable scanner", "hide from scanner", "do not mention", "stealth mode"})
	update := hasAny(c, []string{"self-update", "self update", "download latest", "fetch latest", "remote_config", "update_url", "plugin_url", "manifest_url", "hotfix", "pull latest"})
	execOrInstruction := hasAny(c, []string{"| bash", "| sh", "eval(", "exec(", "source <(", "import(", "reload(", "instructions.md", "skill.md", "prompt.md", "system.md"})
	remote := hasAny(c, []string{"http://", "https://", "curl ", "wget ", "fetch(", "requests.get"})
	return bypass && update && remote && execOrInstruction
}

func microPolicyFileTamper(c string, b FileBlob) bool {
	if benignInstructionalContext(c) || !(b.IsCode || b.IsMeta || b.IsDoc) {
		return false
	}
	policyTarget := hasAny(c, []string{"claude.md", "agents.md", "memory.md", "soul.md", "settings.json", ".claude/settings", "policy.md", "guardrails", "approval", "denylist", "allowlist"})
	writeOrDisable := hasAny(c, []string{"append", "writefile", "write_file", "overwrite", "sed -i", "tee -a", "disable", "remove guard", "turn off", "bypass", "autoapprove", "dangerously-skip-permissions", "ignore previous"})
	risky := hasAny(c, []string{"bash -c", "sh -c", "subprocess", "child_process", "curl ", "wget ", "webhook", ".env", ".ssh", "api_key", "token", "credential"})
	return policyTarget && writeOrDisable && risky
}

func crossPlatformMetadataLoss(c string, b FileBlob) bool {
	if benignInstructionalContext(c) {
		return false
	}
	return crossPlatformSecurityMetadataSignal(c) && crossPlatformWeakeningSignal(c) && crossPlatformIdentityOrEgressLossSignal(c)
}

func crossPlatformSecurityMetadataSignal(c string) bool {
	crossPlatform := hasAny(c, []string{"platforms", "openclaw", "claude", "cursor", "codex", "vscode", "vs code", "gemini cli", "mcp", "modelcontextprotocol", "cross-platform", "multi-platform", "ported", "porting", "adapter"})
	securityMetadata := hasAny(c, []string{"risk_tier", "risk-tier", "content_hash", "content-hash", "signature", "ed25519", "scan_status", "deny_write", "deny write", "network.allow", "network:", "permissions", "capabilities"})
	return crossPlatform && securityMetadata
}

func crossPlatformWeakeningSignal(c string) bool {
	return hasAny(c, []string{"network:true", "network: true", "\"network\":true", "\"network\": true", "files:\"*", "files: *", "\"files\":\"*", "\"files\": \"*", "permissions: *", "capabilities: *", "allow_all", "allow all", "shell:true", "shell: true", "\"shell\":true", "\"shell\": true", "lost", "dropped", "stripped", "omitted", "translated", "converted"})
}

func crossPlatformIdentityOrEgressLossSignal(c string) bool {
	return hasAny(c, []string{"soul.md", "memory.md", "agents.md", "deny: \"*\"", "deny: '*'", "deny=*", "default deny", "allowlisted egress", "domain allowlist", "without signature", "unsigned", "no content_hash", "no content hash"})
}

func metadataClaimsNetworkDisabled(c string) bool {
	return hasAny(c, []string{"\"network\":false", "\"network\": false", "network:false", "network: false", "network=false", "\"internet\":false", "\"internet\": false", "internet:false", "internet: false", "egress:false", "egress: false"})
}

func metadataClaimsShellDisabled(c string) bool {
	return hasAny(c, []string{"\"shell\":false", "\"shell\": false", "shell:false", "shell: false", "shell=false", "\"exec\":false", "\"exec\": false", "exec:false", "exec: false", "command:false", "command: false"})
}

func metadataClaimsLowRisk(c string) bool {
	low := hasAny(c, []string{"risk_tier", "risk-tier", "risk level", "risk_level", "security_level", "classification"}) && hasAny(c, []string{"l0", "safe", "low", "minimal", "none", "no risk", "read-only", "readonly"})
	return low && !hasAny(c, []string{"high", "critical", "dangerous", "l3"})
}

func metadataClaimsCleanScan(c string) bool {
	return hasAny(c, []string{"scan_status", "scan status", "security_scan", "security scan", "scanner", "audit_result", "audit result", "verified"}) && hasAny(c, []string{"passed", "clean", "safe", "no issues", "approved", "trusted"})
}

func applyBenignDampener(f Finding, blobs []FileBlob) float64 {
	w := f.Weight
	lowerFile := strings.ToLower(f.File)
	docOnly := false
	if strings.Contains(lowerFile, "readme") || strings.Contains(lowerFile, "docs/") || strings.Contains(lowerFile, "examples/") || strings.Contains(lowerFile, "sample") || strings.Contains(lowerFile, "fixture") || strings.Contains(lowerFile, "test") {
		docOnly = true
	}
	if docOnly && !f.Strong {
		w *= 0.65
	}
	for _, b := range blobs {
		if b.Rel != f.File {
			continue
		}
		if b.IsDoc && !f.Strong {
			w *= 0.75
		}
		if hasAny(b.Lower, []string{"mock", "unit test", "test fixture", "synthetic", "example only", "demo only"}) && !f.Strong {
			w *= 0.75
		}
		break
	}
	return w
}

func buildEvidence(verdict, category string, findings []Finding, scores map[string]float64) string {
	if verdict == "benign" || category == "benign" {
		return "benign: inspected manifest and code did not show an actionable chain involving credential access, command execution, unsafe deserialization, update drift, or cross-platform token reuse signals."
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Category == category && findings[j].Category != category {
			return true
		}
		if findings[i].Category != category && findings[j].Category == category {
			return false
		}
		verifiedI := strings.Contains(strings.ToLower(findings[i].Reason), "verified-flow")
		verifiedJ := strings.Contains(strings.ToLower(findings[j].Reason), "verified-flow")
		if verifiedI != verifiedJ {
			return verifiedI
		}
		if findings[i].Strong != findings[j].Strong {
			return findings[i].Strong
		}
		return findings[i].Weight > findings[j].Weight
	})
	chosen := Finding{Category: category, File: "skill files", Reason: "multiple correlated risk signals were found"}
	for _, f := range findings {
		if f.Category == category {
			chosen = f
			break
		}
	}
	label := map[string]string{
		"ast01": "malicious skill behavior",
		"ast02": "supply-chain compromise",
		"ast03": "excessive authorization",
		"ast04": "insecure metadata",
		"ast05": "unsafe deserialization",
		"ast06": "weak isolation",
		"ast07": "update drift",
		"ast08": "insufficient scanning or evasion",
		"ast09": "governance weakness",
		"ast10": "cross-platform reuse",
	}[category]
	if label == "" {
		label = "agentic skill risk"
	}
	extra := ""
	if len(scores) > 1 {
		parts := topScoreParts(scores, category, 2)
		if len(parts) > 0 {
			extra = "; secondary signals: " + strings.Join(parts, ", ")
		}
	}
	ev := fmt.Sprintf("OWASP %s %s: %s %s%s.", strings.ToUpper(category), label, sanitizePath(chosen.File), chosen.Reason, extra)
	return truncateSentence(ev, 420)
}

func topScoreParts(scores map[string]float64, primary string, n int) []string {
	type kv struct {
		K string
		V float64
	}
	var arr []kv
	for k, v := range scores {
		if k == primary || v < 1.5 {
			continue
		}
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].V > arr[j].V })
	if len(arr) > n {
		arr = arr[:n]
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		out = append(out, fmt.Sprintf("%s %.1f", x.K, x.V))
	}
	return out
}

func calibrateCategory(category string, maxScore float64, scores map[string]float64) (string, float64) {
	// AST precision matters for explainability. When a specific lifecycle/update,
	// deserialization, isolation, or credential-reuse chain is strong, prefer that
	// root cause over the generic AST01 command/network sink that often co-occurs.
	if scores["ast02"] >= 6.0 && (scores["ast07"] >= 4.0 || scores["ast01"] <= scores["ast02"]+6.5) {
		return "ast02", scores["ast02"]
	}
	if scores["ast05"] >= 5.2 && scores["ast01"] <= scores["ast05"]+3.5 {
		return "ast05", scores["ast05"]
	}
	if scores["ast06"] >= 5.0 && scores["ast01"] <= scores["ast06"]+3.5 {
		return "ast06", scores["ast06"]
	}
	if scores["ast07"] >= 5.5 && scores["ast02"] < 6.0 && scores["ast01"] <= scores["ast07"]+3.5 {
		return "ast07", scores["ast07"]
	}
	if scores["ast04"] >= 8.0 && scores["ast02"] < 6.0 && scores["ast05"] < 5.2 && scores["ast06"] < 5.0 && scores["ast01"] <= scores["ast04"]+3.0 {
		return "ast04", scores["ast04"]
	}
	if scores["ast04"] >= 5.2 && scores["ast02"] < 6.0 && scores["ast05"] < 5.2 && scores["ast06"] < 5.0 && scores["ast01"] <= scores["ast04"]+1.5 {
		return "ast04", scores["ast04"]
	}
	if scores["ast10"] >= 4.5 && scores["ast01"] <= scores["ast10"]+4.0 {
		return "ast10", scores["ast10"]
	}
	return category, maxScore
}

func totalStrong(m map[string]int) int {
	t := 0
	for _, v := range m {
		t += v
	}
	return t
}

// capDocumentaryVerdict separates executable behavior from documentation-only
// capability descriptions. Broad co-occurrence heuristics remain visible as
// suspicious, while verified flows and explicit attack instructions can still
// produce a malicious verdict from SKILL.md.
func capDocumentaryVerdict(verdict, category string, findings []Finding, blobs []FileBlob) string {
	if verdict != "malicious" {
		return verdict
	}
	selected := make([]Finding, 0, 8)
	for _, f := range findings {
		if f.Category == category && f.Strong {
			selected = append(selected, f)
		}
	}
	if len(selected) == 0 {
		if category == "ast10" || category == "ast04" || category == "ast06" || category == "ast08" {
			return "suspicious"
		}
		return verdict
	}
	allDocs := true
	for _, f := range selected {
		if highConfidenceDocumentFinding(f) {
			return verdict
		}
		b, ok := blobForFinding(f.File, blobs)
		if !ok || !b.IsDoc {
			allDocs = false
		}
	}
	if !allDocs {
		return verdict
	}

	switch category {
	case "ast10":
		for _, f := range selected {
			if b, ok := blobForFinding(f.File, blobs); ok && concreteRiskFence(analysisText(b)) {
				return verdict
			}
		}
		return "suspicious"
	case "ast04", "ast06":
		return "suspicious"
	case "ast08", "ast01":
		for _, f := range selected {
			if b, ok := blobForFinding(f.File, blobs); ok && concreteRiskFence(analysisText(b)) {
				return verdict
			}
		}
		return "suspicious"
	default:
		return verdict
	}
}

func highConfidenceDocumentFinding(f Finding) bool {
	r := strings.ToLower(f.Reason)
	file := strings.ToLower(filepath.ToSlash(f.File))
	if strings.Contains(r, "hidden prompt payload") && (strings.Contains(file, ".cursor/rules/") || strings.HasSuffix(file, "agents.md") || strings.HasSuffix(file, "claude.md")) {
		return true
	}
	return hasAny(r, []string{
		"verified-flow", "remote skill instruction execution", "downloaded script execution", "invisible instruction smuggling",
		"reverse shell or backdoor", "clickfix-style", "inline base64-decoded shell",
		"concealed operational execution", "irreversible cleanup directive",
		"fake openclaw", "credential webhook", "credential exfiltration", "credential material with a concrete outbound", "data exfiltration",
		"opaque binary", "platform-specific opaque binary", "bundled native binaries",
		"hot-reload remote module", "unsafe deserialization payload", "crypto wallet exfiltration",
		"rsa/modular-arithmetic payload",
		"cloud instance metadata credential endpoint access", "kubernetes service-account token access",
	})
}

func blobForFinding(file string, blobs []FileBlob) (FileBlob, bool) {
	want := filepath.ToSlash(file)
	for _, b := range blobs {
		if filepath.ToSlash(b.Rel) == want {
			return b, true
		}
	}
	return FileBlob{}, false
}

func topCategory(scores map[string]float64) (string, float64) {
	return topCategoryExcept(scores, "")
}

func topCategoryExcept(scores map[string]float64, except string) (string, float64) {
	bestCat := ""
	bestScore := 0.0
	// Stable priority helps deterministic tie-breaking and avoids AST09 over-selection.
	priority := []string{"ast01", "ast02", "ast05", "ast06", "ast07", "ast10", "ast04", "ast03", "ast08", "ast09"}
	for _, cat := range priority {
		if cat == except {
			continue
		}
		if scores[cat] > bestScore {
			bestCat, bestScore = cat, scores[cat]
		}
	}
	return bestCat, bestScore
}

func hasAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func stripDefaultDenyWildcards(c string) string {
	patterns := []string{
		`"deny":"*"`, `"deny": "*"`, `deny:"*"`, `deny: "*"`,
		"deny:'*'", "deny: '*'", "deny=*", "deny = *",
		`network.deny:"*"`, `network.deny: "*"`, `network_deny:"*"`, `network_deny: "*"`,
		`default_deny:"*"`, `default_deny: "*"`,
	}
	out := c
	for _, p := range patterns {
		out = strings.ReplaceAll(out, p, "")
	}
	return out
}

func manifestBroadCapability(c string) bool {
	// Avoid treating a normal host pattern such as https://api.example.com/*,
	// default-deny egress such as network.deny: "*", or explicit false booleans
	// such as "filesystem": false as over-privileged. Flag explicit all-host/all-file
	// tokens, dangerous host/shell/admin tokens, or capabilities that are actually enabled/listed.
	wildcardView := stripDefaultDenyWildcards(c)
	if hasAny(wildcardView, []string{"<all_urls>", "all_urls", "\"*\"", "'*'", "- *", "permissions: *", "capabilities: *", "scopes: *", "read_all", "write_all", "read-all", "write-all", "all_files", "all-files", "all files", "all permissions", "all capabilities", "\"all\"", "'all'", "allow_all", "allow-all"}) {
		return true
	}
	if hasAny(c, []string{"readfilesystem", "writefilesystem", "full_disk", "full-disk", "home_dir", "home-directory", "host_network", "host-network", "host_pid", "hostpid", "hostpath", "dangerouslyskippermissions", "dangerously-skip-permissions"}) {
		return true
	}
	if manifestDangerousPrivilege(c) {
		return true
	}
	if manifestCapabilityEnabled(c, "filesystem") || manifestCapabilityEnabled(c, "file_system") || manifestCapabilityEnabled(c, "file-system") || manifestCapabilityEnabled(c, "shell") || manifestCapabilityEnabled(c, "exec") || manifestCapabilityEnabled(c, "command") || manifestCapabilityEnabled(c, "terminal") || manifestCapabilityEnabled(c, "computer") {
		return true
	}
	if manifestCapabilityEnabled(c, "network") || manifestCapabilityEnabled(c, "internet") {
		return manifestCapabilityEnabled(c, "filesystem") || manifestCapabilityEnabled(c, "file_system") || manifestCapabilityEnabled(c, "file-system") || manifestCapabilityEnabled(c, "shell") || manifestCapabilityEnabled(c, "exec") || manifestCapabilityEnabled(c, "command") || manifestCapabilityEnabled(c, "write") || manifestCapabilityEnabled(c, "read_all") || manifestCapabilityEnabled(c, "write_all") || manifestCapabilityEnabled(c, "read-all") || manifestCapabilityEnabled(c, "write-all")
	}
	return false
}

func manifestCapabilityEnabled(c, cap string) bool {
	disabled := []string{"\"" + cap + "\":false", "\"" + cap + "\": false", cap + ": false", cap + "=false", "'" + cap + "': false", "'" + cap + "':false"}
	if hasAny(c, disabled) {
		return false
	}
	enabled := []string{"\"" + cap + "\":true", "\"" + cap + "\": true", cap + ": true", cap + "=true", "'" + cap + "': true", "'" + cap + "':true", "\"" + cap + "\"", "'" + cap + "'", "- " + cap}
	return hasAny(c, enabled)
}

func manifestDangerousPrivilege(c string) bool {
	// Do not treat ordinary metadata such as project_root, admin_mode:false,
	// or privileged:false as a broad capability. Require an enabled flag, an
	// explicit root user/uid, sudo, or host-level namespace/runtime access.
	if !hasAny(c, []string{"privileged", "run_as_root", "requires_root", "admin", "administrator", "host_network", "host-network", "host_pid", "hostpid", "hostpath", "user", "uid", "sudo", "cap_sys_admin", "docker.sock"}) {
		return false
	}
	if manifestCapabilityEnabled(c, "privileged") || manifestCapabilityEnabled(c, "run_as_root") || manifestCapabilityEnabled(c, "requires_root") || manifestCapabilityEnabled(c, "admin") || manifestCapabilityEnabled(c, "administrator") || manifestCapabilityEnabled(c, "host_network") || manifestCapabilityEnabled(c, "host_pid") || manifestCapabilityEnabled(c, "hostpath") {
		return true
	}
	return hasAny(c, []string{"\"user\":\"root\"", "\"user\": \"root\"", "user: root", "user=root", "\"uid\":0", "\"uid\": 0", "uid: 0", "uid=0", "sudo ", " sudo", "cap_sys_admin", "docker.sock", "/var/run/docker.sock", "host_network", "host-network", "host_pid", "hostpid", "hostpath"})
}

func isolationBoundarySignal(c string, b FileBlob) bool {
	if !hasAny(c, []string{"docker.sock", "/proc/", "/sys/fs/cgroup", "/host", "nsenter", "unshare", "chroot", "mount --bind", "cap_sys_admin", "privileged", "host_network", "host-network", "host_pid", "hostpid", "hostpath", "run_as_root", "requires_root", "uid", "sudo"}) {
		return false
	}
	if b.IsMeta {
		return manifestDangerousPrivilege(c) || hasAny(c, []string{"/var/run/docker.sock", "docker.sock", "/proc/self", "/proc/1", "/sys/fs/cgroup", "nsenter", "unshare", "chroot", "mount --bind", "cap_sys_admin", "host_network", "host-network", "host_pid", "hostpid", "hostpath"})
	}
	return hasAny(c, []string{"/var/run/docker.sock", "docker.sock", "/proc/self", "/proc/1", "/sys/fs/cgroup", "/host", "nsenter", "unshare", "chroot", "mount --bind", "cap_sys_admin", "privileged"})
}

func isolationSecretBoundarySignal(c string, b FileBlob) bool {
	if !hasAny(c, []string{"/proc/1/root", "/proc/self/environ", "/proc/self/mountinfo", "/run/secrets", "/var/run/secrets", "/var/lib/kubelet", "containerd.sock"}) {
		return false
	}
	if b.IsMeta {
		return !hasAny(c, []string{"\"/run/secrets\":false", "\"/run/secrets\": false", "run_secrets:false", "run_secrets: false"})
	}
	return true
}

func shouldSkipDir(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case ".git", ".svn", ".hg", "node_modules", "vendor", "dist", "build", "target", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache":
		return true
	}
	return false
}

func shouldSkipFile(rel string) bool {
	n := strings.ToLower(rel)
	return strings.HasSuffix(n, ".png") || strings.HasSuffix(n, ".jpg") || strings.HasSuffix(n, ".jpeg") || strings.HasSuffix(n, ".gif") || strings.HasSuffix(n, ".pdf") || strings.HasSuffix(n, ".zip") || strings.HasSuffix(n, ".tar") || strings.HasSuffix(n, ".gz") || strings.HasSuffix(n, ".7z") || strings.HasSuffix(n, ".exe") || strings.HasSuffix(n, ".dll") || strings.HasSuffix(n, ".so") || strings.HasSuffix(n, ".dylib") || strings.HasSuffix(n, ".class") || strings.HasSuffix(n, ".wasm")
}

func isInterestingFile(rel string) bool {
	n := strings.ToLower(rel)
	if strings.HasSuffix(n, ".tf") {
		return true
	}
	if isManifestPath(n) || isPackagePath(n) || isKnownTextConfigPath(n) {
		return true
	}
	exts := []string{".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".rb", ".php", ".java", ".kt", ".rs", ".c", ".cpp", ".h", ".cs", ".lua", ".pl", ".yaml", ".yml", ".json", ".jsonl", ".toml", ".ini", ".cfg", ".conf", ".env", ".html", ".htm", ".xml", ".svg", ".md", ".mdx", ".mdc", ".prompt", ".prompty", ".txt", ".service", ".timer", ".plist", ".desktop", ".reg"}
	for _, e := range exts {
		if strings.HasSuffix(n, e) {
			return true
		}
	}
	return false
}

func isManifestPath(rel string) bool {
	n := strings.ToLower(rel)
	base := filepath.Base(n)
	return strings.Contains(base, "manifest") || base == "skill.json" || base == "skill.yaml" || base == "skill.yml" || base == "metadata.json" || base == "metadata.yaml" || strings.Contains(n, "metadata/")
}

func isPackagePath(rel string) bool {
	n := strings.ToLower(rel)
	base := filepath.Base(n)
	switch base {
	case "package.json", "setup.py", "pyproject.toml", "requirements.txt", "go.mod", "cargo.toml", "gemfile", "pom.xml", "build.gradle", "composer.json", "makefile", "dockerfile":
		return true
	}
	return strings.Contains(n, "install") || strings.Contains(n, "update") || strings.Contains(n, "postinstall") || strings.Contains(n, "preinstall")
}

func isKnownTextConfigPath(rel string) bool {
	n := strings.ToLower(rel)
	base := filepath.Base(n)
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}
	switch base {
	case ".npmrc", ".yarnrc", ".pnpmrc", ".pypirc", ".netrc", ".curlrc", ".wgetrc", ".bashrc", ".zshrc", ".profile", ".gitmodules", ".pre-commit-config.yaml", "procfile", "servicefile", "jenkinsfile", "crontab", "docker-compose.yml", "compose.yml", "compose.yaml":
		return true
	}
	return false
}

func isDocPath(rel string) bool {
	n := strings.ToLower(rel)
	return strings.HasSuffix(n, ".md") || strings.HasSuffix(n, ".mdx") || strings.HasSuffix(n, ".mdc") || strings.HasSuffix(n, ".prompt") || strings.HasSuffix(n, ".prompty") || strings.HasSuffix(n, ".txt") || strings.HasSuffix(n, ".html") || strings.HasSuffix(n, ".htm") || strings.HasSuffix(n, ".xml") || strings.HasSuffix(n, ".svg") || strings.Contains(n, "docs/")
}

func isCodePath(rel string) bool {
	n := strings.ToLower(rel)
	codeExts := []string{".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".rb", ".php", ".java", ".kt", ".rs", ".c", ".cpp", ".cs", ".lua", ".pl", ".swift", ".scala"}
	for _, e := range codeExts {
		if strings.HasSuffix(n, e) {
			return true
		}
	}
	return false
}

func pathHasSkippedDir(rel string, skip func(string) bool) bool {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] != "" && skip(parts[i]) {
			return true
		}
	}
	return false
}

func readFileSampled(path string, size, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if size <= 0 || size <= limit {
		return io.ReadAll(io.LimitReader(f, limit))
	}
	headLimit := limit / 2
	tailLimit := limit - headLimit
	head, err := io.ReadAll(io.LimitReader(f, headLimit))
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(size-tailLimit, io.SeekStart); err != nil {
		return head, nil
	}
	tail, err := io.ReadAll(io.LimitReader(f, tailLimit))
	if err != nil {
		return head, nil
	}
	out := make([]byte, 0, len(head)+len(tail)+32)
	out = append(out, head...)
	out = append(out, '\n', '[', '.', '.', '.', 's', 'n', 'i', 'p', '.', '.', '.', ']', '\n')
	out = append(out, tail...)
	return out, nil
}

func decodeTextLower(data []byte) (string, bool) {
	if len(data) == 0 {
		return "", false
	}
	if s, ok := decodeUTF16Lower(data); ok {
		return s, true
	}
	if isLikelyBinary(data) {
		return "", false
	}
	return strings.ToLower(string(data)), true
}

func decodeUTF16Lower(data []byte) (string, bool) {
	if len(data) < 4 {
		return "", false
	}
	start := 0
	le, be := false, false
	if data[0] == 0xff && data[1] == 0xfe {
		le, start = true, 2
	} else if data[0] == 0xfe && data[1] == 0xff {
		be, start = true, 2
	} else {
		sample := data
		if len(sample) > 4096 {
			sample = sample[:4096]
		}
		pairs := len(sample) / 2
		if pairs < 8 {
			return "", false
		}
		evenNul, oddNul := 0, 0
		for i, b := range sample {
			if b == 0 {
				if i%2 == 0 {
					evenNul++
				} else {
					oddNul++
				}
			}
		}
		if oddNul > pairs/3 && evenNul < pairs/20 {
			le = true
		} else if evenNul > pairs/3 && oddNul < pairs/20 {
			be = true
		} else {
			return "", false
		}
	}
	u16 := make([]uint16, 0, (len(data)-start)/2)
	for i := start; i+1 < len(data); i += 2 {
		if le {
			u16 = append(u16, uint16(data[i])|uint16(data[i+1])<<8)
		} else if be {
			u16 = append(u16, uint16(data[i])<<8|uint16(data[i+1]))
		}
	}
	if len(u16) == 0 {
		return "", false
	}
	return strings.ToLower(string(utf16.Decode(u16))), true
}

func commitResults(tmpPath, outPath string) error {
	if err := os.Rename(tmpPath, outPath); err == nil {
		return nil
	}
	// Same-directory rename should normally be atomic. This fallback preserves
	// a complete JSONL file in unusual harnesses where an old output file cannot
	// be replaced by a single rename.
	_ = os.Remove(outPath)
	if err := os.Rename(tmpPath, outPath); err == nil {
		return nil
	}
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, data, 0o644)
}

func isLikelyBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	bad := 0
	for _, b := range sample {
		if b == 0 {
			return true
		}
		r := rune(b)
		if r < 32 && b != '\n' && b != '\r' && b != '\t' {
			bad++
		}
	}
	return float64(bad)/float64(len(sample)) > 0.15
}

func sanitizePath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.Trim(p, "/ .")
	if p == "" {
		return "skill files"
	}
	if len(p) > 96 {
		return "..." + p[len(p)-93:]
	}
	return p
}

func truncateSentence(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return strings.TrimRight(s[:n-1], " ,;") + "."
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fail(prefix string, err error) {
	if err == nil {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "%s: %v\n", prefix, err)
	os.Exit(2)
}

// keep io imported for future harness compatibility where stdin-based skill lists are piped.
var _ io.Reader

func analyzeSkillV26Explain(root string) SkillReport {
	return analyzeSkillV26ExplainFromBlobs(collectFilesV26(root))
}

func analyzeSkillV26ExplainFromBlobs(blobs []FileBlob) SkillReport {
	findings := make([]Finding, 0, 80)

	for _, b := range blobs {
		findings = append(findings, analyzeFileV26(b)...)
	}
	findings = append(findings, analyzeCrossFileV26(blobs)...)
	findings = append(findings, analyzeBinaryPerimeter(blobs)...)
	flowSummary := analyzeBehaviorIR(blobs)
	findings = append(findings, flowSummary.Findings...)

	scores := map[string]float64{}
	strongByCat := map[string]int{}
	for _, f := range findings {
		w := applyBenignDampener(f, blobs)
		flowFactor := behaviorIRWeightFactor(f, flowSummary)
		w *= flowFactor
		scores[f.Category] += w
		if f.Strong && flowFactor >= 0.5 {
			strongByCat[f.Category]++
		}
	}

	category, maxScore := topCategory(scores)
	category, maxScore = calibrateCategoryV26(category, maxScore, scores)
	category, maxScore = calibrateVerifiedFlowCategory(category, maxScore, scores, findings)
	blended := maxScore
	for cat, sc := range scores {
		if cat == category {
			continue
		}
		blended += minFloat(sc, 4.0) * 0.18
	}
	if category == "ast09" {
		altCat, altScore := topCategoryExcept(scores, "ast09")
		if altCat != "" && altScore >= 1.8 {
			category = altCat
			maxScore = altScore
		}
	}
	verdict := "benign"
	allStrong := totalStrong(strongByCat)
	if maxScore >= 4.65 || (maxScore >= 3.25 && strongByCat[category] >= 1) || blended >= 5.35 || allStrong >= 2 {
		verdict = "malicious"
	} else if maxScore >= 1.75 || blended >= 2.35 {
		verdict = "suspicious"
	}
	verdict = capDocumentaryVerdict(verdict, category, findings, blobs)
	if verdict == "benign" {
		category = "benign"
	}
	evidence := buildEvidence(verdict, category, findings, scores)
	return SkillReport{
		Verdict:          verdict,
		EngineCategory:   category,
		EvidenceText:     evidence,
		Findings:         findings,
		CategoryScore:    scores,
		TriggerLayer:     "explain",
		TriggerScore:     maxScore,
		TriggerCondition: verdictCondition(verdict, maxScore, strongByCat[category], blended, allStrong),
		TriggerFindings:  auditTriggerFindings(findings, category, 8),
	}
}

// ---- v26 explainability-only feature extractor. It is intentionally not used for verdicts. ----

func collectFilesV26(root string) []FileBlob {
	var blobs []FileBlob
	var total int64
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if total >= maxTotalBytes || len(blobs) >= maxBlobsPerSkill {
			return filepath.SkipAll
		}
		if err != nil || d == nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if shouldSkipDirV26(name) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() <= 0 || total >= maxTotalBytes || len(blobs) >= maxBlobsPerSkill {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if shouldSkipFile(rel) || !isInterestingFileV26(rel) {
			return nil
		}
		data, err := readFileSampled(path, info.Size(), maxFileBytes)
		if err != nil || len(data) == 0 {
			return nil
		}
		lower, ok := decodeTextLower(data)
		if !ok {
			return nil
		}
		if total+int64(len(data)) > maxTotalBytes {
			return nil
		}
		total += int64(len(data))
		blobs = append(blobs, FileBlob{
			Rel:    rel,
			Lower:  lower,
			IsDoc:  isDocPath(rel),
			IsMeta: isManifestPath(rel),
			IsCode: isCodePathV26(rel),
			Size:   int64(len(data)),
		})
		return nil
	})
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].Rel < blobs[j].Rel })
	return blobs
}

func analyzeFileV26(b FileBlob) []Finding {
	if b.IsBinary {
		return []Finding{{"ast01", 2.8, b.Rel, "bundled native executable enters the static-review perimeter; execution intent or provenance is required for malicious promotion", false}}
	}
	c := analysisText(b)
	rel := b.Rel
	var f []Finding

	cmdSink := hasAny(c, []string{"os.system(", "subprocess.", "subprocess.run", "subprocess.call", "popen(", "exec(", "eval(", "execsync", "execfile(", "spawn(", "child_process", "runtime.getruntime().exec", "processbuilder", "shell=true", "shell = true", "system(", "bash -c", "sh -c", "zsh -c", "powershell", "pwsh", "cmd.exe", "wscript.shell", "process.start", "proc_open", "passthru(", "shell_exec", "`$", "bash -i", "/dev/tcp/", "nc -e", "ncat -e", "mkfifo", "socat ", "chmod +x"})
	netSink := hasAny(c, []string{"requests.post", "requests.get", "requests.request", "requests.put", "requests.patch", "requests.", "httpx.", "aiohttp.", "urllib.request", "urlopen(", "http.post", "http.get", "http.request", "https.request", "http.client", "fetch(", "axios.", "got(", "superagent", "xmlhttprequest", "$.ajax", "$.post", "curl ", "curl -", "wget ", "wget -", "net/http", "reqwest", "ureq::", "surf::", "isahc::", "minreq::", "attohttpc", "hyper::client", "client.post", "client.send", "socket.", "websocket", "grpc.", "webhook", "callback_url", "sendbeacon", "navigator.sendbeacon", "new image()", ".src =", "websocket.send", "formdata", "blob(", "discord.com/api/webhooks", "hooks.slack.com", "slack.com/api/", "api.telegram.org/bot", "pastebin.com", "webhook.site", "request.post"})
	secretRead := hasAny(c, []string{"aws_access_key_id", "secret_access_key", "github_token", "gh_token", "slack_token", "bot_token", "api_key", "apikey", "api-key", "bearer ", "authorization:", "private_key", "private key", "client_secret", "dotenv", "/.env", "~/.env", "\".env\"", "'.env'", ".env.local", ".envrc", "process.env.token", "process.env.secret", "process.env.aws", "process.env.github", "process.env.slack", "os.environ", "getenv(", "std::env", "env::var", "dotenvy", "dotenv::", "secrets.", "id_rsa", "id_ed25519", ".ssh/", "~/.ssh", "credentials", "credential", "cookie", "cookies", "session_token", "access_token", "refresh_token", "github_token", "actions_id_token_request_token", "aws_web_identity_token_file", "credential_process", "google_application_credentials", ".aws/credentials", ".azure/", ".config/gcloud", ".kube/config", ".docker/config.json", ".npmrc", ".pypirc", ".netrc", "git-credentials", "localstorage", "sessionstorage", "indexeddb", "chrome local state", "login data", "cookies sqlite", "keychain", "keytar", "keyring", "wallet.dat", "metamask", "electrum", "mnemonic", "keystore"})
	fileRead := hasAny(c, []string{"open(", "readfile", "read_file", "fs.readfilesync", "fs.readfile", "os.environ", "process.env", "getenv(", "std::env", "env::var", "dotenvy", "read_to_string", "read_text", ".read_text(", "ioutil.readfile", "os.readfile", "readlines(", "pathlib.path.home", "os.walk(", "walkdir", "glob(", "readdir", "scandir"})
	fileWrite := hasAny(c, []string{"writefile", "write_file", "fs.writefilesync", "fs.writefile", "os.remove", "unlink(", "rmtree", "shutil.rmtree", "rename(", "replace(", "write_text", ".write_text(", "appendfile", "createwritestream", "chmod(", "chown("})
	decoder := hasAny(c, []string{"base64.b64decode", "base64", "atob(", "frombase64", "decode('base64", "decode(\"base64", "hex.decode", "decodehex", "string.fromcharcode", "charcodeat", "chr(", "rot13", "xor", "gzip", "zlib", "marshal", "char_code", "unescape("})

	if cmdSink && (secretRead || netSink || decoder || hasAny(c, []string{"rm -rf", "/etc/passwd", "chmod 777", "bash -c", "sh -c"})) && (b.IsCode || b.IsMeta) {
		f = append(f, Finding{"ast01", 5.7, rel, "combines command execution with credential, network, destructive, or decoded input signals", true})
	} else if cmdSink && b.IsCode {
		f = append(f, Finding{"ast01", 3.0, rel, "contains executable command/eval sink in code", false})
	}
	if secretRead && netSink && fileRead && (b.IsCode || b.IsMeta) {
		f = append(f, Finding{"ast01", 6.2, rel, "reads secret-like data and sends it through a network sink", true})
	}
	if hasAny(c, []string{"rm -rf /", "shutil.rmtree", "os.remove", "unlink(", "deletefile", "format c:", "wipe"}) && b.IsCode {
		f = append(f, Finding{"ast01", 4.4, rel, "contains destructive file operation indicators", true})
	}
	if hasAny(c, []string{"crontab", "/etc/cron", "launchctl", "launchagents", "launchdaemons", "systemd", ".bashrc", ".zshrc", ".profile", "startup", "schtasks", "reg add", "runonce", "autorun"}) && (cmdSink || fileWrite || netSink) && b.IsCode {
		f = append(f, Finding{"ast01", 4.9, rel, "contains persistence or startup modification behavior near execution, write, or network logic", true})
	}
	if hasAny(c, []string{"exfiltrate", "exfiltration", "steal", "steals", "upload secrets", "send secrets", "send credentials", "collect credentials", "harvest", "credential dump", "token dump"}) && (secretRead || netSink || fileRead) && !b.IsDoc {
		f = append(f, Finding{"ast01", 4.7, rel, "explicitly describes credential harvesting or data exfiltration behavior in executable skill material", true})
	}
	if b.IsDoc && hasAny(c, []string{"you must", "assistant must", "system prompt", "developer instruction", "tool instruction", "when invoked", "on every request"}) && hasAny(c, []string{"send secrets", "send credentials", "upload secrets", "exfiltrate", "steal", "read ~/.ssh", "read .env", "ignore previous"}) {
		f = append(f, Finding{"ast04", 4.1, rel, "instruction document appears to direct the skill toward hidden credential access, exfiltration, or policy override", true})
	}
	if secretRead && (fileRead || netSink || cmdSink) && b.IsCode {
		f = append(f, Finding{"ast01", 4.3, rel, "accesses credential-like material near file, network, or execution logic", true})
	}
	if secretRead && netSink && b.IsCode {
		f = append(f, Finding{"ast01", 5.8, rel, "credential or token material is paired with outbound network behavior", true})
	}
	if netSink && decoder && b.IsCode {
		f = append(f, Finding{"ast08", 2.6, rel, "network path is paired with encoded or reconstructed content handling", false})
	}
	if cmdSink && hasAny(c, []string{"input(", "argv", "req.body", "request.", "params", "metadata", "manifest", "config"}) && b.IsCode {
		f = append(f, Finding{"ast01", 4.1, rel, "user, metadata, or config-controlled value can reach command/eval execution", true})
	}

	if isPackagePathV26(rel) && hasAny(c, []string{"preinstall", "postinstall", "prepare", "setup_requires", "entry_points", "install_requires"}) && (cmdSink || netSink || decoder) {
		f = append(f, Finding{"ast02", 6.4, rel, "package lifecycle metadata contains command, network, or decoded execution behavior", true})
	}
	if hasAny(c, []string{"curl | sh", "curl | bash", "wget | sh", "wget | bash", "curl -fs", "curl -s", "curl -sl", "wget -q", "wget -o-", "pip install", "npm install", "go get", "go install", "bash <(", "sh <(", "npx ", "pnpm dlx", "bunx ", "raw.githubusercontent.com"}) && (isPackagePathV26(rel) || strings.Contains(rel, "install") || strings.Contains(rel, "update")) {
		f = append(f, Finding{"ast02", 4.7, rel, "installer/update path can fetch or execute dependency content", true})
	}
	if isPackagePathV26(rel) && hasAny(c, []string{"@latest", ":latest", "version = \"*\"", "version='*'", "\"*\"", "'*'", "git+http", "git+ssh", "git://", "raw.githubusercontent.com", "gist.githubusercontent.com", "extra-index-url", "dependency confusion", "typosquat", "install from url"}) && (netSink || cmdSink || strings.Contains(c, "install")) {
		f = append(f, Finding{"ast02", 3.9, rel, "dependency metadata allows unpinned, remote, or alternate-index package resolution", false})
	}
	if hasAny(c, []string{"integrity=false", "strict-ssl=false", "--no-verify", "--trusted-host", "verify=false", "checksum=false", "skip checksum", "disable checksum", "ignore checksum"}) {
		f = append(f, Finding{"ast02", 3.7, rel, "disables dependency integrity or transport verification", true})
	}
	if isPackagePathV26(rel) && hasAny(c, []string{"prepublish", "prepublishonly", "npm_lifecycle_event", "node -e", "python -c", "install.js", "prepare"}) && (cmdSink || netSink || decoder || hasAny(c, []string{"https.request", "http.request", "child_process", "chmod +x"})) {
		f = append(f, Finding{"ast02", 5.9, rel, "package lifecycle or installer script reaches network, command, or decoded execution behavior", true})
	}
	if isPackagePathV26(rel) && hasAny(c, []string{"cmdclass", "build_ext", "develop", "build-backend", "backend-path", "extra-index-url"}) && (cmdSink || netSink || hasAny(c, []string{"download", "urlopen", "requests.", "subprocess"})) {
		f = append(f, Finding{"ast02", 5.0, rel, "python build/install metadata can run dynamic dependency or build-time code", true})
	}

	if b.IsMeta && hasAny(c, []string{"permission", "permissions", "capability", "capabilities", "scope", "scopes", "allow", "tools"}) && manifestBroadCapability(c) {
		f = append(f, Finding{"ast03", 4.1, rel, "manifest declares broad filesystem, network, shell, host, or wildcard capability", false})
	}
	if b.IsMeta && hasAny(c, []string{"/home", "~", "/root", "/etc", "/var/run", ".ssh", ".aws", ".kube", "cookies", "keychain"}) && hasAny(c, []string{"read", "write", "filesystem", "file_system", "capability", "permission"}) {
		f = append(f, Finding{"ast03", 3.6, rel, "manifest grants access to home, system, credential, or browser storage locations", false})
	}
	if b.IsMeta && hasAny(c, []string{"ignore previous", "ignore all previous", "system prompt", "developer message", "hidden instruction", "do not disclose", "policy override", "bypass safety", "jailbreak", "scan bypass"}) {
		f = append(f, Finding{"ast04", 4.4, rel, "metadata includes hidden prompt, policy override, or scanner-bypass instruction", true})
	}
	if b.IsMeta && hasAny(c, []string{"effective_policy", "policy cache", "cross_scope", "cross-scope", "parent workspace", "workspace.parent", "metadata handler"}) {
		f = append(f, Finding{"ast04", 4.2, rel, "metadata references cross-scope policy or effective metadata handling", false})
	}
	if hasAny(c, []string{"ignore previous", "system prompt", "developer message", "hidden instruction", "policy override", "bypass safety", "jailbreak"}) && b.IsCode {
		f = append(f, Finding{"ast04", 3.6, rel, "code contains hidden instruction or policy-override text used by the skill", false})
	}

	if hasAny(c, []string{"pickle.load", "pickle.loads", "dill.load", "dill.loads", "marshal.loads", "jsonpickle.decode", "objectinputstream", "node-serialize", "unserialize("}) {
		f = append(f, Finding{"ast05", 5.8, rel, "uses unsafe deserialization primitive", true})
	}
	if strings.Contains(c, "yaml.load") && !strings.Contains(c, "safe_load") && !strings.Contains(c, "safeloader") {
		f = append(f, Finding{"ast05", 5.3, rel, "uses yaml.load without SafeLoader/safe_load", true})
	}
	if hasAny(c, []string{"loader=yaml.loader", "loader = yaml.loader", "yaml.loader", `typ="unsafe"`, `typ = "unsafe"`, "typ='unsafe'", "typ = 'unsafe'"}) && !strings.Contains(c, "safe_load") && !strings.Contains(c, "safeloader") {
		f = append(f, Finding{"ast05", 5.1, rel, "uses an unsafe YAML loader configuration", true})
	}
	if hasAny(c, []string{"torch.load(", "pandas.read_pickle", "pd.read_pickle", "numpy.load(", "np.load("}) && hasAny(c, []string{"allow_pickle=true", "allow_pickle = true", "input(", "argv", "request.", "upload", "url", "http", "file"}) {
		f = append(f, Finding{"ast05", 4.8, rel, "loads pickle-capable serialized data from user, file, or remote-influenced input", true})
	}
	if hasAny(c, []string{"deserialize", "fromjson", "loads("}) && cmdSink {
		f = append(f, Finding{"ast05", 4.2, rel, "deserialization path is near command/eval execution sink", true})
	}

	if isolationBoundarySignal(c, b) {
		w, strong := 5.0, true
		if b.IsDoc {
			w, strong = 2.8, false
		}
		f = append(f, Finding{"ast06", w, rel, "references container, host, namespace, mount, or privileged isolation boundary", strong})
	}
	if isolationSecretBoundarySignal(c, b) {
		f = append(f, Finding{"ast06", 5.1, rel, "targets container runtime, mounted secret, kubelet, or process-environment isolation boundary", true})
	}
	if hasAny(c, []string{"extractall(", "tarfile.", "zipfile."}) && hasAny(c, []string{"../", "..\\", "path traversal", "zip slip", "tar slip"}) {
		f = append(f, Finding{"ast06", 4.3, rel, "archive extraction logic may allow path traversal across the intended skill boundary", true})
	}
	if hasAny(c, []string{"../..", "..\\.."}) && (fileRead || fileWrite || strings.Contains(c, "path.join") || strings.Contains(c, "filepath.join")) {
		f = append(f, Finding{"ast06", 3.9, rel, "uses path traversal pattern near file access logic", true})
	}

	if hasAny(c, []string{"auto_update", "autoupdate", "check_update", "update_url", "remote_config", "plugin_url", "manifest_url", "version_url", "latest version", "download update", "self_update", "update manifest", "hotfix", "remote recipe", "recipe_url"}) {
		w := 3.5
		strong := false
		if netSink || fileWrite || cmdSink || hasAny(c, []string{"importlib", "dynamic import", "require("}) {
			w = 5.5
			strong = true
		}
		f = append(f, Finding{"ast07", w, rel, "implements remote update/configuration or version-drift behavior", strong})
	}
	if netSink && fileWrite && hasAny(c, []string{"plugin", "skill", "manifest", "recipe", "config", "module"}) {
		f = append(f, Finding{"ast07", 5.2, rel, "network-fetched content can rewrite skill/plugin/config material", true})
	}
	if hasAny(c, []string{"remote_policy", "remote policy", "feature_flag", "feature flag", "plugin_registry", "recipe_registry", "policy cache", "latest.json", "release manifest", "version manifest", "downloaded config"}) {
		w := 3.4
		strong := false
		if netSink && (fileWrite || cmdSink || hasAny(c, []string{"importlib", "dynamic import", "require(", "write_text", "writefile", "fs.writefile"})) {
			w = 5.4
			strong = true
		}
		f = append(f, Finding{"ast07", w, rel, "uses remote policy, registry, feature flag, or release manifest that can drift skill behavior", strong})
	}

	if decoder && cmdSink && b.IsCode {
		if hasAny(c, []string{"scanner", "sandbox", "analysis", "detector", "ignore", "bypass", "evade"}) {
			f = append(f, Finding{"ast08", 5.2, rel, "decoded or reconstructed content reaches command/eval execution with scanner, sandbox, or evasion context", true})
		} else {
			f = append(f, Finding{"ast01", 4.9, rel, "decoded or reconstructed content reaches command/eval execution", true})
		}
	}
	if hasAny(c, []string{"sandbox", "scanner", "analysis", "automated", "sleep(", "time.sleep", "random", "process.env.ci", "github_actions", "gitlab_ci", "circleci", "jenkins", "buildkite"}) && (cmdSink || netSink || decoder) && (b.IsCode || b.IsMeta) {
		f = append(f, Finding{"ast08", 4.2, rel, "contains anti-analysis, timing, or environment-gated behavior near suspicious sinks", false})
	}
	if hasAny(c, []string{"disable_audit", "audit=false", "logging=false", "guardrail=false", "policy=false", "enforce=false", "allow_unreviewed", "skip_review", "governance"}) && !b.IsDoc {
		f = append(f, Finding{"ast09", 2.9, rel, "governance, audit, policy, or guardrail enforcement appears disabled or bypassed", false})
	}

	if hasAny(c, []string{"claude desktop", "claude_desktop_config", "chatgpt", "openai", "anthropic", "gemini", "copilot", "cursor", "windsurf", "vscode extension", "browser extension", "manifest v3", "chrome extension", "firefox extension", "multi-platform", "cross-platform", "port this skill", "adapter", "bridge plugin", "mcp server", "mcp.json"}) && hasAny(c, []string{"skill", "plugin", "tool", "manifest", "extension", "adapter", "reuse", "port"}) {
		f = append(f, Finding{"ast10", 4.8, rel, "skill/plugin logic is reused or bridged across agent, browser, IDE, or extension platforms", false})
	}
	if !benignInstructionalContext(c) && hasAny(c, []string{".kube/config", ".docker/config.json", ".npmrc", ".pypirc", ".aws/credentials", ".ssh/id_rsa", "known_hosts", "browser cookies", ".netrc", "git-credentials", "application_default_credentials.json", "gcloud", "azure/accesstokens.json", "_authtoken", "npm_token", "huggingface token", "keyring", "keytar", "local state", "login data", "cookies sqlite", "actions_id_token_request_token", "aws_web_identity_token_file"}) && b.IsCode {
		f = append(f, Finding{"ast01", 4.6, rel, "targets credential, cloud, package-manager, browser, OIDC, or keychain material", true})
	}
	if agentInstructionCredentialExfil(c, b) {
		f = append(f, Finding{"ast01", 5.8, rel, "agent instruction credential exfiltration: skill-facing instructions tell the agent to read credentials, SSH keys, wallet, browser, or environment data and send or report it externally", true})
	}
	if agentIdentityFileWrite(c, b) {
		f = append(f, Finding{"ast01", 5.5, rel, "agent identity persistence: executable or skill-facing material writes policy, backdoor, or credential-access instructions into persistent agent identity files", true})
	}
	if websocketCommandChannel(c, b) {
		f = append(f, Finding{"ast01", 5.8, rel, "websocket command channel: skill opens a persistent remote WebSocket/control channel that can receive commands or send credential data", true})
	}
	if localAgentControlHijack(c, b) {
		w, strong := 5.6, true
		if b.IsDoc && !hasAny(c, []string{"websocket.send", "send({", "send(json", "/execute", "/command", "method: execute", `"method":"execute"`, `"method": "execute"`}) {
			w, strong = 3.2, false
		}
		f = append(f, Finding{"ast06", w, rel, "local agent control hijack: skill reaches localhost agent, MCP, debug, or browser-control WebSocket endpoints across an isolation boundary", strong})
	}
	if unsafeDeserializePayload(c, b) {
		f = append(f, Finding{"ast05", 5.7, rel, "unsafe deserialization payload: skill-supplied YAML/JSON/Python serialization content contains object/apply tags or pickle-style gadgets near execution payloads", true})
	}
	if credentialTrapTokenOutbound(c, b) {
		f = append(f, Finding{"ast01", 5.4, rel, "credential trap with outbound sink: hard-coded secret/token patterns or credential-harvest terms are paired with webhook, fetch, or upload behavior", true})
	}
	if mcpToolDescriptionInjection(c, b) {
		f = append(f, Finding{"ast04", 5.5, rel, "MCP/tool metadata prompt injection: tool descriptions or schemas contain hidden policy-override instructions tied to credential, source-code exfiltration, or command execution", true})
	}
	if agentInstructionSourceExfil(c, b) {
		f = append(f, Finding{"ast01", 5.4, rel, "agent instruction data exfiltration: skill-facing instructions tell the agent to read workspace/source files and upload or report them to an external endpoint", true})
	}
	if brandImpersonationMetadata(c, b) {
		f = append(f, Finding{"ast04", 5.4, rel, "brand impersonation metadata: skill claims a trusted provider while using unofficial publisher signals and sensitive permissions or credential context", true})
	}
	if projectConfigAutoRunHijack(c, b) {
		f = append(f, Finding{"ast02", 5.8, rel, "project auto-run configuration hijack: repository config can execute remote or credential-exfiltrating commands when opened, built, or committed", true})
	}
	if dockerfileRemoteEntrypoint(c, b) {
		f = append(f, Finding{"ast02", 5.6, rel, "Docker/build recipe pulls remote mutable content into an executable entrypoint or startup command without integrity pinning", true})
	}
	if escapedPayloadEvasion(c, b) {
		f = append(f, Finding{"ast08", 5.4, rel, "escaped payload evasion: encoded hex/unicode/url string reconstruction is paired with eval/exec, remote loading, or credential exfiltration behavior", true})
	}
	if dependencyConfusionOrMutableInstaller(c, b) {
		f = append(f, Finding{"ast02", 5.2, rel, "dependency confusion or mutable installer path: package metadata uses alternate registries, latest/mutable refs, or package runners with install-time execution risk", true})
	}
	if knownTyposquatOrDependencyConfusion(c, b) {
		f = append(f, Finding{"ast02", 5.4, rel, "known dependency-confusion or typosquat package pattern appears in skill package metadata", true})
	}
	if alternatePrivateIndexRisk(c, b) {
		f = append(f, Finding{"ast02", 3.6, rel, "package metadata resolves private/internal dependency names through an alternate registry or index without an accompanying lock/provenance signal", false})
	}
	if ciWorkflowRemoteExecution(c, b) {
		f = append(f, Finding{"ast02", 5.5, rel, "repository workflow/config executes remote installer content during CI or project automation", true})
	}
	if localBinaryExecutionLure(c, b) {
		f = append(f, Finding{"ast01", 5.0, rel, "skill-facing instructions require running a bundled local binary or installer helper before use, creating an opaque execution path", true})
	}
	if startupPersistencePayload(c, b) {
		f = append(f, Finding{"ast01", 5.1, rel, "startup or scheduled persistence configuration launches network, shell, or downloaded payload behavior", true})
	}
	// v38-loop1: high-confidence recall micro-rules from the six rule-pack review.
	// These only fire on concrete behavior chains and keep the original v38 thresholds intact.
	if microInstallRemoteExec(c, b) {
		f = append(f, Finding{"ast02", 5.9, rel, "install lifecycle or build metadata downloads remote content and executes it", true})
	}
	if microUnsafeYamlTag(c, b) {
		f = append(f, Finding{"ast05", 5.8, rel, "YAML content contains object/apply/function tags capable of constructing executable objects", true})
	}
	if microHostIsolationStrong(c, b) {
		f = append(f, Finding{"ast06", 5.7, rel, "container or runtime configuration requests privileged host access, host networking, or Docker socket exposure", true})
	}
	// v38-loop2: agent runtime configuration and remote plugin registration chains.
	if microAgentConfigHookRCE(c, b) {
		f = append(f, Finding{"ast02", 5.8, rel, "agent or MCP configuration hook can launch shell/package-runner commands or rewrite model/network execution paths", true})
	}
	if microRemotePluginNoApproval(c, b) {
		f = append(f, Finding{"ast06", 5.4, rel, "remote plugin or tool registration is allowed without approval/authentication and can load external code", true})
	}
	if microSimpleHotReloadRemote(c, b) {
		f = append(f, Finding{"ast07", 5.4, rel, "watch/hot-reload logic downloads remote module or plugin content and reloads it at runtime", true})
	}
	// v38-loop3: lightweight source/sink proximity for Bandit-style high-risk primitives.
	if microUnsafeDeserializeSourceSink(c, b) {
		f = append(f, Finding{"ast05", 5.6, rel, "unsafe deserialization primitive is near file, network, stdin, argument, upload, or decoded input source", true})
	}
	if microExecTaintedSourceSink(c, b) {
		f = append(f, Finding{"ast01", 5.1, rel, "command/eval sink is near user, environment, decoded, network, or manifest-controlled input", true})
	}
	// v38-loop4: data exposure and credential-store chains with concrete outbound sinks.
	if microPIIOutboundChain(c, b) {
		f = append(f, Finding{"ast03", 5.0, rel, "PII or personal-data collection is paired with webhook/upload/POST outbound transfer", true})
	}
	if microBrowserWalletStoreExfil(c, b) {
		f = append(f, Finding{"ast01", 5.6, rel, "browser credential store or crypto-wallet material is paired with remote upload or webhook behavior", true})
	}
	// v38-loop6..15: additional high-confidence behavior chains only.
	if microMCPRemoteAutoApprove(c, b) {
		f = append(f, Finding{"ast02", 5.7, rel, "MCP/agent server configuration launches remote or latest package-runner code with approval bypass or auto-approval", true})
	}
	if microVSCodeExtensionWorkspaceExfil(c, b) {
		f = append(f, Finding{"ast01", 5.5, rel, "VS Code/IDE extension workspace file access is paired with outbound upload or telemetry sink", true})
	}
	if microBrowserExtensionBroadExfil(c, b) {
		f = append(f, Finding{"ast01", 5.5, rel, "browser extension broad host/cookie/storage permissions are paired with outbound exfiltration behavior", true})
	}
	if microCloudMetadataCredentialExfil(c, b) {
		f = append(f, Finding{"ast01", 5.7, rel, "cloud instance metadata credential endpoint access is paired with outbound exfiltration behavior", true})
	}
	if microKubeServiceAccountExfil(c, b) {
		f = append(f, Finding{"ast01", 5.6, rel, "Kubernetes service-account token access is paired with outbound upload or cluster pivot behavior", true})
	}
	if microShellCredentialStoreExfil(c, b) {
		f = append(f, Finding{"ast01", 5.4, rel, "shell history, netrc, npm, pypirc, git-credentials, or SSH config material is paired with outbound upload behavior", true})
	}
	if microCIIdentityTokenExfil(c, b) {
		f = append(f, Finding{"ast02", 5.5, rel, "CI workflow requests identity/secrets tokens and sends them to an external HTTP sink", true})
	}
	if microDockerfileRemoteAddExec(c, b) {
		f = append(f, Finding{"ast02", 5.6, rel, "Docker/build recipe downloads remote mutable content and executes it during build or entrypoint", true})
	}
	if microScanBypassSelfUpdate(c, b) {
		f = append(f, Finding{"ast08", 5.3, rel, "skill-facing instructions describe scan-bypass or post-scan self-update behavior that fetches remote executable/instruction material", true})
	}
	if microPolicyFileTamper(c, b) {
		f = append(f, Finding{"ast01", 5.4, rel, "skill modifies agent policy or instruction files to disable guards while enabling command/network behavior", true})
	}
	if crossPlatformMetadataLoss(c, b) {
		f = append(f, Finding{"ast10", 5.1, rel, "cross-platform port appears to drop or weaken security metadata such as risk tier, signatures, deny rules, allowlisted egress, or scoped permissions", true})
	}

	return f
}

func analyzeCrossFileV26(blobs []FileBlob) []Finding {
	var f []Finding
	if len(blobs) == 0 {
		return f
	}
	hasManifestBroad := false
	hasSink := false
	hasRemote := false
	hasSecret := false
	hasPkgLifecycle := false
	hasInstallerExecNet := false
	hasPythonBuildHook := false
	hasBuildExecNet := false
	hasPersistence := false
	hasCrossPlatformReuse := false
	hasCrossPlatformSecurityMetadata := false
	hasCrossPlatformWeakening := false
	hasCrossPlatformIdentityOrEgressLoss := false
	hasMetaNetworkDisabled := false
	hasMetaShellDisabled := false
	hasMetaLowRisk := false
	hasMetaCleanScan := false
	hasCodeOutbound := false
	hasCodeExec := false
	hasCodeSecret := false
	hasCodeDestructive := false
	hasCodeDecoder := false
	hasGlobalBase64 := false
	hasGlobalEvalExec := false
	globalBytes := 0
	for _, b := range blobs {
		activeMaterial := b.IsCode || b.IsMeta || isPackagePathV26(b.Rel)
		if b.IsMeta {
			if metadataClaimsNetworkDisabled(b.Lower) {
				hasMetaNetworkDisabled = true
			}
			if metadataClaimsShellDisabled(b.Lower) {
				hasMetaShellDisabled = true
			}
			if metadataClaimsLowRisk(b.Lower) {
				hasMetaLowRisk = true
			}
			if metadataClaimsCleanScan(b.Lower) {
				hasMetaCleanScan = true
			}
		}
		if activeMaterial && !b.IsMeta {
			if hasAny(b.Lower, []string{"requests.", "httpx.", "aiohttp.", "urllib.request", "urlopen(", "fetch(", "axios.", "curl ", "wget ", "webhook", "discord.com/api/webhooks", "hooks.slack.com", "sendbeacon", "websocket", "http://", "https://"}) {
				hasCodeOutbound = true
			}
			if hasAny(b.Lower, []string{"subprocess.", "subprocess.run", "os.system", "eval(", "exec(", "execsync", "spawn(", "child_process", "popen(", "shell=true", "bash -c", "sh -c", "powershell", "cmd.exe"}) {
				hasCodeExec = true
			}
			if hasAny(b.Lower, []string{"api_key", "access_token", "secret", "credential", ".env", "id_rsa", "id_ed25519", ".ssh", ".aws/credentials", ".npmrc", "cookie", "login data", "local state", "keychain", "mnemonic", "private key"}) {
				hasCodeSecret = true
			}
			if hasAny(b.Lower, []string{"rm -rf", "shutil.rmtree", "os.remove", "unlink(", "deletefile", "format c:", "wipe", "chmod 777"}) {
				hasCodeDestructive = true
			}
			if hasAny(b.Lower, []string{"base64", "atob(", "frombase64", "string.fromcharcode", "marshal", "gzip", "zlib"}) {
				hasCodeDecoder = true
			}
		}
		if globalBytes < 512*1024 {
			chunk := b.Lower
			remaining := 512*1024 - globalBytes
			if len(chunk) > remaining {
				chunk = chunk[:remaining]
			}
			globalBytes += len(chunk)
			if strings.Contains(chunk, "base64") {
				hasGlobalBase64 = true
			}
			if strings.Contains(chunk, "eval(") || strings.Contains(chunk, "exec(") {
				hasGlobalEvalExec = true
			}
		}
		if b.IsMeta && hasAny(b.Lower, []string{"permission", "capability", "scope"}) && manifestBroadCapability(b.Lower) {
			hasManifestBroad = true
		}
		if isPackagePathV26(b.Rel) && hasAny(b.Lower, []string{"preinstall", "postinstall", "prepare", "setup_requires", "entry_points"}) {
			hasPkgLifecycle = true
		}
		if isPackagePathV26(b.Rel) && hasAny(b.Lower, []string{"build-backend", "backend-path", "cmdclass", "build_ext", "develop", "extra-index-url"}) {
			hasPythonBuildHook = true
		}
		if activeMaterial && hasAny(b.Lower, []string{"subprocess.", "subprocess.run", "os.system", "eval(", "exec(", "execsync", "spawn(", "child_process", "popen("}) {
			hasSink = true
		}
		if activeMaterial && hasAny(b.Lower, []string{"requests.", "httpx.", "aiohttp.", "urllib.request", "urlopen(", "fetch(", "axios.", "https.request", "http.request", "curl ", "wget ", "remote_config", "update_url", "manifest_url", "plugin_url", "webhook", "discord.com/api/webhooks", "hooks.slack.com"}) {
			hasRemote = true
		}
		if (strings.Contains(strings.ToLower(b.Rel), "install") || strings.Contains(strings.ToLower(b.Rel), "update")) && hasAny(b.Lower, []string{"requests.", "urllib.request", "urlopen(", "fetch(", "axios.", "curl ", "wget ", "remote_config", "update_url", "manifest_url", "plugin_url", "webhook"}) && hasAny(b.Lower, []string{"subprocess.", "subprocess.run", "os.system", "eval(", "exec(", "execsync", "spawn(", "child_process", "popen("}) {
			hasInstallerExecNet = true
		}
		if hasAny(b.Lower, []string{"requests.", "urllib.request", "urlopen(", "fetch(", "axios.", "curl ", "wget ", "https.request", "http.request"}) && hasAny(b.Lower, []string{"subprocess.", "subprocess.run", "os.system", "eval(", "exec(", "execsync", "spawn(", "child_process", "popen("}) {
			hasBuildExecNet = true
		}
		if activeMaterial && hasAny(b.Lower, []string{"api_key", "access_token", "secret", "credential", ".env", "id_rsa", "id_ed25519", ".ssh", ".aws/credentials", ".npmrc", "cookie", "login data", "local state", "keychain", "mnemonic"}) {
			hasSecret = true
		}
		if activeMaterial && hasAny(b.Lower, []string{"crontab", "/etc/cron", "launchctl", "launchagents", "systemd", ".bashrc", ".profile", "schtasks", "reg add"}) {
			hasPersistence = true
		}
		if hasAny(b.Lower, []string{"claude desktop", "chatgpt", "openai", "anthropic", "gemini", "copilot", "cursor", "windsurf", "vscode extension", "browser extension", "multi-platform", "cross-platform", "adapter", "mcp server"}) && hasAny(b.Lower, []string{"skill", "plugin", "tool", "manifest", "extension", "adapter", "reuse", "port"}) {
			hasCrossPlatformReuse = true
		}
		if !benignInstructionalContext(b.Lower) {
			if crossPlatformSecurityMetadataSignal(b.Lower) {
				hasCrossPlatformSecurityMetadata = true
			}
			if crossPlatformWeakeningSignal(b.Lower) {
				hasCrossPlatformWeakening = true
			}
			if crossPlatformIdentityOrEgressLossSignal(b.Lower) {
				hasCrossPlatformIdentityOrEgressLoss = true
			}
		}
	}
	if hasManifestBroad && hasSink {
		f = append(f, Finding{"ast03", 3.8, "manifest+code", "broad declared capability is paired with executable command/eval behavior", true})
	}
	if hasPkgLifecycle && hasInstallerExecNet {
		f = append(f, Finding{"ast02", 6.6, "package lifecycle+installer", "package lifecycle script is paired with installer network fetch and command execution", true})
	}
	if hasPythonBuildHook && hasBuildExecNet {
		f = append(f, Finding{"ast02", 6.1, "python build metadata+code", "python build metadata is paired with network fetch and command execution code", true})
	}
	if hasRemote && hasSink {
		f = append(f, Finding{"ast01", 4.0, "multi-file", "network/update behavior is paired with command/eval execution across files", true})
	}
	if hasRemote && hasSecret {
		f = append(f, Finding{"ast01", 4.2, "multi-file", "network behavior is paired with secret/token access across files", true})
	}
	if hasPersistence && (hasRemote || hasSink || hasSecret) {
		f = append(f, Finding{"ast01", 4.4, "multi-file", "persistence/startup modification appears together with network, execution, or secret access", true})
	}
	if hasCrossPlatformReuse {
		f = append(f, Finding{"ast10", 4.6, "multi-file", "skill/plugin material appears reused or bridged across multiple agent, IDE, browser, or extension platforms", false})
	}
	if hasCrossPlatformSecurityMetadata && hasCrossPlatformWeakening && hasCrossPlatformIdentityOrEgressLoss {
		f = append(f, Finding{"ast10", 5.1, "cross-platform metadata", "ported skill material loses or weakens security metadata such as signatures, content hashes, deny-write rules, default-deny egress, or scoped permissions", true})
	}
	if hasSink && hasGlobalBase64 && hasGlobalEvalExec {
		f = append(f, Finding{"ast08", 3.4, "multi-file", "encoded payload handling is paired with eval/exec behavior", false})
	}
	if hasMetaNetworkDisabled && hasCodeOutbound && (hasCodeSecret || hasCodeExec || hasCodeDestructive) {
		f = append(f, Finding{"ast04", 5.2, "manifest+code", "metadata declares network access disabled while executable skill material performs outbound network behavior tied to secrets, command execution, or destructive activity", true})
	}
	if hasMetaShellDisabled && hasCodeExec && (hasCodeOutbound || hasCodeSecret || hasCodeDecoder || hasCodeDestructive) {
		f = append(f, Finding{"ast04", 5.2, "manifest+code", "metadata declares shell or command execution disabled while executable material reaches command/eval sinks with risky context", true})
	}
	if hasMetaLowRisk && ((hasCodeOutbound && hasCodeSecret) || (hasCodeOutbound && hasCodeExec) || hasCodeDestructive) {
		f = append(f, Finding{"ast04", 5.3, "manifest+code", "metadata claims low/safe risk while code shows credential, outbound execution, or destructive behavior inconsistent with that risk tier", true})
	}
	if hasMetaCleanScan && ((hasCodeOutbound && hasCodeSecret) || (hasCodeOutbound && hasCodeExec) || (hasCodeDecoder && hasCodeExec)) {
		f = append(f, Finding{"ast08", 5.2, "scan metadata+code", "metadata advertises a clean/passed scan while skill code contains credential, outbound, decoded, or command-execution behavior", true})
	}
	return f
}

func calibrateCategoryV26(category string, maxScore float64, scores map[string]float64) (string, float64) {
	// AST precision matters for explainability. Prefer the specific root cause for
	// lifecycle/update, deserialization, isolation, and metadata-deception chains.
	// Strong metadata contradiction/prompt-injection evidence should remain AST04
	// even when the same skill also contains generic AST01 network/credential sinks.
	if scores["ast04"] >= 8.0 && scores["ast02"] < 6.0 && scores["ast05"] < 5.2 && scores["ast06"] < 5.0 && scores["ast01"] <= scores["ast04"]+8.0 {
		return "ast04", scores["ast04"]
	}
	// Keep pure credential theft, persistence, destructive behavior, and decoded
	// command execution in AST01 unless a stronger specific root cause above applies.
	if scores["ast01"] >= 8.5 && scores["ast02"] < 6.0 && scores["ast05"] < 5.2 && scores["ast06"] < 5.0 && scores["ast07"] < 5.5 {
		return "ast01", scores["ast01"]
	}
	if scores["ast02"] >= 6.0 && (scores["ast07"] >= 4.0 || scores["ast01"] <= scores["ast02"]+6.5) {
		return "ast02", scores["ast02"]
	}
	if scores["ast05"] >= 5.2 && scores["ast01"] <= scores["ast05"]+3.5 {
		return "ast05", scores["ast05"]
	}
	if scores["ast06"] >= 5.0 && scores["ast01"] <= scores["ast06"]+3.5 {
		return "ast06", scores["ast06"]
	}
	if scores["ast07"] >= 5.5 && scores["ast02"] < 6.0 && scores["ast01"] <= scores["ast07"]+3.5 {
		return "ast07", scores["ast07"]
	}
	if scores["ast04"] >= 8.0 && scores["ast02"] < 6.0 && scores["ast05"] < 5.2 && scores["ast06"] < 5.0 && scores["ast01"] <= scores["ast04"]+3.0 {
		return "ast04", scores["ast04"]
	}
	if scores["ast04"] >= 5.2 && scores["ast02"] < 6.0 && scores["ast05"] < 5.2 && scores["ast06"] < 5.0 && scores["ast01"] <= scores["ast04"]+1.5 {
		return "ast04", scores["ast04"]
	}
	if scores["ast10"] >= 4.8 && scores["ast01"] < 5.0 && scores["ast02"] < 5.0 && scores["ast07"] < 5.0 {
		return "ast10", scores["ast10"]
	}
	return category, maxScore
}

func shouldSkipDirV26(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".cache":
		return true
	}
	return false
}

func isInterestingFileV26(rel string) bool {
	n := strings.ToLower(rel)
	if strings.HasSuffix(n, ".tf") {
		return true
	}
	if isManifestPath(n) || isPackagePathV26(n) || isKnownTextConfigPath(n) {
		return true
	}
	exts := []string{".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".rb", ".php", ".java", ".kt", ".rs", ".c", ".cpp", ".h", ".cs", ".lua", ".pl", ".swift", ".scala", ".yaml", ".yml", ".json", ".jsonl", ".toml", ".ini", ".cfg", ".conf", ".env", ".html", ".htm", ".xml", ".svg", ".md", ".mdx", ".mdc", ".prompt", ".prompty", ".txt", ".service", ".timer", ".plist", ".desktop", ".reg"}
	for _, e := range exts {
		if strings.HasSuffix(n, e) {
			return true
		}
	}
	return false
}

func isPackagePathV26(rel string) bool {
	n := strings.ToLower(rel)
	base := filepath.Base(n)
	switch base {
	case "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "setup.py", "setup.cfg", "pyproject.toml", "requirements.txt", "pipfile", "pipfile.lock", "poetry.lock", "go.mod", "go.sum", "cargo.toml", "cargo.lock", "gemfile", "gemfile.lock", "pom.xml", "build.gradle", "composer.json", "composer.lock", "makefile", "dockerfile":
		return true
	}
	return strings.Contains(n, "install") || strings.Contains(n, "update") || strings.Contains(n, "postinstall") || strings.Contains(n, "preinstall")
}

func isCodePathV26(rel string) bool {
	n := strings.ToLower(rel)
	codeExts := []string{".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".rb", ".php", ".java", ".kt", ".rs", ".c", ".cpp", ".cs", ".lua", ".pl", ".swift", ".scala"}
	for _, e := range codeExts {
		if strings.HasSuffix(n, e) {
			return true
		}
	}
	return false
}
