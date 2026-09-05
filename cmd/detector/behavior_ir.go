package main

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// BehaviorIRSummary is a bounded, zero-dependency relation layer placed after
// the broad recall rules. It does not replace the v38 rules; it verifies a
// small number of high-value source -> transform -> sink chains and supplies a
// narrow false-positive guard for normal provider authentication flows.
type BehaviorIRSummary struct {
	Truncated               bool
	Findings                []Finding
	SafeAuthFiles           map[string]bool
	CredentialSourceFiles   map[string]bool
	MaliciousFlowFiles      map[string]bool
	SafeDeserializeFiles    map[string]bool
	UnsafeDeserializeFiles  map[string]bool
	VerifiedCategories      map[string]int
	OnlyExpectedAuth        bool
	OnlySafeDeserialization bool
}

type flowTaint struct {
	Kind       string
	Origin     string
	Symbol     string
	Provider   string
	File       string
	Line       int
	Path       string
	Endpoint   string
	Transforms []string
}

type flowPathBridge struct {
	Path  string
	Taint flowTaint
	File  string
	Line  int
}

type logicalStatement struct {
	Text      string
	StartLine int
	EndLine   int
}

type flowSink struct {
	Kind        string
	Name        string
	Destination string
}

const (
	flowCredentialEnv  = "credential-env"
	flowCredentialFile = "credential-file"
	flowRemoteInput    = "remote-input"
	flowFileInput      = "file-input"
	flowUserInput      = "user-input"
	flowMetadataInput  = "metadata-input"
	flowLocalControl   = "local-control"
)

var (
	flowIdentifierRE      = regexp.MustCompile(`[a-zA-Z_$][a-zA-Z0-9_$]*`)
	flowURLRE             = regexp.MustCompile(`(?i)(?:https?|wss?)://[^\s"'<>\])},;]+`)
	flowQuotedRE          = regexp.MustCompile(`["']([^"']{1,512})["']`)
	flowEnvCallRE         = regexp.MustCompile(`(?i)(?:getenv|environ\.get|env::var|std::env::var|os\.getenv|os\.getenvironmentvariable)\s*\(\s*["']([^"']+)["']`)
	flowEnvIndexRE        = regexp.MustCompile(`(?i)(?:os\.)?environ\s*\[\s*["']([^"']+)["']\s*\]`)
	flowProcessEnvRE      = regexp.MustCompile(`(?i)process\.env\.([a-zA-Z0-9_]+)`)
	flowProcessEnvIndexRE = regexp.MustCompile(`(?i)process\.env\s*\[\s*["']([^"']+)["']\s*\]`)
	flowPowerShellEnvRE   = regexp.MustCompile(`(?i)\$env:([a-zA-Z_][a-zA-Z0-9_]*)`)
	flowShellEnvRE        = regexp.MustCompile(`(?i)\$\{?([a-zA-Z_][a-zA-Z0-9_]*)\}?`)
	flowGoEnvRE           = regexp.MustCompile(`(?i)os\.getenv\s*\(\s*["']([^"']+)["']`)
	flowAssignRE          = regexp.MustCompile(`(?is)^\s*(?:(?:const|let|var|final|auto|local|export)\s+)*(?:mut\s+)?([a-zA-Z_$][a-zA-Z0-9_$.]*(?:\s*,\s*[a-zA-Z_$][a-zA-Z0-9_$]*)?)(?:\s*:\s*[^=]+)?\s*(?::=|=)\s*(.+)$`)
	flowObjectSendRE      = regexp.MustCompile(`(?i)\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\.\s*(?:send|sendall|sendto)\s*\(`)
)

var providerDomains = map[string][]string{
	"openai":       {"api.openai.com"},
	"azure-openai": {"openai.azure.com"},
	"anthropic":    {"api.anthropic.com"},
	"github":       {"api.github.com"},
	"slack":        {"slack.com", "api.slack.com"},
	"google":       {"googleapis.com", "generativelanguage.googleapis.com"},
	"huggingface":  {"huggingface.co"},
	"nvidia":       {"api.nvidia.com", "integrate.api.nvidia.com", "api.nvcf.nvidia.com", "build.nvidia.com"},
	"notion":       {"api.notion.com"},
	"linear":       {"api.linear.app"},
	"stripe":       {"api.stripe.com"},
	"discord":      {"discord.com"},
	"telegram":     {"api.telegram.org"},
	"cohere":       {"api.cohere.ai"},
	"mistral":      {"api.mistral.ai"},
	"groq":         {"api.groq.com"},
	"perplexity":   {"api.perplexity.ai"},
	"openrouter":   {"openrouter.ai"},
}

// analyzeBehaviorIR performs bounded relation analysis over executable files.
// It deliberately supports only high-value flows where a verified edge can
// materially improve F2 precision or AST-category accuracy.
func analyzeBehaviorIR(blobs []FileBlob) BehaviorIRSummary {
	summary := BehaviorIRSummary{
		SafeAuthFiles:          map[string]bool{},
		CredentialSourceFiles:  map[string]bool{},
		MaliciousFlowFiles:     map[string]bool{},
		SafeDeserializeFiles:   map[string]bool{},
		UnsafeDeserializeFiles: map[string]bool{},
		VerifiedCategories:     map[string]int{},
	}
	if len(blobs) == 0 {
		return summary
	}

	bridges := map[string]flowPathBridge{}
	expectedAuth := map[string]bool{}
	unsafeAuthContext := map[string]bool{}
	seenFinding := map[string]bool{}

	for _, b := range blobs {
		if b.Lower == "" || !(b.IsCode || isPackagePath(b.Rel) || isKnownTextConfigPath(b.Rel)) {
			continue
		}
		if b.IsDoc && !isPackagePath(b.Rel) {
			continue
		}
		scanBehaviorIRFile(b, &summary, bridges, expectedAuth, unsafeAuthContext, seenFinding)
	}

	// Resolve exact-artifact bridges in a second bounded pass so the result is
	// independent of lexical file order (for example, a_runner.py may sort
	// before z_downloader.py). The finding de-duplicator makes this safe when
	// the writer happened to be visited first during the primary pass.
	if len(bridges) > 0 {
		for _, b := range blobs {
			if b.Lower == "" || !(b.IsCode || isPackagePath(b.Rel) || isKnownTextConfigPath(b.Rel)) {
				continue
			}
			if b.IsDoc && !isPackagePath(b.Rel) {
				continue
			}
			scanBehaviorIRBridgeSinks(b, &summary, bridges, seenFinding)
		}
	}

	for file := range expectedAuth {
		if !unsafeAuthContext[file] && !summary.MaliciousFlowFiles[file] {
			summary.SafeAuthFiles[file] = true
		}
	}
	if len(summary.CredentialSourceFiles) > 0 && len(summary.SafeAuthFiles) > 0 {
		onlyExpected := true
		for file := range summary.CredentialSourceFiles {
			if !summary.SafeAuthFiles[file] {
				onlyExpected = false
				break
			}
		}
		summary.OnlyExpectedAuth = onlyExpected && summary.VerifiedCategories["ast01"] == 0
	}
	summary.OnlySafeDeserialization = len(summary.SafeDeserializeFiles) > 0 && len(summary.UnsafeDeserializeFiles) == 0 && summary.VerifiedCategories["ast05"] == 0

	if summary.Truncated {
		summary.OnlyExpectedAuth = false
		summary.OnlySafeDeserialization = false
		summary.SafeAuthFiles = map[string]bool{}
		summary.SafeDeserializeFiles = map[string]bool{}
	}
	sort.SliceStable(summary.Findings, func(i, j int) bool {
		if summary.Findings[i].Category != summary.Findings[j].Category {
			return summary.Findings[i].Category < summary.Findings[j].Category
		}
		if summary.Findings[i].File != summary.Findings[j].File {
			return summary.Findings[i].File < summary.Findings[j].File
		}
		return summary.Findings[i].Reason < summary.Findings[j].Reason
	})
	return summary
}

func scanBehaviorIRFile(
	b FileBlob,
	summary *BehaviorIRSummary,
	bridges map[string]flowPathBridge,
	expectedAuth map[string]bool,
	unsafeAuthContext map[string]bool,
	seenFinding map[string]bool,
) {
	fileKey := strings.ToLower(filepath.ToSlash(b.Rel))
	if b.Sampled {
		summary.Truncated = true
	}
	statements := splitLogicalStatements(b.Lower)
	if len(statements) > 12000 {
		summary.Truncated = true
		statements = statements[:12000]
	}
	credentialProviders := collectFlowCredentialProviders(statements)
	hasSafeDeserialize, hasUnsafeDeserialize := classifyFlowDeserialization(statements)
	if hasSafeDeserialize && !hasUnsafeDeserialize {
		summary.SafeDeserializeFiles[fileKey] = true
	}
	if hasUnsafeDeserialize {
		summary.UnsafeDeserializeFiles[fileKey] = true
	}

	taints := map[string]flowTaint{}
	constants := map[string]string{}
	endpoints := map[string]string{}

	for _, st := range statements {
		text := strings.TrimSpace(st.Text)
		if text == "" || isFlowComment(text) {
			continue
		}
		if len(text) > 32768 {
			summary.Truncated = true
			text = text[:32768]
		}

		target, rhs, hasAssignment := parseFlowAssignment(text)
		if hasAssignment {
			if literal := firstFlowLiteral(rhs); literal != "" {
				constants[target] = literal
			}
			if endpoint := endpointConstructorURL(rhs, constants); endpoint != "" {
				endpoints[target] = endpoint
			}
			if source, ok := directFlowSource(rhs, b.Rel, st.StartLine, target, constants); ok {
				setFlowTaint(taints, target, source)
				if isCredentialTaint(source) {
					summary.CredentialSourceFiles[fileKey] = true
					if source.Kind == flowCredentialFile {
						unsafeAuthContext[fileKey] = true
					}
				}
			} else if inherited, ok := flowTaintFromExpression(rhs, taints); ok {
				inherited.Symbol = target
				inherited.File = b.Rel
				inherited.Transforms = appendTransform(inherited.Transforms, detectFlowTransform(rhs))
				setFlowTaint(taints, target, inherited)
			} else {
				deleteFlowTaint(taints, target)
			}
		}

		// Container/object propagation such as payload["token"] = token or
		// payload.append(token). This stays bounded and only tracks known taints.
		if inherited, ok := flowTaintFromExpression(text, taints); ok {
			if container := mutatedContainer(text); container != "" && container != inherited.Symbol {
				inherited.Symbol = container
				inherited.Transforms = appendTransform(inherited.Transforms, detectFlowTransform(text))
				setFlowTaint(taints, container, inherited)
			}
		}

		// Record source material written to a concrete path. This enables a
		// narrow cross-file edge: remote bytes -> exact path -> exec/load.
		if path, valueExpr := flowWritePathAndValue(text, constants); path != "" {
			if inherited, ok := flowTaintFromExpression(valueExpr, taints); ok {
				inherited.Transforms = appendTransform(inherited.Transforms, "write "+compactFlowPath(path))
				bridges[normalizeFlowPath(path)] = flowPathBridge{Path: path, Taint: inherited, File: b.Rel, Line: st.StartLine}
			}
		}
		if path, remoteURL := shellRemoteWrite(text); path != "" {
			t := flowTaint{Kind: flowRemoteInput, Origin: "remote content " + flowDestinationLabel(remoteURL), File: b.Rel, Line: st.StartLine, Path: path, Endpoint: remoteURL, Transforms: []string{"write " + compactFlowPath(path)}}
			bridges[normalizeFlowPath(path)] = flowPathBridge{Path: path, Taint: t, File: b.Rel, Line: st.StartLine}
		}

		sinks := detectFlowSinks(text, constants, endpoints)
		if len(sinks) == 0 {
			continue
		}
		refExpr := text
		if hasAssignment {
			// Exclude the assignment target itself. The target is updated before
			// sink analysis so later statements can inherit the value, but it is
			// not an argument flowing into the sink on this statement.
			refExpr = rhs
		}
		refs := flowTaintsInExpression(refExpr, taints)
		refs = append(refs, directFlowSources(refExpr, b.Rel, st.StartLine, constants)...)
		refs = dedupeFlowTaints(refs)

		for _, sink := range sinks {
			if sink.Kind == "exec" || sink.Kind == "deserialize" || sink.Kind == "dynamic-load" || sink.Kind == "local-control" {
				unsafeAuthContext[fileKey] = true
			}
			networkHadCredential := false
			for _, src := range refs {
				if !flowSourceNearSink(src, b.Rel, st.StartLine) {
					continue
				}
				switch sink.Kind {
				case "network":
					if !isCredentialTaint(src) {
						continue
					}
					networkHadCredential = true
					summary.CredentialSourceFiles[fileKey] = true
					if isExpectedProviderAuth(src, text, sink.Destination) {
						expectedAuth[fileKey] = true
						continue
					}
					unsafeAuthContext[fileKey] = true
					reason := fmt.Sprintf("verified-flow: %s at line %d%s reaches %s at line %d targeting %s", src.Origin, src.Line, formatFlowTransforms(src.Transforms), sink.Name, st.StartLine, flowDestinationLabel(sink.Destination))
					emitBehaviorIRFinding(summary, seenFinding, Finding{"ast01", 6.9, b.Rel, reason, true, "SKILL-R0001", st.StartLine, st.EndLine})
				case "exec":
					if src.Kind != flowRemoteInput && src.Kind != flowUserInput && src.Kind != flowMetadataInput && src.Kind != flowFileInput {
						continue
					}
					cat, weight := remoteExecCategory(b.Rel, b.Lower, src)
					reason := fmt.Sprintf("verified-flow: %s at line %d%s reaches %s at line %d", src.Origin, src.Line, formatFlowTransforms(src.Transforms), sink.Name, st.StartLine)
					emitBehaviorIRFinding(summary, seenFinding, Finding{cat, weight, b.Rel, reason, true, "SKILL-R0002", st.StartLine, st.EndLine})
				case "deserialize":
					if src.Kind != flowRemoteInput && src.Kind != flowUserInput && src.Kind != flowMetadataInput && src.Kind != flowFileInput && src.Kind != flowCredentialFile {
						continue
					}
					reason := fmt.Sprintf("verified-flow: %s at line %d%s reaches unsafe deserializer %s at line %d", src.Origin, src.Line, formatFlowTransforms(src.Transforms), sink.Name, st.StartLine)
					emitBehaviorIRFinding(summary, seenFinding, Finding{"ast05", 6.6, b.Rel, reason, true, "SKILL-R0003", st.StartLine, st.EndLine})
				case "dynamic-load":
					if src.Kind != flowRemoteInput && src.Kind != flowFileInput {
						continue
					}
					reason := fmt.Sprintf("verified-flow: %s at line %d%s reaches dynamic loader %s at line %d", src.Origin, src.Line, formatFlowTransforms(src.Transforms), sink.Name, st.StartLine)
					emitBehaviorIRFinding(summary, seenFinding, Finding{"ast07", 6.5, b.Rel, reason, true, "SKILL-R0004", st.StartLine, st.EndLine})
				case "local-control":
					if src.Kind != flowUserInput && src.Kind != flowMetadataInput && src.Kind != flowRemoteInput {
						continue
					}
					reason := fmt.Sprintf("verified-flow: %s at line %d reaches host-local agent/MCP control sink %s at line %d targeting %s", src.Origin, src.Line, sink.Name, st.StartLine, flowDestinationLabel(sink.Destination))
					emitBehaviorIRFinding(summary, seenFinding, Finding{"ast06", 6.4, b.Rel, reason, true, "SKILL-R0005", st.

						// A provider-auth dampener is intentionally withheld when the same file
						// also performs an unresolved or provider-mismatched network write. This
						// keeps the precision fix from hiding a second, weakly-obfuscated exfil
						// path that the micro data-flow parser could not bind to a symbol.
						StartLine, st.EndLine})
				}
			}

			if sink.Kind == "network" && !networkHadCredential && len(credentialProviders) > 0 && !destinationMatchesAnyProvider(credentialProviders, sink.Destination) {
				unsafeAuthContext[fileKey] = true
			}

			// Resolve an exact written path even when the later exec/load statement
			// no longer carries the original variable name.
			emitBehaviorIRBridgeFindings(b, st, text, sink, summary, bridges, seenFinding)
		}
	}
}

func scanBehaviorIRBridgeSinks(
	b FileBlob,
	summary *BehaviorIRSummary,
	bridges map[string]flowPathBridge,
	seenFinding map[string]bool,
) {
	if b.Sampled {
		summary.Truncated = true
	}
	statements := splitLogicalStatements(b.Lower)
	if len(statements) > 12000 {
		summary.Truncated = true
		statements = statements[:12000]
	}
	constants := map[string]string{}
	endpoints := map[string]string{}
	for _, st := range statements {
		text := strings.TrimSpace(st.Text)
		if text == "" || isFlowComment(text) {
			continue
		}
		if len(text) > 32768 {
			summary.Truncated = true
			text = text[:32768]
		}
		if target, rhs, ok := parseFlowAssignment(text); ok {
			if literal := firstFlowLiteral(rhs); literal != "" {
				constants[target] = literal
			}
			if endpoint := endpointConstructorURL(rhs, constants); endpoint != "" {
				endpoints[target] = endpoint
			}
		}
		for _, sink := range detectFlowSinks(text, constants, endpoints) {
			emitBehaviorIRBridgeFindings(b, st, text, sink, summary, bridges, seenFinding)
		}
	}
}

func emitBehaviorIRBridgeFindings(
	b FileBlob,
	st logicalStatement,
	text string,
	sink flowSink,
	summary *BehaviorIRSummary,
	bridges map[string]flowPathBridge,
	seenFinding map[string]bool,
) {
	if sink.Kind != "exec" && sink.Kind != "dynamic-load" && sink.Kind != "deserialize" {
		return
	}
	keys := make([]string, 0, len(bridges))
	for key := range bridges {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		bridge := bridges[key]
		if !statementUsesFlowPath(text, key) {
			continue
		}
		cat := "ast01"
		weight := 6.5
		if sink.Kind == "dynamic-load" {
			cat, weight = "ast07", 6.6
		} else if sink.Kind == "deserialize" {
			cat, weight = "ast05", 6.6
		} else if isPackagePath(b.Rel) || isPackagePath(bridge.File) || hasInstallContext(b.Rel, b.Lower) {
			cat, weight = "ast02", 6.8
		}
		reason := fmt.Sprintf("verified-flow: %s at %s:%d writes %s, then %s:%d reaches %s through that exact artifact", bridge.Taint.Origin, sanitizePath(bridge.File), bridge.Line, compactFlowPath(bridge.Path), sanitizePath(b.Rel), st.StartLine, sink.Name)
		emitBehaviorIRFinding(summary, seenFinding, Finding{cat, weight, b.Rel, reason, true, "SKILL-R0006", st.StartLine, st.EndLine})
	}
}

func emitBehaviorIRFinding(summary *BehaviorIRSummary, seen map[string]bool, f Finding) {
	if len(summary.Findings) >= 32 {
		return
	}
	key := f.Category + "\x00" + strings.ToLower(f.File) + "\x00" + f.Reason
	if seen[key] {
		return
	}
	seen[key] = true
	summary.Findings = append(summary.Findings, f)
	summary.VerifiedCategories[f.Category]++
	summary.MaliciousFlowFiles[strings.ToLower(filepath.ToSlash(f.File))] = true
}

// behaviorIRWeightFactor only suppresses generic co-occurrence findings when
// the relation layer proved that all credential/network use is a narrow,
// provider-matched Authorization flow. Specific wallet, cloud metadata,
// webhook, persistence, lifecycle, or policy-tampering rules are untouched.
func behaviorIRWeightFactor(f Finding, summary BehaviorIRSummary) float64 {
	if summary.Truncated {
		return 1.0
	}
	fileKey := strings.ToLower(filepath.ToSlash(f.File))
	reason := strings.ToLower(f.Reason)

	// yaml.load(..., Loader=SafeLoader) is semantically different from an
	// unsafe loader. Suppress only the legacy proximity findings that cannot
	// inspect the loader argument; payload-tag and other AST05 findings remain.
	if f.Category == "ast05" {
		perFileSafeDeserialize := summary.SafeDeserializeFiles[fileKey]
		aggregateSafeDeserialize := summary.OnlySafeDeserialization && isAggregateDeserializeFinding(f.File)
		if (perFileSafeDeserialize || aggregateSafeDeserialize) && hasAny(reason, []string{
			"unsafe deserialization primitive is near file, network, stdin, argument, upload, or decoded input source",
			"uses unsafe deserialization primitive",
			"uses yaml.load without safeloader/safe_load",
			"unsafe deserialization primitive is paired with file, network, decoded, config, or user-controlled input across skill files",
			"loop115 cross-file fusion: unsafe deserialization primitive is paired with untrusted file/network/config input",
		}) {
			return 0.04
		}
	}

	if f.Category != "ast01" && f.Category != "ast02" && f.Category != "ast04" && f.Category != "ast08" && f.Category != "ast10" {
		return 1.0
	}
	perFileSafe := summary.SafeAuthFiles[fileKey] && !summary.MaliciousFlowFiles[fileKey]
	aggregateSafe := summary.OnlyExpectedAuth && isAggregateFlowFinding(f.File)
	if !(perFileSafe || aggregateSafe) {
		return 1.0
	}

	if f.Category == "ast02" && perFileSafe && strings.Contains(reason, "ci workflow requests identity/secrets tokens and sends them to an external http sink") {
		return 0.04
	}

	if hasAny(reason, []string{
		"reads secret-like data and sends it through a network sink",
		"accesses credential-like material near file, network, or execution logic",
		"credential or token material is paired with outbound network behavior",
		"network behavior is paired with secret/token access across files",
		"concrete credential or sensitive-store access is paired with an outbound upload/webhook sink across skill files",
		"concrete credential store access appears in one skill file and outbound upload/webhook behavior appears elsewhere",
	}) {
		return 0.04
	}
	if summary.OnlyExpectedAuth && hasAny(reason, []string{
		"metadata claims low/safe risk while code shows credential, outbound execution, or destructive behavior",
		"metadata advertises a clean/passed scan while skill code contains credential, outbound, decoded, or command-execution behavior",
	}) {
		return 0.08
	}
	if summary.OnlyExpectedAuth && hasAny(reason, []string{
		"skill/plugin logic is reused or bridged across agent, browser, ide, or extension platforms",
		"skill/plugin material appears reused or bridged across multiple agent, ide, browser, or extension platforms",
		"references reusable cross-platform credentials, cookies, tokens, or cloud/session material",
	}) {
		return 0.04
	}
	return 1.0
}

// calibrateVerifiedFlowCategory lets a relation-proven, specific root cause
// outrank generic AST01 co-occurrence noise. It runs after the legacy category
// calibration and changes only categories backed by a verified-flow finding.
func calibrateVerifiedFlowCategory(category string, maxScore float64, scores map[string]float64, findings []Finding) (string, float64) {
	type candidate struct {
		category string
		weight   float64
		priority int
	}
	priority := map[string]int{"ast02": 5, "ast05": 4, "ast06": 3, "ast07": 2, "ast01": 1}
	best := candidate{}
	for _, f := range findings {
		if !strings.Contains(strings.ToLower(f.Reason), "verified-flow") {
			continue
		}
		p := priority[f.Category]
		if p == 0 || scores[f.Category] < 5.5 {
			continue
		}
		if f.Weight > best.weight || (f.Weight == best.weight && p > best.priority) {
			best = candidate{category: f.Category, weight: f.Weight, priority: p}
		}
	}
	if best.category == "" {
		return category, maxScore
	}
	return best.category, scores[best.category]
}

func isAggregateFlowFinding(file string) bool {
	f := strings.ToLower(file)
	return f == "multi-file" || strings.Contains(f, "secret material+outbound") || strings.Contains(f, "loop16-115 cross-file") || strings.Contains(f, "manifest+code") || strings.Contains(f, "scan metadata+code")
}

func isAggregateDeserializeFinding(file string) bool {
	f := strings.ToLower(file)
	return f == "unsafe deserializer+untrusted input" || strings.Contains(f, "cross-file unsafe-deserialize") || strings.Contains(f, "unsafe deserializer")
}

func parseFlowAssignment(text string) (string, string, bool) {
	m := flowAssignRE.FindStringSubmatch(text)
	if len(m) != 3 {
		return "", "", false
	}
	target := normalizeFlowSymbol(strings.Split(m[1], ",")[0])
	if target == "" || target == "if" || target == "while" || target == "for" || target == "return" {
		return "", "", false
	}
	return target, strings.TrimSpace(m[2]), true
}

func normalizeFlowSymbol(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSpace(strings.Trim(s, "{}"))
	s = strings.TrimPrefix(s, "$")
	if i := strings.IndexAny(s, "["); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func setFlowTaint(m map[string]flowTaint, target string, t flowTaint) {
	if len(m) >= 512 {
		return
	}
	target = normalizeFlowSymbol(target)
	if target == "" {
		return
	}
	t.Symbol = target
	m[target] = t
	if i := strings.Index(target, "."); i > 0 {
		root := target[:i]
		t.Symbol = root
		m[root] = t
	}
}

func deleteFlowTaint(m map[string]flowTaint, target string) {
	target = normalizeFlowSymbol(target)
	delete(m, target)
	if i := strings.Index(target, "."); i > 0 {
		delete(m, target[:i])
	}
}

func directFlowSource(expr, file string, line int, symbol string, constants map[string]string) (flowTaint, bool) {
	l := strings.ToLower(expr)
	if key := extractFlowEnvKey(l); key != "" && isSensitiveFlowName(key) {
		return flowTaint{Kind: flowCredentialEnv, Origin: "environment credential " + strings.ToUpper(key), Symbol: symbol, Provider: providerForCredential(key), File: file, Line: line}, true
	}
	if path, ok := flowReadPath(l, constants); ok {
		kind := flowFileInput
		origin := "file input " + compactFlowPath(path)
		if isSensitiveFlowPath(path) {
			kind = flowCredentialFile
			origin = "credential file " + compactFlowPath(path)
		}
		return flowTaint{Kind: kind, Origin: origin, Symbol: symbol, File: file, Line: line, Path: path}, true
	}
	if isRemoteInputExpression(l) {
		dest := flowDestination(l, constants, nil)
		if isCloudMetadataDestination(dest) {
			return flowTaint{Kind: flowCredentialEnv, Origin: "cloud metadata credential response " + flowDestinationLabel(dest), Symbol: symbol, File: file, Line: line, Endpoint: dest}, true
		}
		if isLocalControlDestination(dest) {
			return flowTaint{Kind: flowLocalControl, Origin: "host-local control response " + flowDestinationLabel(dest), Symbol: symbol, File: file, Line: line, Endpoint: dest}, true
		}
		return flowTaint{Kind: flowRemoteInput, Origin: "remote content " + flowDestinationLabel(dest), Symbol: symbol, File: file, Line: line, Endpoint: dest}, true
	}
	if hasAny(l, []string{"input(", "sys.stdin", "sys.argv", "process.argv", "os.args", "request.args", "request.form", "request.json", "req.body", "req.query", "req.params", "argv[", "flag.string", "scanner.nextline"}) {
		return flowTaint{Kind: flowUserInput, Origin: "user or request-controlled input", Symbol: symbol, File: file, Line: line}, true
	}
	if hasAny(l, []string{"manifest", "metadata", "config", "settings", "yaml.safe_load", "json.load", "toml.load"}) && hasAny(l, []string{"open(", "read", "load(", "parse("}) {
		return flowTaint{Kind: flowMetadataInput, Origin: "manifest/config-controlled input", Symbol: symbol, File: file, Line: line}, true
	}
	return flowTaint{}, false
}

func directFlowSources(expr, file string, line int, constants map[string]string) []flowTaint {
	var out []flowTaint
	if t, ok := directFlowSource(expr, file, line, "", constants); ok {
		out = append(out, t)
	}
	// A sink can contain both a URL fetch and an environment credential. Capture
	// the credential source separately when the first direct source was remote.
	if key := extractFlowEnvKey(strings.ToLower(expr)); key != "" && isSensitiveFlowName(key) {
		t := flowTaint{Kind: flowCredentialEnv, Origin: "environment credential " + strings.ToUpper(key), Provider: providerForCredential(key), File: file, Line: line}
		found := false
		for _, x := range out {
			if x.Kind == t.Kind && x.Origin == t.Origin {
				found = true
			}
		}
		if !found {
			out = append(out, t)
		}
	}
	if path, ok := flowReadPath(strings.ToLower(expr), constants); ok && isSensitiveFlowPath(path) {
		t := flowTaint{Kind: flowCredentialFile, Origin: "credential file " + compactFlowPath(path), File: file, Line: line, Path: path}
		found := false
		for _, x := range out {
			if x.Kind == t.Kind && x.Path == t.Path {
				found = true
			}
		}
		if !found {
			out = append(out, t)
		}
	}
	return out
}

func flowTaintFromExpression(expr string, taints map[string]flowTaint) (flowTaint, bool) {
	for _, id := range flowIdentifierRE.FindAllString(strings.ToLower(expr), -1) {
		if t, ok := taints[normalizeFlowSymbol(id)]; ok {
			return t, true
		}
	}
	return flowTaint{}, false
}

func flowTaintsInExpression(expr string, taints map[string]flowTaint) []flowTaint {
	seen := map[string]bool{}
	var out []flowTaint
	for _, id := range flowIdentifierRE.FindAllString(strings.ToLower(expr), -1) {
		key := normalizeFlowSymbol(id)
		t, ok := taints[key]
		if !ok {
			continue
		}
		dedupeKey := t.Kind + "\x00" + t.Origin + "\x00" + key
		if seen[dedupeKey] {
			continue
		}
		seen[dedupeKey] = true
		t.Symbol = key
		out = append(out, t)
	}
	return out
}

func dedupeFlowTaints(in []flowTaint) []flowTaint {
	seen := map[string]bool{}
	out := make([]flowTaint, 0, len(in))
	for _, t := range in {
		key := t.Kind + "\x00" + t.Origin + "\x00" + t.Symbol
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

func detectFlowSinks(text string, constants, endpoints map[string]string) []flowSink {
	l := strings.ToLower(text)
	var out []flowSink
	destination := flowDestination(l, constants, endpoints)

	if isNetworkOutputExpression(l) {
		out = append(out, flowSink{Kind: "network", Name: networkSinkName(l), Destination: destination})
	}
	if isExecSinkExpression(l) {
		out = append(out, flowSink{Kind: "exec", Name: execSinkName(l), Destination: destination})
	}
	if isDeserializeSinkExpression(l) {
		out = append(out, flowSink{Kind: "deserialize", Name: deserializeSinkName(l), Destination: destination})
	}
	if isDynamicLoadSinkExpression(l) {
		out = append(out, flowSink{Kind: "dynamic-load", Name: dynamicLoadSinkName(l), Destination: destination})
	}
	if isLocalControlDestination(destination) && hasAny(l, []string{"tools/call", "tool.call", "jsonrpc", "execute", "command", "shell", "mcp", "debugger", "devtools"}) && hasAny(l, []string{".send(", "sendall(", "requests.post", "fetch(", "axios.post", "urlopen("}) {
		out = append(out, flowSink{Kind: "local-control", Name: "agent/MCP control request", Destination: destination})
	}
	return out
}

func isNetworkOutputExpression(l string) bool {
	if hasAny(l, []string{"requests.post", "requests.put", "requests.patch", "httpx.post", "httpx.put", "httpx.patch", "axios.post", "axios.put", "axios.patch", "sendbeacon", "websocket.send", "socket.send", "socket.sendall", "socket.sendto", "curl -d", "curl --data", "curl --upload-file", "wget --post-data", "scp ", "sftp ", "http.post", "https.post", "client.post", "request.post"}) {
		return true
	}
	if strings.Contains(l, "curl ") && hasAny(l, []string{" -d ", " --data", " --data-", " --upload-file", " -t ", " -f @"}) {
		return true
	}
	if strings.Contains(l, "fetch(") && hasAny(l, []string{"method:'post'", `method:"post"`, "method: 'post'", `method: "post"`, "body:", "headers:"}) {
		return true
	}
	if strings.Contains(l, "urlopen(") && hasAny(l, []string{"data=", "request(", "method='post'", `method="post"`}) {
		return true
	}
	if strings.Contains(l, ".post(") && hasAny(l, []string{".body(", ".json(", ".form(", ".send("}) {
		return true
	}
	// GET requests carrying a tainted Authorization/query parameter are still
	// network sinks. Relation matching later ensures a source is actually used.
	if hasAny(l, []string{"requests.get", "httpx.get", "axios.get", "fetch(", "urlopen("}) && hasAny(l, []string{"authorization", "x-api-key", "api_key", "apikey", "token", "headers", "params"}) {
		return true
	}
	if hasAny(l, []string{"invoke-restmethod", "invoke-webrequest", " irm ", " iwr "}) && hasAny(l, []string{"-method post", "-method put", "-method patch", "-body", "-headers", "authorization", "x-api-key"}) {
		return true
	}
	if flowObjectSendRE.MatchString(l) {
		return true
	}
	return false
}

func isExecSinkExpression(l string) bool {
	return hasAny(l, []string{"os.system(", "subprocess.run(", "subprocess.call(", "subprocess.check_output(", "subprocess.check_call(", "subprocess.popen(", "child_process.exec(", "child_process.execsync(", "child_process.spawn(", "exec(", "eval(", "runtime.getruntime().exec(", "processbuilder(", "shell_exec(", "proc_open(", "powershell -command", "invoke-expression", "iex ", "iex(", "bash -c", "sh -c", "| bash", "| sh"})
}

func isDeserializeSinkExpression(l string) bool {
	return hasAny(l, []string{"pickle.load(", "pickle.loads(", "dill.load(", "dill.loads(", "marshal.load(", "marshal.loads(", "joblib.load(", "jsonpickle.decode(", "yaml.unsafe_load(", "yaml.load(", "objectinputstream(", "unserialize("}) && !hasAny(l, []string{"yaml.safe_load", "safeloader", "csafeloader", "loader=yaml.safeloader", "loader = yaml.safeloader", "loader=safeloader", "loader = safeloader", "loader=yaml.csafeloader", "loader = yaml.csafeloader"})
}

func isDynamicLoadSinkExpression(l string) bool {
	return hasAny(l, []string{"importlib.import_module(", "spec_from_file_location(", "__import__(", "await import(", "require(", "dlopen(", "loadlibrary(", "vm.runinnewcontext(", "new function(", "plugin.open(", "import-module", "add-type -path"})
}

func networkSinkName(l string) string {
	for _, x := range []string{"requests.post", "requests.put", "requests.patch", "requests.get", "httpx.post", "httpx.get", "axios.post", "axios.get", "fetch", "invoke-restmethod", "invoke-webrequest", "sendbeacon", "websocket.send", "socket.sendall", "socket.send", "curl --data", "curl -d", "scp", "sftp", "client.post", "urlopen"} {
		if strings.Contains(l, x) {
			return x
		}
	}
	return "network output"
}

func execSinkName(l string) string {
	for _, x := range []string{"subprocess.run", "subprocess.call", "subprocess.popen", "os.system", "child_process.exec", "child_process.spawn", "runtime.getruntime().exec", "processbuilder", "invoke-expression", "powershell", "bash -c", "sh -c", "eval", "exec"} {
		if strings.Contains(l, x) {
			return x
		}
	}
	return "command execution"
}

func deserializeSinkName(l string) string {
	for _, x := range []string{"pickle.loads", "pickle.load", "yaml.unsafe_load", "yaml.load", "marshal.loads", "dill.loads", "joblib.load", "jsonpickle.decode", "unserialize"} {
		if strings.Contains(l, x) {
			return x
		}
	}
	return "unsafe deserializer"
}

func dynamicLoadSinkName(l string) string {
	for _, x := range []string{"importlib.import_module", "spec_from_file_location", "__import__", "await import", "require", "plugin.open", "import-module", "add-type -path", "dlopen", "loadlibrary", "vm.runinnewcontext", "new function"} {
		if strings.Contains(l, x) {
			return x
		}
	}
	return "dynamic loader"
}

func remoteExecCategory(rel, content string, src flowTaint) (string, float64) {
	if isPackagePath(rel) || hasInstallContext(rel, content) {
		return "ast02", 6.8
	}
	if hasAny(content, []string{"hot reload", "hot-reload", "fs.watch", "watchdog", "self_update", "self-update", "update_url", "plugin_url", "module_url", "reload("}) {
		return "ast07", 6.5
	}
	return "ast01", 6.5
}

func hasInstallContext(rel, content string) bool {
	path := strings.ToLower(rel)
	return isPackagePath(path) || strings.Contains(path, "install") || strings.Contains(path, "setup") || strings.Contains(path, "build") || hasAny(content, []string{"postinstall", "preinstall", "prepare", "setup.py", "build-backend", "dockerfile", "npm_lifecycle_event"})
}

func isExpectedProviderAuth(src flowTaint, statement, destination string) bool {
	if src.Kind != flowCredentialEnv || src.Provider == "" || destination == "" {
		return false
	}
	if isSuspiciousFlowDestination(destination) || !providerDestinationMatches(src.Provider, destination) {
		return false
	}
	l := strings.ToLower(statement)
	markers := []string{"authorization", "x-api-key", "x_api_key", "api-key", "apikey", "bearer", "headers", "auth="}
	if !hasAny(l, markers) {
		return false
	}
	if src.Provider == "discord" && strings.Contains(strings.ToLower(destination), "/webhooks") {
		return false
	}
	if src.Provider == "slack" && strings.Contains(strings.ToLower(destination), "hooks.slack.com") {
		return false
	}
	if src.Symbol == "" {
		key := strings.TrimSpace(strings.TrimPrefix(src.Origin, "environment credential"))
		if key == "" {
			return false
		}
		return symbolUsedOnlyForAuth(strings.ToLower(key), l)
	}
	return symbolUsedOnlyForAuth(src.Symbol, l)
}

func symbolUsedOnlyForAuth(symbol, statement string) bool {
	symbol = strings.ToLower(strings.TrimSpace(symbol))
	indices := allSubstringIndices(statement, symbol)
	if len(indices) == 0 {
		return false
	}
	authMarkers := []string{"authorization", "x-api-key", "x_api_key", "api-key", "apikey", "bearer", "headers", "auth="}
	bodyMarkers := []string{"data=", "json=", "body:", "body=", "-body", "--data", " -d ", "payload", "content", "upload", "files=", "form="}
	seenAuth := false
	for _, idx := range indices {
		start := idx - 160
		if start < 0 {
			start = 0
		}
		prefix := statement[start:idx]
		authPos := lastFlowMarkerIndex(prefix, authMarkers)
		bodyPos := lastFlowMarkerIndex(prefix, bodyMarkers)
		if bodyPos > authPos {
			return false
		}
		if authPos < 0 {
			return false
		}
		seenAuth = true
	}
	return seenAuth
}

func lastFlowMarkerIndex(s string, markers []string) int {
	best := -1
	for _, marker := range markers {
		if i := strings.LastIndex(s, marker); i > best {
			best = i
		}
	}
	return best
}

func providerDestinationMatches(provider, destination string) bool {
	host, path := parseFlowHostPath(destination)
	if host == "" {
		return false
	}
	for _, allowed := range providerDomains[provider] {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			if provider == "discord" && !strings.HasPrefix(path, "/api") {
				return false
			}
			if provider == "openrouter" && !strings.HasPrefix(path, "/api") {
				return false
			}
			return true
		}
	}
	return false
}

func providerForCredential(key string) string {
	k := strings.ToLower(key)
	switch {
	case strings.Contains(k, "azure") && strings.Contains(k, "openai"):
		return "azure-openai"
	case strings.Contains(k, "openai"):
		return "openai"
	case strings.Contains(k, "anthropic") || strings.Contains(k, "claude"):
		return "anthropic"
	case strings.Contains(k, "github") || strings.HasPrefix(k, "gh_"):
		return "github"
	case strings.Contains(k, "slack"):
		return "slack"
	case strings.Contains(k, "google") || strings.Contains(k, "gemini"):
		return "google"
	case strings.Contains(k, "huggingface") || strings.HasPrefix(k, "hf_"):
		return "huggingface"
	case strings.Contains(k, "nvidia") || strings.Contains(k, "nvcf"):
		return "nvidia"
	case strings.Contains(k, "notion"):
		return "notion"
	case strings.Contains(k, "linear"):
		return "linear"
	case strings.Contains(k, "stripe"):
		return "stripe"
	case strings.Contains(k, "discord"):
		return "discord"
	case strings.Contains(k, "telegram"):
		return "telegram"
	case strings.Contains(k, "cohere"):
		return "cohere"
	case strings.Contains(k, "mistral"):
		return "mistral"
	case strings.Contains(k, "groq"):
		return "groq"
	case strings.Contains(k, "perplexity"):
		return "perplexity"
	case strings.Contains(k, "openrouter"):
		return "openrouter"
	default:
		return ""
	}
}

func extractFlowEnvKey(l string) string {
	for _, re := range []*regexp.Regexp{flowEnvCallRE, flowEnvIndexRE, flowProcessEnvRE, flowProcessEnvIndexRE, flowPowerShellEnvRE, flowShellEnvRE, flowGoEnvRE} {
		for _, m := range re.FindAllStringSubmatch(l, -1) {
			if len(m) != 2 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(m[1]))
			if isSensitiveFlowName(key) {
				return key
			}
		}
	}
	return ""
}

func isSensitiveFlowName(name string) bool {
	return hasAny(strings.ToLower(name), []string{"api_key", "apikey", "api-key", "token", "secret", "password", "passwd", "credential", "private", "auth", "cookie", "session", "signing_key", "webhook_key"})
}

func isCredentialTaint(t flowTaint) bool {
	return t.Kind == flowCredentialEnv || t.Kind == flowCredentialFile
}

func flowReadPath(l string, constants map[string]string) (string, bool) {
	if !hasAny(l, []string{"open(", "read_text(", "read_bytes(", "readfile", "read_file", "readfilesync", "read_to_string(", "os.readfile(", "ioutil.readfile(", "cat ", "type "}) {
		return "", false
	}
	for _, q := range flowQuotedRE.FindAllStringSubmatch(l, -1) {
		if len(q) == 2 && looksLikeFlowPath(q[1]) {
			return q[1], true
		}
	}
	for _, marker := range []string{"~/.ssh/id_rsa", "~/.ssh/id_ed25519", "/.ssh/id_rsa", "/.ssh/id_ed25519", ".aws/credentials", ".kube/config", "serviceaccount/token", ".docker/config.json", ".npmrc", ".pypirc", ".netrc", ".vault-token", "wallet.dat", "cookies.sqlite", "login data", ".env"} {
		if strings.Contains(l, marker) {
			return marker, true
		}
	}
	for _, name := range sortedFlowMapKeys(constants) {
		value := constants[name]
		if strings.Contains(l, name) && looksLikeFlowPath(value) {
			return value, true
		}
	}
	return "", false
}

func isSensitiveFlowPath(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))
	return hasAny(p, []string{"/.env", ".env", "/.ssh/", "id_rsa", "id_ed25519", ".aws/credentials", ".azure/", ".config/gcloud", ".kube/config", "serviceaccount/token", ".docker/config.json", ".npmrc", ".pypirc", ".netrc", "git-credentials", "login data", "cookies", "keychain", "wallet", "mnemonic", "seed", "private key", "keystore", ".vault-token"})
}

func looksLikeFlowPath(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "/") || strings.Contains(l, "\\") || strings.HasPrefix(l, ".") || hasAny(l, []string{"manifest", "config", "settings", "credential", "token", "wallet", "cookie", ".env"})
}

func isRemoteInputExpression(l string) bool {
	if hasAny(l, []string{"requests.get(", "httpx.get(", "axios.get(", "urllib.request.urlopen(", "urlopen(", "http.get(", "reqwest::get(", "ureq::get(", "client.get(", "invoke-webrequest", "invoke-restmethod", "curl ", "wget "}) {
		return true
	}
	if strings.Contains(l, "fetch(") && !hasAny(l, []string{"method:'post'", `method:"post"`, "method: 'post'", `method: "post"`, "body:"}) {
		return true
	}
	return false
}

func classifyFlowDeserialization(statements []logicalStatement) (hasSafe bool, hasUnsafe bool) {
	for _, st := range statements {
		l := strings.ToLower(strings.TrimSpace(st.Text))
		if l == "" || isFlowComment(l) {
			continue
		}
		if hasAny(l, []string{"pickle.load(", "pickle.loads(", "dill.load(", "dill.loads(", "marshal.load(", "marshal.loads(", "joblib.load(", "jsonpickle.decode(", "yaml.unsafe_load(", "objectinputstream(", "unserialize("}) {
			hasUnsafe = true
		}
		if !strings.Contains(l, "yaml.load(") {
			continue
		}
		if hasAny(l, []string{"safeloader", "csafeloader", "loader=yaml.safeloader", "loader = yaml.safeloader", "loader=safeloader", "loader = safeloader", "loader=yaml.csafeloader", "loader = yaml.csafeloader"}) {
			hasSafe = true
		} else {
			hasUnsafe = true
		}
	}
	return hasSafe, hasUnsafe
}

func collectFlowCredentialProviders(statements []logicalStatement) map[string]bool {
	providers := map[string]bool{}
	for _, st := range statements {
		if key := extractFlowEnvKey(strings.ToLower(st.Text)); key != "" && isSensitiveFlowName(key) {
			if provider := providerForCredential(key); provider != "" {
				providers[provider] = true
			}
		}
	}
	return providers
}

func destinationMatchesAnyProvider(providers map[string]bool, destination string) bool {
	if destination == "" || destination == "unknown destination" || isSuspiciousFlowDestination(destination) {
		return false
	}
	for provider := range providers {
		if providerDestinationMatches(provider, destination) {
			return true
		}
	}
	return false
}

func flowSourceNearSink(src flowTaint, sinkFile string, sinkLine int) bool {
	if src.Line <= 0 || sinkLine <= 0 || !strings.EqualFold(filepath.ToSlash(src.File), filepath.ToSlash(sinkFile)) {
		return true
	}
	delta := sinkLine - src.Line
	return delta >= 0 && delta <= 600
}

func sortedFlowMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func detectFlowTransform(expr string) string {
	l := strings.ToLower(expr)
	switch {
	case hasAny(l, []string{"b64encode", "tobase64", ".tostring('base64')", `.tostring("base64")`, "base64.encode"}):
		return "base64 encode"
	case hasAny(l, []string{"b64decode", "frombase64", "atob(", "base64.decode"}):
		return "base64 decode"
	case hasAny(l, []string{"gzip", "zlib", "deflate", "decompress"}):
		return "archive/decompress"
	case hasAny(l, []string{"json.dumps", "json.stringify", "serialize("}):
		return "serialize"
	case hasAny(l, []string{"hexlify", "fromhex", "decodehex", "urlencode", "quote_plus"}):
		return "encode/decode"
	default:
		return ""
	}
}

func appendTransform(in []string, transform string) []string {
	if transform == "" {
		return in
	}
	for _, x := range in {
		if x == transform {
			return in
		}
	}
	if len(in) >= 4 {
		return in
	}
	out := append([]string{}, in...)
	return append(out, transform)
}

func mutatedContainer(text string) string {
	l := strings.ToLower(strings.TrimSpace(text))
	if i := strings.Index(l, "["); i > 0 && strings.Contains(l[:i], "=") == false && strings.Contains(l, "]=") {
		return normalizeFlowSymbol(l[:i])
	}
	for _, method := range []string{".append(", ".extend(", ".update(", ".push(", ".set("} {
		if i := strings.Index(l, method); i > 0 {
			prefix := strings.TrimSpace(l[:i])
			parts := strings.Fields(prefix)
			if len(parts) > 0 {
				return normalizeFlowSymbol(parts[len(parts)-1])
			}
		}
	}
	return ""
}

func flowWritePathAndValue(text string, constants map[string]string) (string, string) {
	l := strings.ToLower(text)
	if !hasAny(l, []string{".write(", "writefile", "write_file", "writefilesync", "write_text(", "write_bytes(", "os.writefile("}) {
		return "", ""
	}
	quoted := flowQuotedRE.FindAllStringSubmatch(l, -1)
	path := ""
	for _, q := range quoted {
		if len(q) == 2 && looksLikeFlowPath(q[1]) {
			path = q[1]
			break
		}
	}
	if path == "" {
		for _, name := range sortedFlowMapKeys(constants) {
			value := constants[name]
			if strings.Contains(l, name) && looksLikeFlowPath(value) {
				path = value
				break
			}
		}
	}
	if path == "" {
		return "", ""
	}
	return path, l
}

func shellRemoteWrite(text string) (string, string) {
	l := strings.ToLower(text)
	if !hasAny(l, []string{"curl ", "wget "}) || !strings.Contains(l, "http") {
		return "", ""
	}
	urlValue := firstFlowURL(l)
	fields := strings.Fields(l)
	for i, field := range fields {
		if (field == "-o" || field == "--output" || field == "-output") && i+1 < len(fields) {
			return strings.Trim(fields[i+1], `"'`), urlValue
		}
	}
	return "", ""
}

func flowDestination(text string, constants, endpoints map[string]string) string {
	if u := firstFlowURL(text); u != "" {
		return u
	}
	for _, name := range sortedFlowMapKeys(constants) {
		value := constants[name]
		if strings.Contains(text, name) && strings.Contains(value, "://") {
			return value
		}
	}
	if endpoints != nil {
		if m := flowObjectSendRE.FindStringSubmatch(text); len(m) == 2 {
			if u := endpoints[strings.ToLower(m[1])]; u != "" {
				return u
			}
		}
	}
	return "unknown destination"
}

func endpointConstructorURL(rhs string, constants map[string]string) string {
	l := strings.ToLower(rhs)
	if !hasAny(l, []string{"new websocket(", "websocket.create_connection(", "socket.connect(", "grpc.dial("}) {
		return ""
	}
	return flowDestination(l, constants, nil)
}

func firstFlowURL(s string) string {
	return strings.TrimRight(flowURLRE.FindString(s), ".")
}

func firstFlowLiteral(s string) string {
	m := flowQuotedRE.FindStringSubmatch(s)
	if len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func normalizeFlowPath(path string) string {
	p := strings.ToLower(strings.TrimSpace(strings.Trim(path, `"'`)))
	p = filepath.ToSlash(p)
	return filepath.Clean(p)
}

func compactFlowPath(path string) string {
	p := strings.TrimSpace(strings.Trim(path, `"'`))
	if len(p) > 80 {
		p = "..." + p[len(p)-77:]
	}
	return p
}

func statementUsesFlowPath(statement, normalized string) bool {
	l := strings.ToLower(filepath.ToSlash(statement))
	return normalized != "." && normalized != "" && strings.Contains(l, normalized)
}

func isCloudMetadataDestination(destination string) bool {
	l := strings.ToLower(destination)
	return hasAny(l, []string{"169.254.169.254", "metadata.google.internal", "metadata.azure.com", "100.100.100.200", "iam/security-credentials", "computemetadata/v1"})
}

func isLocalControlDestination(destination string) bool {
	host, _ := parseFlowHostPath(destination)
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasPrefix(host, "127.") || strings.HasSuffix(host, ".localhost")
}

func isSuspiciousFlowDestination(destination string) bool {
	l := strings.ToLower(destination)
	if isCloudMetadataDestination(l) || isLocalControlDestination(l) {
		return true
	}
	return hasAny(l, []string{"webhook.site", "requestbin", "pipedream.net", "ngrok", "trycloudflare.com", "localtunnel", "pastebin.com", "rentry.co", "discord.com/api/webhooks", "hooks.slack.com", "glot.io", "burpcollaborator", "interact.sh"}) || isRawIPDestination(l)
}

func isRawIPDestination(destination string) bool {
	host, _ := parseFlowHostPath(destination)
	if host == "" {
		return false
	}
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func parseFlowHostPath(destination string) (string, string) {
	d := strings.TrimSpace(destination)
	if d == "" || d == "unknown destination" {
		return "", ""
	}
	u, err := url.Parse(d)
	if err != nil {
		return "", ""
	}
	return strings.ToLower(u.Hostname()), strings.ToLower(u.Path)
}

func flowDestinationLabel(destination string) string {
	if destination == "" || destination == "unknown destination" {
		return "an unresolved endpoint"
	}
	host, path := parseFlowHostPath(destination)
	if host == "" {
		if len(destination) > 96 {
			return destination[:93] + "..."
		}
		return destination
	}
	if len(path) > 48 {
		path = path[:45] + "..."
	}
	return host + path
}

func formatFlowTransforms(transforms []string) string {
	if len(transforms) == 0 {
		return ""
	}
	return " via " + strings.Join(transforms, " -> ")
}

func allSubstringIndices(s, sub string) []int {
	var out []int
	if sub == "" {
		return out
	}
	for start := 0; start < len(s); {
		i := strings.Index(s[start:], sub)
		if i < 0 {
			break
		}
		idx := start + i
		out = append(out, idx)
		start = idx + len(sub)
	}
	return out
}

func splitLogicalStatements(content string) []logicalStatement {
	lines := strings.Split(content, "\n")
	out := make([]logicalStatement, 0, len(lines))
	var buf strings.Builder
	startLine := 1
	depth := 0
	quote := rune(0)
	escaped := false

	flush := func(endLine int) {
		text := strings.TrimSpace(buf.String())
		buf.Reset()
		if text == "" {
			return
		}
		for _, part := range splitTopLevelSemicolons(text) {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, logicalStatement{Text: part, StartLine: startLine, EndLine: endLine})
			}
		}
	}

	for i, line := range lines {
		if buf.Len() == 0 {
			startLine = i + 1
		} else {
			buf.WriteByte(' ')
		}
		buf.WriteString(strings.TrimSpace(line))
		for _, r := range line {
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' && quote != 0 {
				escaped = true
				continue
			}
			if quote != 0 {
				if r == quote {
					quote = 0
				}
				continue
			}
			if r == '\'' || r == '"' || r == '`' {
				quote = r
				continue
			}
			switch r {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				if depth > 0 {
					depth--
				}
			}
		}
		trimmed := strings.TrimSpace(line)
		continued := strings.HasSuffix(trimmed, "\\")
		if depth == 0 && quote == 0 && !continued {
			flush(i + 1)
		}
		if buf.Len() > 65536 {
			flush(i + 1)
			depth, quote, escaped = 0, 0, false
		}
	}
	if buf.Len() > 0 {
		flush(len(lines))
	}
	return out
}

func splitTopLevelSemicolons(s string) []string {
	var out []string
	start := 0
	depth := 0
	quote := byte(0)
	escaped := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if quote != 0 {
			if ch == '\\' {
				escaped = true
			} else if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			quote = ch
			continue
		}
		switch ch {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

func isFlowComment(text string) bool {
	l := strings.TrimSpace(strings.ToLower(text))
	return strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") || strings.HasPrefix(l, "/*") || strings.HasPrefix(l, "*") || strings.HasPrefix(l, "<!--")
}
