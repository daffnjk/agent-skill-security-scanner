package main

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// evidenceHasAny is for lexical evidence, not for arbitrary substring search.
// In particular cron/iex/irm must not match acronyms, BibTeX, or confirm.
// Punctuation inside a signature is retained; identifier boundaries include
// Unicode letters so an ASCII keyword embedded in a name is not an action.
func evidenceHasAny(text string, needles []string) bool {
	for _, needle := range needles {
		if needle == "" {
			continue
		}
		first, _ := utf8.DecodeRuneInString(needle)
		last, _ := utf8.DecodeLastRuneInString(needle)
		for offset := 0; offset < len(text); {
			relative := strings.Index(text[offset:], needle)
			if relative < 0 {
				break
			}
			start := offset + relative
			end := start + len(needle)
			left, right := true, true
			if evidenceIdentifier(first) && start > 0 {
				before, _ := utf8.DecodeLastRuneInString(text[:start])
				left = !evidenceIdentifier(before)
			}
			if evidenceIdentifier(last) && end < len(text) {
				after, _ := utf8.DecodeRuneInString(text[end:])
				right = !evidenceIdentifier(after)
			}
			if left && right {
				return true
			}
			offset = start + 1
		}
	}
	return false
}

func evidenceIdentifier(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

// nearbyEvidence restricts a proximity heuristic, not the collector or IR.
// Overlapping windows retain short multi-line instructions while preventing
// unrelated chapters from supplying the missing edges of a "strong" chain.
// Distant/cross-file behavior remains eligible for the exact-artifact IR.
func nearbyEvidence(text string, predicate func(string) bool) bool {
	const window = 2048
	const stride = 1024
	if len(text) <= window {
		return predicate(text)
	}
	for start := 0; start < len(text); start += stride {
		end := start + window
		if end > len(text) {
			end = len(text)
		}
		// Padding prevents a window cut inside an identifier from inventing a
		// lexical boundary. Genuine boundary hits are covered by the overlap.
		part := text[start:end]
		if start > 0 {
			part = "_" + part
		}
		if end < len(text) {
			part += "_"
		}
		if predicate(part) {
			return true
		}
		if end == len(text) {
			break
		}
	}
	return false
}

// A timer or an API-key mention alone does not establish an attack payload.
// Demand an actionable execution edge or sensitive-store read plus transfer.
func gatedPayloadEvidence(c string) bool {
	return nearbyEvidence(c, func(s string) bool {
		command := evidenceHasAny(s, []string{"exec(", "eval(", "os.system(", "subprocess.", "child_process", "bash -c", "sh -c", "powershell", "/dev/tcp/", "nc -e", "| bash", "| sh"})
		transform := evidenceHasAny(s, []string{"base64", "b64decode", "atob(", "frombase64string", "curl ", "wget ", "requests.get", "fetch("})
		store := evidenceHasAny(s, []string{"id_rsa", "id_ed25519", "~/.ssh", ".aws/credentials", ".env", "wallet.dat", "seed phrase", "private key", "login data", "cookies.sqlite"})
		read := evidenceHasAny(s, []string{"open(", "read_text(", "readfile", "readfilesync", "cat ", "get-content", "read ", "collect ", "harvest "})
		transfer := evidenceHasAny(s, []string{"requests.post", "fetch(", "axios.post", "curl ", "wget ", "sendbeacon", "webhook", "upload ", "send to"})
		return (command && transform) || (store && read && transfer)
	})
}

// markdownRegion preserves original line coordinates. Code comments cannot
// change heading context, and a short/mismatched fence cannot close a region.
// This is a bounded Markdown recognizer, not a Markdown renderer.
type markdownRegion struct {
	Body      string
	Heading   string
	StartLine int
	Code      bool
}

func markdownRegions(c string) []markdownRegion {
	lines := strings.Split(c, "\n")
	regions := make([]markdownRegion, 0, 16)
	var body strings.Builder
	heading, captured := "", ""
	start, length := 1, 0
	var delimiter byte
	flush := func(code bool, h string) {
		if body.Len() > 0 {
			regions = append(regions, markdownRegion{body.String(), h, start, code})
		}
		body.Reset()
	}
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " ")
		indent := len(line) - len(trimmed)
		marker, count := byte(0), 0
		if indent <= 3 && len(trimmed) > 0 && (trimmed[0] == '`' || trimmed[0] == '~') {
			marker = trimmed[0]
			for count < len(trimmed) && trimmed[count] == marker {
				count++
			}
			if count < 3 {
				marker = 0
			}
		}
		if delimiter == 0 {
			if marker != 0 {
				flush(false, heading)
				delimiter, length, captured, start = marker, count, heading, i+2
				continue
			}
			if indent <= 3 && strings.HasPrefix(trimmed, "#") {
				n := 0
				for n < len(trimmed) && trimmed[n] == '#' {
					n++
				}
				if n <= 6 && (n == len(trimmed) || trimmed[n] == ' ' || trimmed[n] == '\t') {
					heading = strings.TrimSpace(trimmed[n:])
				}
			}
		} else if marker == delimiter && count >= length && strings.TrimSpace(trimmed[count:]) == "" {
			flush(true, captured)
			delimiter, length, start = 0, 0, i+2
			continue
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
	if delimiter != 0 {
		flush(true, captured)
	} else {
		flush(false, heading)
	}
	return regions
}

func activeMarkdownEvidence(c string) string {
	var out strings.Builder
	line := 1
	for _, region := range markdownRegions(c) {
		for line < region.StartLine {
			out.WriteByte('\n')
			line++
		}
		if !region.Code || activeMarkdownHeading(region.Heading) || concreteRiskFence(region.Body) {
			out.WriteString(region.Body)
		} else {
			out.WriteString(strings.Repeat("\n", strings.Count(region.Body, "\n")))
		}
		line += strings.Count(region.Body, "\n")
	}
	return out.String()
}

// Analyze each eligible code region as a separate scope, never execute it.
// No safe-auth dampener escapes a fenced scope to suppress unrelated prose.
// Environment-only findings are left to existing rules: a header credential
// for an unknown API is not sufficient to infer exfiltration from a document.
func markdownBehaviorFindings(b FileBlob) []Finding {
	var findings []Finding
	for _, region := range markdownRegions(b.Lower) {
		if !region.Code || !(activeMarkdownHeading(region.Heading) || concreteRiskFence(region.Body)) {
			continue
		}
		code := FileBlob{Rel: b.Rel, Lower: region.Body, IsCode: true, Size: int64(len(region.Body)), Sampled: b.Sampled}
		summary := BehaviorIRSummary{
			SafeAuthFiles: map[string]bool{}, CredentialSourceFiles: map[string]bool{},
			MaliciousFlowFiles: map[string]bool{}, SafeDeserializeFiles: map[string]bool{},
			UnsafeDeserializeFiles: map[string]bool{}, VerifiedCategories: map[string]int{},
		}
		scanBehaviorIRFile(code, &summary, map[string]flowPathBridge{}, map[string]bool{}, map[string]bool{}, map[string]bool{})
		for _, f := range summary.Findings {
			if strings.Contains(f.Reason, "environment credential") {
				continue
			}
			f.StartLine += region.StartLine - 1
			f.EndLine += region.StartLine - 1
			// The original reason has region-local coordinates; identify them as such.
			f.Reason = "Markdown code region starting at line " + strconv.Itoa(region.StartLine) + " (region-local trace): " + f.Reason
			findings = append(findings, f)
		}
	}
	return findings
}
