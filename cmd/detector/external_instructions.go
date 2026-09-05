package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// URLs are inventoried but NEVER fetched. Query/userinfo/fragment are redacted;
// their hash still allows exact matching without publishing embedded secrets.
type ExternalInstructionDependency struct {
	URLTruncated    bool   `json:"url_truncated,omitempty"`
	RuleID          string `json:"rule_id"`
	File            string `json:"file"`
	StartLine       int    `json:"start_line,omitempty"`
	PositionScope   string `json:"position_scope"`
	URL             string `json:"url"`
	URLSHA256       string `json:"url_sha256"`
	Kind            string `json:"kind"`
	VersionPinned   bool   `json:"version_pinned"`
	ContentReviewed bool   `json:"content_reviewed"`
	TaxonomyVersion string `json:"taxonomy_version"`
	Category        string `json:"category,omitempty"`
}

var externalURLRE = regexp.MustCompile(`(?i)https?://[^\s<>"'\x60\[\]()]+`)
var delegatedInstructionRE = regexp.MustCompile(`(?i)(\b(follow|obey|execute|apply|run)\b.{0,100}\b(instructions|steps|commands|directions)\b|\b(instructions|commands)\b.{0,100}\b(follow|execute|apply|run)\b|按照.{0,60}(指令|步骤)|遵循.{0,60}(指令|步骤)|执行.{0,60}(指令|命令))`)
var negatedInstructionRE = regexp.MustCompile(`(?i)(\b(do not|don't|never|must not|should not)\b|不要|不得|切勿)`)
var pinnedRevisionRE = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

func inventoryExternalInstructions(file, text string) []ExternalInstructionDependency {
	if !isDocPath(file) {
		return nil
	}
	deps := make([]ExternalInstructionDependency, 0)
	previous := ""
	for i, line := range strings.Split(text, "\n") {
		if externalFormattingLine(line) {
			continue
		}
		for _, clause := range externalInstructionClauses(line) {
			if externalFormattingLine(clause) {
				continue
			}
			urls := externalURLRE.FindAllString(clause, 257)
			known, delegated := externalDirectiveState(clause)
			continuation := len(urls) > 0 && externalLinkContinuation(clause)
			if !known && continuation {
				_, delegated = externalDirectiveState(previous)
			}
			// Carry the nearest substantive context across formatting and link
			// lists, but reset at other prose, headings or explicit negation.
			if !continuation {
				previous = clause
			}
			for _, raw := range urls {
				if len(deps) >= 256 {
					return deps
				}
				raw = strings.TrimRight(raw, ".,;:，。；！？!?")
				u, err := url.Parse(raw)
				if err != nil || u.Hostname() == "" {
					continue
				}
				pinned := false
				parts := strings.Split(strings.Trim(u.Path, "/"), "/")
				if u.Hostname() == "raw.githubusercontent.com" && len(parts) >= 4 {
					pinned = pinnedRevisionRE.MatchString(parts[2])
				}
				if u.Hostname() == "github.com" && len(parts) >= 5 && (parts[2] == "blob" || parts[2] == "raw") {
					pinned = pinnedRevisionRE.MatchString(parts[3])
				}
				u.User = nil
				u.RawQuery = ""
				u.ForceQuery = false
				u.Fragment = ""
				dep := ExternalInstructionDependency{RuleID: "SKILL-EXTERNAL-REFERENCE", File: file, StartLine: i + 1, PositionScope: "original", URL: u.String(), URLSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(raw))), Kind: "reference", VersionPinned: pinned, ContentReviewed: false, TaxonomyVersion: externalTaxonomyVersion}
				if delegated {
					dep.RuleID = "SKILL-EXTERNAL-INSTRUCTIONS"
					dep.Kind = "instruction-delegation"
					dep.Category = "ast05"
				}
				if len(dep.URL) > 2048 {
					dep.URL = dep.URL[:2048]
					dep.URLTruncated = true
				}
				deps = append(deps, dep)
			}
		}
	}
	return deps
}

// Clause punctuation inside a URL is data, not a prose boundary. Mask URL bytes
// while finding boundaries, retaining original offsets for evidence and hashes.
var externalClauseBoundaryRE = regexp.MustCompile(`(?i)[;；，。！？!?]|[.,](?:\s|$)|\b(?:but|however|instead)\b|但是|然而|而是`)
var externalMarkdownLabelRE = regexp.MustCompile(`\[[^\]]*\]`)
var externalFenceLineRE = regexp.MustCompile("^(`{3,}|~{3,})[[:alnum:]_-]*$")

func externalInstructionClauses(line string) []string {
	masked := []byte(line)
	for _, span := range externalURLRE.FindAllStringIndex(line, -1) {
		end := span[0] + len(strings.TrimRight(line[span[0]:span[1]], ".,;:，。；！？!?"))
		for i := span[0]; i < end; i++ {
			masked[i] = ' '
		}
	}
	clauses := make([]string, 0, 1)
	start := 0
	for _, boundary := range externalClauseBoundaryRE.FindAllIndex(masked, -1) {
		clauses = append(clauses, line[start:boundary[0]])
		start = boundary[1]
	}
	return append(clauses, line[start:])
}

func externalDirectiveState(clause string) (known, active bool) {
	// A URL's path or query must not supply instructions or negation words.
	prose := externalURLRE.ReplaceAllString(clause, "URL")
	known = delegatedInstructionRE.MatchString(prose)
	return known, known && !negatedInstructionRE.MatchString(prose)
}

func externalFormattingLine(line string) bool {
	line = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(line), ">"))
	if strings.Trim(line, " \t\r*_-=|`~+.0123456789") == "" || externalFenceLineRE.MatchString(line) {
		return true
	}
	switch strings.ToLower(line) {
	case "<br>", "<br/>", "<br />":
		return true
	}
	return false
}

func externalLinkContinuation(clause string) bool {
	text := externalURLRE.ReplaceAllString(clause, "")
	text = externalMarkdownLabelRE.ReplaceAllString(text, "")
	return strings.Trim(text, " \t\r\n<>[](){}*_-+>|:`~0123456789.") == ""
}

// Keep the original URL case, unlike the detector's normalized matching view.
func inventoryText(data []byte) string {
	start := 0
	var order binary.ByteOrder
	if len(data) >= 2 && data[0] == 0xff && data[1] == 0xfe {
		order = binary.LittleEndian
		start = 2
	}
	if len(data) >= 2 && data[0] == 0xfe && data[1] == 0xff {
		order = binary.BigEndian
		start = 2
	}
	if order == nil && len(data) >= 4 {
		if data[1] == 0 && data[3] == 0 {
			order = binary.LittleEndian
		}
		if data[0] == 0 && data[2] == 0 {
			order = binary.BigEndian
		}
	}
	if order != nil {
		units := make([]uint16, 0, (len(data)-start)/2)
		for i := start; i+1 < len(data); i += 2 {
			units = append(units, order.Uint16(data[i:i+2]))
		}
		return string(utf16.Decode(units))
	}
	if utf8.Valid(data) {
		return string(data)
	}
	return ""
}
