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
	lines := strings.Split(text, "\n")
	deps := make([]ExternalInstructionDependency, 0)
	for i, line := range lines {
		urls := externalURLRE.FindAllString(line, 257)
		if len(urls) == 0 {
			continue
		}
		delegated := false
		for j := max(0, i-1); j <= i && j < len(lines); j++ {
			// A warning elsewhere cannot suppress a separate active instruction.
			if delegatedInstructionRE.MatchString(lines[j]) && !negatedInstructionRE.MatchString(lines[j]) {
				delegated = true
			}
		}
		for _, raw := range urls {
			if len(deps) >= 256 {
				return deps
			}
			raw = strings.TrimRight(raw, ".,;:")
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
	return deps
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
