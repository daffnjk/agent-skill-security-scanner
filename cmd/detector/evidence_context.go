package main

import (
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
