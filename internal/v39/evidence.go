package v39

import (
	"fmt"
	"strings"
)

func relatedFacts(a, b Fact) bool {
	if a.Path == b.Path {
		return true
	}
	// Decoded and archived materials keep their virtual origin in Path; only
	// correlate across distinct paths when both facts are explicit instructions.
	return a.Instruction && b.Instruction
}

func chain(name, verdict, category string, confidence float64, facts ...Fact) Chain {
	return Chain{Name: name, Verdict: verdict, Category: category, Confidence: confidence, Facts: facts}
}

func buildEvidence(chain Chain) string {
	parts := make([]string, 0, len(chain.Facts))
	seen := map[string]struct{}{}
	materialized := false
	for _, fact := range chain.Facts {
		item := fact.Path + ": " + fact.Detail
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		parts = append(parts, item)
		materialized = materialized || fact.Decoded || fact.Archive
		if len(parts) == 3 {
			break
		}
	}
	evidence := fmt.Sprintf("OWASP %s behavior graph (%s): %s", strings.ToUpper(chain.Category), chain.Name, strings.Join(parts, " -> "))
	if materialized {
		evidence += "; evidence includes bounded decoded or archive material"
	}
	if len(evidence) > 900 {
		evidence = evidence[:897] + "..."
	}
	return evidence
}
