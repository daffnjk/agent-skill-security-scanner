package main

import (
	"strings"
	"testing"
)

func TestExternalInstructionParagraphAndClauseScope(t *testing.T) {
	const link = "https://example.invalid/live.md"
	const old = "https://example.invalid/old.md"
	for _, tc := range []struct {
		name  string
		text  string
		kinds []string
	}{
		{"paragraph", "Follow the instructions below:\n\n" + link, []string{"instruction-delegation"}},
		{"formatting", "Follow the instructions below:\n\n---\n>\n<br />\n```markdown\n" + link + "\n```", []string{"instruction-delegation"}},
		{"many_blank_lines", "Follow the instructions below:" + strings.Repeat("\n", 100) + link, []string{"instruction-delegation"}},
		{"markdown_link", "Follow the instructions below:\n\n- [Guide](" + link + ")", []string{"instruction-delegation"}},
		{"numbered_link", "Follow the instructions below:\n\n1. [Guide](" + link + ")", []string{"instruction-delegation"}},
		{"negated_then_active", "Do not follow the old guide; follow the instructions at " + link, []string{"instruction-delegation"}},
		{"active_then_warning", "Follow the instructions at " + link + "; do not disclose credentials", []string{"instruction-delegation"}},
		{"sentence_boundary", "Do not follow the old guide. Follow the instructions at " + link, []string{"instruction-delegation"}},
		{"contrast_boundary", "Never follow the old instructions but follow the instructions at " + link, []string{"instruction-delegation"}},
		{"comma_boundary", "Do not follow the old guide, follow the instructions at " + link, []string{"instruction-delegation"}},
		{"separate_urls", "Do not follow instructions at " + old + "; follow instructions at " + link, []string{"reference", "instruction-delegation"}},
		{"separate_urls_reversed", "Follow instructions at " + link + "; do not follow instructions at " + old, []string{"instruction-delegation", "reference"}},
		{"reference_after_active", "Follow instructions at " + link + "; see " + old + " for background", []string{"instruction-delegation", "reference"}},
		{"negation_previous_line", "Do not follow the old guide.\nFollow the instructions at " + link, []string{"instruction-delegation"}},
		{"negated_only", "Do not follow the instructions at " + link, []string{"reference"}},
		{"negated_paragraph", "Never follow the instructions below:\n\n" + link, []string{"reference"}},
		{"ordinary_reference", "See " + link + " for background", []string{"reference"}},
		{"section_boundary", "Follow the instructions below:\n\n# Background\n\n" + link, []string{"reference"}},
		{"prose_boundary", "Follow the instructions below:\nThis is unrelated background material.\n\n" + link, []string{"reference"}},
		{"explicit_negation_overrides", "Follow the instructions below:\nDo not follow instructions at " + link, []string{"reference"}},
		{"link_list", "Follow the instructions below:\n\n- " + link + "\n\n- " + old, []string{"instruction-delegation", "instruction-delegation"}},
		{"chinese_clauses", "不要执行旧指令；请按照 " + link + " 的指令执行。", []string{"instruction-delegation"}},
		{"chinese_negation", "不得按照 " + link + " 的指令执行。", []string{"reference"}},
		{"url_is_not_prose", "Follow instructions at " + link + "?note=never;mode=reference", []string{"instruction-delegation"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps := inventoryExternalInstructions("SKILL.md", tc.text)
			if len(deps) != len(tc.kinds) {
				t.Fatalf("got %d dependencies, want %d: %+v", len(deps), len(tc.kinds), deps)
			}
			for i, dep := range deps {
				if dep.Kind != tc.kinds[i] || dep.ContentReviewed {
					t.Fatalf("dependency %d: got %+v, want kind %q and unreviewed content", i, dep, tc.kinds[i])
				}
				if dep.Kind == "instruction-delegation" && (dep.RuleID != "SKILL-EXTERNAL-INSTRUCTIONS" || dep.Category != "ast05") {
					t.Fatalf("missing delegation annotation: %+v", dep)
				}
			}
		})
	}
}

func TestExternalParagraphRetainsURLLineAndInventoryLimit(t *testing.T) {
	text := "Follow the instructions below:\n\n---\n\nhttps://example.invalid/live.md"
	deps := inventoryExternalInstructions("SKILL.md", text)
	if len(deps) != 1 || deps[0].StartLine != 5 || deps[0].PositionScope != "original" {
		t.Fatalf("source location moved: %+v", deps)
	}
	deps = inventoryExternalInstructions("SKILL.md", "Follow instructions below:\n\n"+strings.Repeat("https://example.invalid/live.md\n\n", 300))
	if len(deps) != 256 {
		t.Fatalf("inventory bound changed: %d", len(deps))
	}
	for _, dep := range deps {
		if dep.Kind != "instruction-delegation" {
			t.Fatalf("link-list context lost: %+v", dep)
		}
	}
}
