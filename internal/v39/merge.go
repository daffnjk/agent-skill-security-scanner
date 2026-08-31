package v39

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	minimumMaliciousPromotionConfidence = 0.94
	minimumCategoryOverrideConfidence   = 0.97
)

// Merge applies only monotonic, high-confidence overlay changes. It never
// downgrades a base result. Missing base rows fail closed as suspicious.
func Merge(base BaseResult, overlay OverlayResult) BaseResult {
	if base.SkillID == "" {
		base = BaseResult{
			SkillID:        overlay.SkillID,
			Verdict:        "suspicious",
			EngineCategory: "ast08",
			EvidenceText:   "OWASP AST08: base engine did not emit a result row for this Skill",
		}
	}
	base = normalizeBase(base)
	overlay.Verdict = strings.ToLower(strings.TrimSpace(overlay.Verdict))
	overlay.Category = normalizeOverlayCategory(overlay.Verdict, overlay.Category)

	switch {
	case overlay.Verdict == "malicious" && overlay.Confidence >= minimumMaliciousPromotionConfidence && (base.Verdict == "benign" || base.Verdict == "suspicious"):
		base.Verdict = "malicious"
		base.EngineCategory = overlay.Category
		base.EvidenceText = overlay.Evidence
	case overlay.Verdict == "suspicious" && base.Verdict == "benign":
		base.Verdict = "suspicious"
		base.EngineCategory = overlay.Category
		base.EvidenceText = overlay.Evidence
	case base.Verdict == "malicious" && overlay.Verdict == "malicious":
		if strings.EqualFold(base.EngineCategory, overlay.Category) {
			if overlay.Confidence >= minimumMaliciousPromotionConfidence && strings.TrimSpace(overlay.Evidence) != "" {
				base.EvidenceText = overlay.Evidence
			}
		} else if overlay.Confidence >= minimumCategoryOverrideConfidence && shouldOverrideCategory(base.EngineCategory, overlay.Category, overlay.Facts) {
			base.EngineCategory = overlay.Category
			base.EvidenceText = overlay.Evidence
		}
	}
	return normalizeBase(base)
}

func shouldOverrideCategory(baseCategory, overlayCategory string, facts []Fact) bool {
	baseCategory = strings.ToLower(baseCategory)
	overlayCategory = strings.ToLower(overlayCategory)
	if overlayCategory == "ast01" || overlayCategory == "ast02" || overlayCategory == "ast05" || overlayCategory == "ast06" || overlayCategory == "ast07" {
		switch baseCategory {
		case "ast03", "ast08", "ast09", "ast10":
			return hasStrongExecutableOutcome(facts)
		case "ast04":
			// Keep AST04 for pure metadata/instruction attacks. Override only when
			// the overlay observed a concrete executable outbound outcome.
			return hasStrongExecutableOutcome(facts) && hasExecutableFact(facts, FactOutboundSink)
		}
	}
	return false
}

func hasStrongExecutableOutcome(facts []Fact) bool {
	for _, fact := range facts {
		if fact.Strong && fact.Executable && (fact.Kind == FactOutboundSink || fact.Kind == FactCommandExec || fact.Kind == FactHostControl || fact.Kind == FactUnsafeDeserialize) {
			return true
		}
	}
	return false
}

func hasExecutableFact(facts []Fact, kind FactKind) bool {
	for _, fact := range facts {
		if fact.Kind == kind && fact.Strong && fact.Executable {
			return true
		}
	}
	return false
}

func normalizeOverlayCategory(verdict, category string) string {
	verdict = strings.ToLower(strings.TrimSpace(verdict))
	category = strings.ToLower(strings.TrimSpace(category))
	if verdict == "benign" {
		return "benign"
	}
	if validASTCategory(category) {
		return category
	}
	return "ast08"
}

func normalizeBase(base BaseResult) BaseResult {
	base.Verdict = strings.ToLower(strings.TrimSpace(base.Verdict))
	base.EngineCategory = strings.ToLower(strings.TrimSpace(base.EngineCategory))
	if base.Verdict != "benign" && base.Verdict != "suspicious" && base.Verdict != "malicious" {
		base.Verdict = "suspicious"
	}
	if base.Verdict == "benign" {
		base.EngineCategory = "benign"
	} else if !validASTCategory(base.EngineCategory) {
		base.EngineCategory = "ast08"
	}
	if strings.TrimSpace(base.EvidenceText) == "" {
		base.EvidenceText = "scanner emitted no evidence text"
	}
	return base
}

func validASTCategory(category string) bool {
	if len(category) != 5 || !strings.HasPrefix(category, "ast") {
		return false
	}
	return category[3] == '0' && category[4] >= '1' && category[4] <= '9' || category == "ast10"
}

func ReadResults(path string) ([]BaseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []BaseResult
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(f)
	buffer := make([]byte, 64<<10)
	scanner.Buffer(buffer, 2<<20)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var row BaseResult
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, fmt.Errorf("decode base result: %w", err)
		}
		if row.SkillID == "" {
			return nil, fmt.Errorf("base result missing skill_id")
		}
		if _, duplicate := seen[row.SkillID]; duplicate {
			return nil, fmt.Errorf("base result contains duplicate skill_id %q", row.SkillID)
		}
		seen[row.SkillID] = struct{}{}
		out = append(out, normalizeBase(row))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("base engine emitted no results")
	}
	return out, nil
}

func MergeAll(base []BaseResult, overlays []OverlayResult) []BaseResult {
	byID := make(map[string]OverlayResult, len(overlays))
	for _, overlay := range overlays {
		byID[overlay.SkillID] = overlay
	}
	out := make([]BaseResult, 0, len(base)+len(overlays))
	seen := make(map[string]struct{}, len(base))
	for _, row := range base {
		seen[row.SkillID] = struct{}{}
		if overlay, ok := byID[row.SkillID]; ok {
			row = Merge(row, overlay)
		}
		out = append(out, row)
	}
	var missing []string
	for _, overlay := range overlays {
		if _, ok := seen[overlay.SkillID]; !ok {
			missing = append(missing, overlay.SkillID)
		}
	}
	sort.Strings(missing)
	for _, skillID := range missing {
		out = append(out, Merge(BaseResult{}, byID[skillID]))
	}
	return out
}

func WriteResultsAtomic(outputDir string, rows []BaseResult) error {
	return writeJSONLAtomic(filepath.Join(outputDir, "results.jsonl"), func(enc *json.Encoder) error {
		for _, row := range rows {
			if err := enc.Encode(normalizeBase(row)); err != nil {
				return err
			}
		}
		return nil
	})
}

func WriteOverlayMetadata(outputDir string, rows []OverlayResult) error {
	return writeJSONLAtomic(filepath.Join(outputDir, "analysis-metadata.jsonl"), func(enc *json.Encoder) error {
		for _, row := range rows {
			if err := enc.Encode(row); err != nil {
				return err
			}
		}
		return nil
	})
}

func writeJSONLAtomic(path string, encode func(*json.Encoder) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	if err := encode(enc); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return replaceFile(tmp, path)
}

func replaceFile(tmp, path string) error {
	if err := os.Rename(tmp, path); err == nil {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
