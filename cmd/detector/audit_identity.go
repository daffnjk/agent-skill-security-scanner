package main

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
)

const externalTaxonomyVersion = "owasp-ast-v1-public-review-observed-2026-09-05"
const legacyTaxonomyVersion = "skillscan-legacy-v41"

var scannerVersion = "v0.3.0-dev"
var buildCommit = "unknown"

// This fingerprints the actual compiled rule/collection source, not a manually
// maintained version label. Tests and documentation are deliberately excluded.
//
//go:embed main.go hardening.go behavior_ir.go analysis_metadata.go audit_identity.go coverage.go external_instructions.go security_boundaries.go scan_cli.go
var scannerSources embed.FS

type ScannerIdentity struct {
	Version         string `json:"version"`
	EngineVersion   string `json:"engine_version"`
	Commit          string `json:"commit"`
	RulesetHash     string `json:"ruleset_hash"`
	TaxonomyVersion string `json:"taxonomy_version"`
}

var identityOnce sync.Once
var identity ScannerIdentity

func currentScannerIdentity() ScannerIdentity {
	identityOnce.Do(func() {
		h := sha256.New()
		entries, _ := scannerSources.ReadDir(".")
		for _, e := range entries {
			b, _ := scannerSources.ReadFile(e.Name())
			fmt.Fprintf(h, "%d:%s:%d:", len(e.Name()), e.Name(), len(b))
			_, _ = h.Write(b)
		}
		commit := buildCommit
		if info, ok := debug.ReadBuildInfo(); ok && commit == "unknown" {
			for _, setting := range info.Settings {
				if setting.Key == "vcs.revision" {
					commit = setting.Value
				}
			}
		}
		identity = ScannerIdentity{Version: scannerVersion, EngineVersion: "v41-hardening.1", Commit: commit, RulesetHash: fmt.Sprintf("sha256:%x", h.Sum(nil)), TaxonomyVersion: legacyTaxonomyVersion}
	})
	return identity
}

func findingRuleID(f Finding) string {
	if f.RuleID != "" {
		return f.RuleID
	}
	// Historical/in-process callers can still create a finding without an ID.
	// Never describe this compatibility fallback as a stable rule identifier.
	return "LEGACY-" + legacyFindingRuleID(f)
}

func findingFingerprint(f Finding) string {
	basis := fmt.Sprintf("%s\x00%s\x00%s\x00%d:%d", findingRuleID(f), f.Category, f.File, f.StartLine, f.EndLine)
	if f.StartLine == 0 {
		basis += "\x00" + f.Reason
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(basis)))
}

func ruleIDStability(f Finding) string {
	if strings.HasPrefix(findingRuleID(f), "LEGACY-") {
		return "legacy-evidence-derived"
	}
	return "explicit"
}
