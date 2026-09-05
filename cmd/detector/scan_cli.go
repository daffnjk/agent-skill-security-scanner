package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type ScanSeal struct {
	SchemaVersion int               `json:"schema_version"`
	RunID         string            `json:"run_id"`
	SkillCount    int               `json:"skill_count"`
	Reports       map[string]string `json:"reports"`
}

func runCLI(args []string) int {
	flags := flag.NewFlagSet("skillscan", flag.ContinueOnError)
	mode := flags.String("mode", "auto", "input mode: auto, single, or collection")
	single := flags.Bool("single", false, "scan the input directory as one Skill")
	collection := flags.Bool("collection", false, "scan immediate child directories as Skills")
	timeout := flags.Duration("timeout", 5*time.Minute, "whole-run deadline, including discovery and analysis")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *single && *collection {
		fmt.Fprintln(os.Stderr, "--single and --collection are mutually exclusive")
		return 2
	}
	if (*single || *collection) && *mode != "auto" {
		fmt.Fprintln(os.Stderr, "use either --mode or a mode alias")
		return 2
	}
	if *single {
		*mode = "single"
	}
	if *collection {
		*mode = "collection"
	}
	if *mode != "auto" && *mode != "single" && *mode != "collection" {
		fmt.Fprintln(os.Stderr, "invalid input mode")
		return 2
	}
	if *timeout <= 0 || *timeout > 24*time.Hour || flags.NArg() > 2 {
		fmt.Fprintln(os.Stderr, "invalid timeout or positional arguments")
		return 2
	}
	input := getenv("SKILLS_DIR", defaultInputDir)
	output := getenv("OUTPUT_DIR", defaultOutputDir)
	if flags.NArg() > 0 {
		input = flags.Arg(0)
	}
	if flags.NArg() > 1 {
		output = flags.Arg(1)
	}
	out, err := prepareOutput(input, output)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prepare output:", err)
		return 2
	}
	// This function is the process entrypoint. Returning on expiry lets main call
	// os.Exit, so a blocked target read or slow analysis cannot outlive the deadline.
	finished := make(chan int, 1)
	go func() { finished <- runScan(input, out, *mode) }()
	timer := time.NewTimer(*timeout)
	defer timer.Stop()
	select {
	case status := <-finished:
		return status
	case <-timer.C:
		fmt.Fprintln(os.Stderr, "scan deadline exceeded; reports without a verified seal must not be consumed")
		return 2
	}
}

func runScan(input, output, mode string) int {
	failRun := func(err error) int { fmt.Fprintln(os.Stderr, "scan failed:", err); return 2 }
	skills, err := discoverSkillsMode(input, mode)
	if err != nil {
		return failRun(err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return failRun(err)
	}
	runID := hex.EncodeToString(id)
	rows := make([]Result, 0, len(skills))
	scans := make([]ScanMetadata, 0, len(skills))
	audits := make([]AnalysisMetadata, 0, len(skills))
	reportBytes := [3]int{}
	visited := 0
	for _, skill := range skills {
		report := safeAnalyzeSkill(skill.Path)
		scan := newScanMetadata(skill.ID, report.Scan)
		scan.RunID = runID
		audit := newAnalysisMetadata(skill.ID, report)
		audit.RunID = runID
		res := Result{skill.ID, report.Verdict, report.EngineCategory, report.EvidenceText}
		for i, obj := range []any{res, scan, audit} {
			encoded, err := json.Marshal(obj)
			if err != nil {
				return failRun(err)
			}
			reportBytes[i] += len(encoded) + 1
			if reportBytes[i] > maxReportBytes {
				return failRun(fmt.Errorf("collection report byte budget exceeded"))
			}
		}
		visited += scan.EntriesVisited
		if visited > maxCollectionVisitedEntries {
			return failRun(fmt.Errorf("collection visited entry budget exceeded"))
		}
		scans = append(scans, scan)
		audits = append(audits, audit)
		rows = append(rows, res)
	}
	if err := writeJSONLinesAtomic(output, "results.jsonl", rows); err != nil {
		return failRun(err)
	}
	if err := writeScanMetadata(output, scans); err != nil {
		return failRun(err)
	}
	if err := writeAnalysisMetadata(output, audits); err != nil {
		return failRun(err)
	}
	seal := ScanSeal{SchemaVersion: 2, RunID: runID, SkillCount: len(skills), Reports: map[string]string{}}
	for _, name := range []string{"results.jsonl", "scan-metadata.jsonl", "analysis-metadata.jsonl"} {
		data, err := os.ReadFile(filepath.Join(output, name))
		if err != nil {
			return failRun(err)
		}
		seal.Reports[name] = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	if err := writeJSONLinesAtomic(output, "scan-complete.json", []ScanSeal{seal}); err != nil {
		return failRun(err)
	}
	if n := countIncompleteScans(scans); n > 0 && !partialScansAllowed() {
		fmt.Fprintf(os.Stderr, "scan incomplete: %d skill(s); see scan-metadata.jsonl\n", n)
		return incompleteScanExitCode
	}
	return 0
}
