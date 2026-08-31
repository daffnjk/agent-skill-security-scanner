package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/daffnjk/agent-skill-security-scanner/internal/v39"
)

const (
	defaultInputDir  = "/data/skills"
	defaultOutputDir = "/output"

	modeEnforce = "enforce"
	modeObserve = "observe"
	modeOff     = "off"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) (exitCode int) {
	defer func() {
		if recovered := recover(); recovered != nil {
			_, _ = fmt.Fprintf(os.Stderr, "v39 wrapper panic: %v\n%s", recovered, debug.Stack())
			exitCode = 2
		}
	}()

	if len(args) == 1 {
		switch args[0] {
		case "--version", "version":
			fmt.Println(v39.Version)
			return 0
		case "--help", "-h", "help":
			printUsage(os.Stdout)
			return 0
		}
	}
	if len(args) > 2 {
		printUsage(os.Stderr)
		return 2
	}

	inputDir := getenv("SKILLS_DIR", defaultInputDir)
	outputDir := getenv("OUTPUT_DIR", defaultOutputDir)
	if len(args) > 0 && args[0] != "" {
		inputDir = args[0]
	}
	if len(args) > 1 && args[1] != "" {
		outputDir = args[1]
	}
	if info, err := os.Stat(inputDir); err != nil || !info.IsDir() {
		_, _ = fmt.Fprintf(os.Stderr, "invalid input directory %s: %v\n", inputDir, err)
		return 2
	}
	if overlaps, err := outputInsideInput(inputDir, outputDir); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "validate input/output paths: %v\n", err)
		return 2
	} else if overlaps {
		_, _ = fmt.Fprintln(os.Stderr, "output directory must not be inside the input directory")
		return 2
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create output directory: %v\n", err)
		return 2
	}

	mode, err := overlayMode()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "invalid v39 mode: %v\n", err)
		return 2
	}
	engine, err := resolveEngine()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "resolve base engine: %v\n", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	workDir, err := os.MkdirTemp("", "skillscan-v39-")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create temporary directory: %v\n", err)
		return 2
	}
	defer os.RemoveAll(workDir)
	baseOutput := filepath.Join(workDir, "base-output")
	if err := os.MkdirAll(baseOutput, 0o755); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create base output: %v\n", err)
		return 2
	}

	competition := strings.EqualFold(os.Getenv("SKILLSCAN_PROFILE"), "competition") || os.Getenv("SKILLSCAN_ALLOW_PARTIAL") == "1"
	engineExit, err := runEngine(ctx, engine, inputDir, baseOutput, competition)
	if err != nil && engineExit != 3 {
		_, _ = fmt.Fprintf(os.Stderr, "base engine failed: %v\n", err)
		return 2
	}
	if ctx.Err() != nil {
		_, _ = fmt.Fprintf(os.Stderr, "scan interrupted: %v\n", ctx.Err())
		return 2
	}

	baseRows, err := v39.ReadResults(filepath.Join(baseOutput, "results.jsonl"))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "read base results: %v\n", err)
		return 2
	}
	var overlays []v39.OverlayResult
	if mode != modeOff {
		overlays, err = v39.AnalyzeInput(inputDir, v39.DefaultLimits())
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "v39 overlay analysis failed: %v\n", err)
			return 2
		}
	}
	merged := baseRows
	if mode == modeEnforce {
		merged = v39.MergeAll(baseRows, overlays)
	}
	if err := v39.WriteResultsAtomic(outputDir, merged); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "write merged results: %v\n", err)
		return 2
	}
	if err := writeMetadata(mode, baseOutput, outputDir, overlays); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "write scan metadata: %v\n", err)
		return 2
	}

	incompleteOverlay := false
	for _, overlay := range overlays {
		if !overlay.Stats.Complete {
			incompleteOverlay = true
			break
		}
	}
	if !competition && (engineExit == 3 || mode == modeEnforce && incompleteOverlay) {
		return 3
	}
	return 0
}
