package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func printUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, "usage: skillscan-v39 [skills-dir] [output-dir]")
	_, _ = fmt.Fprintln(writer, "environment: SKILLSCAN_ENGINE, SKILLSCAN_V39_MODE=enforce|observe|off, SKILLSCAN_PROFILE=competition")
}

func overlayMode() (string, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("SKILLSCAN_V39_MODE")))
	if mode == "" {
		return modeEnforce, nil
	}
	switch mode {
	case modeEnforce, modeObserve, modeOff:
		return mode, nil
	default:
		return "", fmt.Errorf("%q; expected enforce, observe, or off", mode)
	}
}

func outputInsideInput(inputDir, outputDir string) (bool, error) {
	inputCanonical, err := canonicalExistingPath(inputDir)
	if err != nil {
		return false, err
	}
	outputCanonical, err := canonicalProspectivePath(outputDir)
	if err != nil {
		return false, err
	}
	relative, err := filepath.Rel(inputCanonical, outputCanonical)
	if err != nil {
		return false, err
	}
	return relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)), nil
}

func canonicalExistingPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func canonicalProspectivePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := absolute
	var suffix []string
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved), nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return filepath.Clean(absolute), nil
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
