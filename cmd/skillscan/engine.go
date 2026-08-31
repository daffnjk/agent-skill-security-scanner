package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func resolveEngine() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("SKILLSCAN_ENGINE")); configured != "" {
		return validateEnginePath(configured)
	}
	if executable, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(executable), "skillscan-engine")
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return validateEnginePath(candidate)
		}
	}
	if candidate, err := exec.LookPath("skillscan-engine"); err == nil {
		return validateEnginePath(candidate)
	}
	return "", fmt.Errorf("skillscan-engine not found; set SKILLSCAN_ENGINE")
}

func runEngine(ctx context.Context, engine, inputDir, outputDir string, competition bool) (int, error) {
	cmd := exec.CommandContext(ctx, engine, inputDir, outputDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if competition {
		cmd.Env = setEnv(cmd.Env, "SKILLSCAN_ALLOW_PARTIAL", "1")
	}
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), err
	}
	return 2, err
}

func validateEnginePath(candidate string) (string, error) {
	resolved, err := exec.LookPath(candidate)
	if err != nil {
		return "", err
	}
	resolved, err = canonicalExistingPath(resolved)
	if err != nil {
		return "", err
	}
	if wrapper, wrapperErr := os.Executable(); wrapperErr == nil {
		if wrapper, wrapperErr = canonicalExistingPath(wrapper); wrapperErr == nil && wrapper == resolved {
			return "", fmt.Errorf("base engine resolves to the v39 wrapper itself")
		}
	}
	return resolved, nil
}

func setEnv(environment []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(environment)+1)
	for _, item := range environment {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+value)
}
