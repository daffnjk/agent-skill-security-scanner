package main

import (
	"io"
	"os"
	"path/filepath"

	"github.com/daffnjk/agent-skill-security-scanner/internal/v39"
)

func writeMetadata(mode, baseOutput, outputDir string, overlays []v39.OverlayResult) error {
	if mode != modeOff {
		if err := v39.WriteOverlayMetadata(outputDir, overlays); err != nil {
			return err
		}
	} else if err := removeIfPresent(filepath.Join(outputDir, "analysis-metadata.jsonl")); err != nil {
		return err
	}
	return copyIfPresent(filepath.Join(baseOutput, "scan-metadata.jsonl"), filepath.Join(outputDir, "scan-metadata.jsonl"))
}

func copyIfPresent(source, destination string) error {
	in, err := os.Open(source)
	if os.IsNotExist(err) {
		return removeIfPresent(destination)
	}
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	tmp := destination + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return replaceLocalFile(tmp, destination)
}

func replaceLocalFile(tmp, destination string) error {
	if err := os.Rename(tmp, destination); err == nil {
		return nil
	}
	if err := os.Remove(destination); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, destination); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func removeIfPresent(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
