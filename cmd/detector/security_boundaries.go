package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxDiscoveryEntries         = 100000
	maxReportBytes              = 32 * 1024 * 1024
	maxCollectionVisitedEntries = 1000000
	maxSkills                   = 4096
	maxVisitedEntries           = 100000
	maxDirectoryDepth           = 64
)

// canonicalPath resolves existing ancestors, including when the final path is new.
func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	probe := abs
	var tail []string
	for {
		_, err = os.Lstat(probe)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", err
		}
		tail = append(tail, filepath.Base(probe))
		probe = parent
	}
	resolved, err := filepath.EvalSymlinks(probe)
	if err != nil {
		return "", err
	}
	for i := len(tail) - 1; i >= 0; i-- {
		resolved = filepath.Join(resolved, tail[i])
	}
	return resolved, nil
}

func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

// Output parents must be trusted and must not be modified concurrently.
func prepareOutput(input, output string) (string, error) {
	in, err := canonicalPath(input)
	if err != nil {
		return "", err
	}
	if info, e := os.Lstat(output); e == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("output directory must not be a symlink")
	} else if e != nil && !os.IsNotExist(e) {
		return "", e
	}
	out, err := canonicalPath(output)
	if err != nil {
		return "", err
	}
	if pathContains(in, out) || pathContains(out, in) {
		return "", fmt.Errorf("input and output directories must not overlap")
	}
	if err := os.MkdirAll(out, 0700); err != nil {
		return "", err
	}
	// Removing a link removes the link, never its target. Invalidate the previous
	// commit marker before validation/scanning; a failed run cannot reuse its seal.
	if err := os.Remove(filepath.Join(out, "scan-complete.json")); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return out, nil
}

func writeJSONLinesAtomic[T any](dir, name string, rows []T) (err error) {
	if filepath.Base(name) != name {
		return fmt.Errorf("invalid report name")
	}
	f, err := os.CreateTemp(dir, ".skillscan-"+name+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = f.Close(); _ = os.Remove(tmp) }()
	encoder := json.NewEncoder(&boundedReportWriter{writer: f, remaining: maxReportBytes})
	encoder.SetEscapeHTML(false)
	for _, row := range rows {
		if err = encoder.Encode(row); err != nil {
			return err
		}
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	// Do not follow a pre-existing report link. Rename atomically replaces the
	// directory entry on supported platforms; failure never removes the old file.
	return os.Rename(tmp, filepath.Join(dir, name))
}

func discoverSkillsMode(input, mode string) ([]skillPath, error) {
	if mode != "auto" && mode != "single" && mode != "collection" {
		return nil, fmt.Errorf("invalid input mode %q", mode)
	}
	if err := validateInputRoot(input); err != nil {
		return nil, err
	}
	single := func() []skillPath { return []skillPath{{ID: filepath.Base(filepath.Clean(input)), Path: input}} }
	if mode == "single" {
		return single(), nil
	}
	if mode == "auto" {
		if _, err := os.Lstat(filepath.Join(input, "SKILL.md")); err == nil {
			return single(), nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	dir, err := os.Open(input)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(maxDiscoveryEntries + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > maxDiscoveryEntries {
		return nil, fmt.Errorf("discovery entry limit %d exceeded", maxDiscoveryEntries)
	}
	var out []skillPath
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		// Include links as explicit targets: the collector will flag them incomplete,
		// without following them. They must not disappear from collection metadata.
		if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			continue
		}
		if len(out) == maxSkills {
			return nil, fmt.Errorf("skill limit %d exceeded", maxSkills)
		}
		out = append(out, skillPath{ID: entry.Name(), Path: filepath.Join(input, entry.Name())})
	}
	if len(out) == 0 {
		if mode == "collection" {
			return nil, fmt.Errorf("collection contains no visible Skill directories")
		}
		return single(), nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Unlike filepath.WalkDir, this walker never materializes an unbounded directory.
// Candidate processing is sorted later. Budget-exhausted scans fail closed.
func walkDirBounded(root string, entryLimit, depthLimit int, visit fs.WalkDirFunc) error {
	seen := 0
	var walk func(string, fs.DirEntry, int) error
	walk = func(path string, entry fs.DirEntry, depth int) error {
		if seen >= entryLimit {
			return fmt.Errorf("visited entry limit %d exceeded", entryLimit)
		}
		seen++
		if depth > depthLimit {
			return fmt.Errorf("directory depth limit %d exceeded", depthLimit)
		}
		if err := visit(path, entry, nil); err != nil {
			if err == filepath.SkipDir {
				return nil
			}
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		dir, err := os.Open(path)
		if err != nil {
			return visit(path, entry, err)
		}
		defer dir.Close()
		for {
			entries, err := dir.ReadDir(256)
			for _, child := range entries {
				if e := walk(filepath.Join(path, child.Name()), child, depth+1); e != nil {
					return e
				}
			}
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return visit(path, entry, err)
			}
		}
	}
	info, err := os.Lstat(root)
	if err != nil {
		return visit(root, nil, err)
	}
	err = walk(root, fs.FileInfoToDirEntry(info), 0)
	if err == filepath.SkipAll {
		return nil
	}
	return err
}

// Report limits match the independent gate and prevent unbounded retained output.
type boundedReportWriter struct {
	writer    io.Writer
	remaining int
}

func (w *boundedReportWriter) Write(data []byte) (int, error) {
	if len(data) > w.remaining {
		return 0, fmt.Errorf("report byte budget exceeded")
	}
	n, err := w.writer.Write(data)
	w.remaining -= n
	return n, err
}
