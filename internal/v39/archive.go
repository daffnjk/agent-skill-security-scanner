package v39

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
)

type archiveWalker struct {
	limits       Limits
	stats        *ScanStats
	materials    []Material
	expanded     int64
	entries      int
	maxByRatio   int64
	decodedBytes int64
	variants     int
}

// ExtractArchive statically expands supported archives into virtual materials.
// Paths are never written to disk. Traversal, symlink, entry-count, size,
// recursion, and compression-ratio limits are enforced before analysis.
func ExtractArchive(name string, data []byte, limits Limits, stats *ScanStats) []Material {
	if stats == nil {
		local := newStats()
		stats = &local
	}
	maxByRatio := int64(len(data)) * limits.MaxCompressionRatio
	if maxByRatio < 1<<20 {
		maxByRatio = 1 << 20
	}
	if maxByRatio > limits.MaxArchiveExpandedBytes {
		maxByRatio = limits.MaxArchiveExpandedBytes
	}
	w := &archiveWalker{limits: limits, stats: stats, maxByRatio: maxByRatio}
	if err := w.walk(name, data, 0); err != nil {
		stats.markIncomplete("archive materialization incomplete: " + err.Error())
	}
	stats.ArchiveEntries += w.entries
	stats.ArchiveBytes += w.expanded
	return w.materials
}

func (w *archiveWalker) walk(name string, data []byte, depth int) error {
	if depth > w.limits.MaxArchiveDepth {
		return fmt.Errorf("archive recursion limit reached")
	}
	if int64(len(data)) > w.limits.MaxArchiveBytes {
		return fmt.Errorf("archive exceeds %d bytes", w.limits.MaxArchiveBytes)
	}
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".zip") || isZIP(data):
		return w.walkZIP(name, data, depth)
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return w.walkTarGzip(name, data, depth)
	case strings.HasSuffix(lower, ".tar"):
		return w.walkTar(name, bytes.NewReader(data), depth)
	case strings.HasSuffix(lower, ".gz") || isGzip(data):
		return w.walkGzip(name, data, depth)
	default:
		return fmt.Errorf("unsupported archive format")
	}
}

func (w *archiveWalker) walkZIP(name string, data []byte, depth int) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	for _, entry := range zr.File {
		if err := w.reserveEntry(); err != nil {
			return err
		}
		clean, ok := safeArchivePath(entry.Name)
		if !ok {
			w.stats.markIncomplete("archive traversal path skipped")
			continue
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		if entry.Mode()&fs.ModeSymlink != 0 {
			w.stats.markIncomplete("archive symlink entry skipped")
			continue
		}
		if entry.UncompressedSize64 > uint64(w.limits.MaxFileBytes) && !isArchiveName(clean) {
			w.stats.markTruncated("archive entry exceeds per-file limit")
			continue
		}
		r, err := entry.Open()
		if err != nil {
			w.stats.ReadErrors++
			w.stats.markIncomplete("archive entry open failed")
			continue
		}
		entryData, readErr := w.readArchiveEntry(r, clean)
		_ = r.Close()
		if readErr != nil {
			continue
		}
		w.consume(name+"!"+clean, entryData, depth)
	}
	return nil
}

func (w *archiveWalker) walkTarGzip(name string, data []byte, depth int) error {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gr.Close()
	return w.walkTar(name, gr, depth)
}

func (w *archiveWalker) walkTar(name string, r io.Reader, depth int) error {
	remaining := w.remaining()
	if remaining <= 0 {
		return fmt.Errorf("archive expanded-byte limit reached")
	}
	tr := tar.NewReader(io.LimitReader(r, remaining+1))
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := w.reserveEntry(); err != nil {
			return err
		}
		clean, ok := safeArchivePath(header.Name)
		if !ok {
			w.stats.markIncomplete("archive traversal path skipped")
			continue
		}
		if header.FileInfo().IsDir() {
			continue
		}
		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			w.stats.markIncomplete("archive link entry skipped")
			continue
		}
		if header.Size > w.limits.MaxFileBytes && !isArchiveName(clean) {
			w.stats.markTruncated("archive entry exceeds per-file limit")
			if _, err := io.CopyN(io.Discard, tr, header.Size); err != nil && err != io.EOF {
				return err
			}
			continue
		}
		entryData, readErr := w.readArchiveEntry(tr, clean)
		if readErr != nil {
			continue
		}
		w.consume(name+"!"+clean, entryData, depth)
	}
}

func (w *archiveWalker) walkGzip(name string, data []byte, depth int) error {
	if err := w.reserveEntry(); err != nil {
		return err
	}
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gr.Close()
	entryName := strings.TrimSuffix(name, path.Ext(name))
	entryData, err := w.readArchiveEntry(gr, entryName)
	if err != nil {
		return err
	}
	w.consume(name+"!"+path.Base(entryName), entryData, depth)
	return nil
}

func (w *archiveWalker) reserveEntry() error {
	if w.entries >= w.limits.MaxArchiveEntries {
		w.stats.markTruncated("archive entry limit reached")
		return fmt.Errorf("archive entry limit reached")
	}
	w.entries++
	return nil
}

func (w *archiveWalker) readArchiveEntry(r io.Reader, name string) ([]byte, error) {
	limit := w.limits.MaxFileBytes
	if isArchiveName(name) {
		limit = w.limits.MaxArchiveBytes
	}
	remaining := w.remaining()
	if limit > remaining {
		limit = remaining
	}
	if limit <= 0 {
		w.stats.markTruncated("archive expanded-byte limit reached")
		return nil, io.ErrUnexpectedEOF
	}
	data, err := readLimited(r, limit)
	if err != nil {
		w.stats.markTruncated("archive entry read limit reached")
		return nil, err
	}
	w.expanded += int64(len(data))
	return data, nil
}

func (w *archiveWalker) consume(virtualPath string, data []byte, depth int) {
	if isArchiveName(virtualPath) || isZIP(data) || isGzip(data) {
		if depth >= w.limits.MaxArchiveDepth {
			w.stats.markTruncated("nested archive depth limit reached")
			return
		}
		if err := w.walk(virtualPath, data, depth+1); err != nil {
			w.stats.markIncomplete("nested archive materialization incomplete")
		}
		return
	}
	materialLimits := w.limits
	remainingVariants := w.limits.MaxDecodedVariantsPerSkill - w.variants
	remainingDecodedBytes := w.limits.MaxDecodedBytesPerSkill - w.decodedBytes
	if remainingVariants <= 0 || remainingDecodedBytes <= 0 {
		materialLimits.MaxDecodeDepth = 0
		materialLimits.MaxDecodedVariantsPerFile = 0
		materialLimits.MaxDecodedBytesPerFile = 0
	} else {
		if materialLimits.MaxDecodedVariantsPerFile > remainingVariants {
			materialLimits.MaxDecodedVariantsPerFile = remainingVariants
		}
		if materialLimits.MaxDecodedBytesPerFile > remainingDecodedBytes {
			materialLimits.MaxDecodedBytesPerFile = remainingDecodedBytes
		}
	}
	for _, material := range MaterializeText(virtualPath, data, materialLimits) {
		material.FromArchive = true
		w.materials = append(w.materials, material)
		if material.Decoded {
			w.variants++
			w.decodedBytes += int64(len(material.Text))
		}
	}
	if w.variants >= w.limits.MaxDecodedVariantsPerSkill || w.decodedBytes >= w.limits.MaxDecodedBytesPerSkill {
		w.stats.markTruncated("archive decoded-material budget reached")
	}
}

func (w *archiveWalker) remaining() int64 {
	remaining := w.maxByRatio - w.expanded
	if global := w.limits.MaxArchiveExpandedBytes - w.expanded; global < remaining {
		remaining = global
	}
	return remaining
}

func safeArchivePath(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	clean := path.Clean(name)
	if clean == "." || clean == "" || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}

func isArchiveName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".tar") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".gz")
}

func isZIP(data []byte) bool {
	return len(data) >= 4 && data[0] == 'P' && data[1] == 'K' && (data[2] == 3 || data[2] == 5 || data[2] == 7)
}

func isGzip(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}
