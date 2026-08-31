package v39

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func discoverSkills(input string) ([]skillPath, error) {
	entries, err := os.ReadDir(input)
	if err != nil {
		return nil, err
	}
	var skills []skillPath
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			skills = append(skills, skillPath{ID: entry.Name(), Path: filepath.Join(input, entry.Name())})
		}
	}
	if len(skills) == 0 {
		skills = append(skills, skillPath{ID: filepath.Base(filepath.Clean(input)), Path: input})
	}
	sort.Slice(skills, func(i, j int) bool { return skills[i].ID < skills[j].ID })
	return skills, nil
}

func readSampled(path string, size, limit int64) ([]byte, bool, error) {
	if size <= limit {
		data, err := os.ReadFile(path)
		return data, false, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	headSize := limit / 2
	tailSize := limit - headSize
	head := make([]byte, headSize)
	if _, err := io.ReadFull(file, head); err != nil {
		return nil, false, err
	}
	if _, err := file.Seek(size-tailSize, io.SeekStart); err != nil {
		return nil, false, err
	}
	tail := make([]byte, tailSize)
	if _, err := io.ReadFull(file, tail); err != nil {
		return nil, false, err
	}
	return append(head, tail...), true, nil
}
