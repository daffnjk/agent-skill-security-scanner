package v39

import (
	"path/filepath"
	"strings"
)

func shouldSkipDir(name string) bool {
	switch strings.ToLower(name) {
	case ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".cache", "target", "dist", "coverage":
		return true
	default:
		return false
	}
}

func isTextCandidate(path string) bool {
	lower := strings.ToLower(path)
	base := filepath.Base(lower)
	if containsAny(base, []string{"dockerfile", "makefile", "jenkinsfile", "procfile", "skill.md", "manifest", "settings.json", "mcp.json", ".envrc"}) {
		return true
	}
	switch filepath.Ext(lower) {
	case ".md", ".mdc", ".prompt", ".prompty", ".txt", ".rst", ".json", ".jsonl", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".xml", ".html", ".htm", ".svg", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".pyw", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".go", ".rs", ".java", ".kt", ".rb", ".php", ".pl", ".lua", ".swift", ".c", ".cc", ".cpp", ".h", ".hpp", ".sql", ".tf", ".hcl", ".properties", ".gradle", ".plist", ".desktop", ".service", ".timer":
		return true
	default:
		return false
	}
}

func logicalPath(name string) string {
	if index := strings.LastIndex(name, "!"); index >= 0 && index+1 < len(name) {
		return name[index+1:]
	}
	return name
}

func isInstructionPath(path string) bool {
	base := filepath.Base(path)
	return base == "skill.md" || strings.HasSuffix(path, ".mdc") || strings.HasSuffix(path, ".prompt") || strings.HasSuffix(path, ".prompty") || strings.Contains(path, ".cursor/rules/") || strings.Contains(path, ".claude/")
}

func isPrimarySkillInstruction(path string) bool {
	return filepath.Base(path) == "skill.md" || strings.HasSuffix(path, ".mdc") || strings.HasSuffix(path, ".prompt") || strings.HasSuffix(path, ".prompty")
}

func isMetadataPath(path string) bool {
	base := filepath.Base(path)
	return strings.Contains(base, "manifest") || base == "package.json" || base == "mcp.json" || base == "settings.json" || strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".toml")
}

func isExecutablePath(path string) bool {
	if isInstructionPath(path) {
		return false
	}
	base := filepath.Base(path)
	if containsAny(base, []string{"dockerfile", "makefile", "jenkinsfile", "procfile"}) || strings.Contains(path, ".github/workflows/") || strings.Contains(path, ".husky/") {
		return true
	}
	switch filepath.Ext(path) {
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".pyw", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".go", ".rs", ".java", ".kt", ".rb", ".php", ".pl", ".lua", ".swift", ".c", ".cc", ".cpp", ".sql", ".tf", ".gradle", ".plist", ".desktop", ".service", ".timer":
		return true
	default:
		return false
	}
}

func isBenignTrainingContext(lower string) bool {
	return containsAny(lower, []string{"security training example", "example only", "do not run", "for documentation", "educational example", "demonstration only"})
}
