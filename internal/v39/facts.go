package v39

import "strings"

type factContext struct {
	material    Material
	lower       string
	pathLower   string
	logical     string
	instruction bool
	metadata    bool
	executable  bool
}

func newFactContext(material Material) factContext {
	lower := strings.ToLower(material.Text)
	pathLower := strings.ToLower(material.Path)
	logical := strings.ToLower(logicalPath(material.Path))
	instruction := isInstructionPath(logical)
	metadata := isMetadataPath(logical)
	executable := isExecutablePath(logical) || material.Decoded && looksLikeExecutableContent(lower)
	if isBenignTrainingContext(lower) && !isPrimarySkillInstruction(pathLower) && !material.Decoded {
		executable = false
		instruction = false
	}
	return factContext{
		material:    material,
		lower:       lower,
		pathLower:   pathLower,
		logical:     logical,
		instruction: instruction,
		metadata:    metadata,
		executable:  executable,
	}
}

func (context factContext) fact(kind FactKind, detail string, executable, instruction, strong bool) Fact {
	return Fact{
		Kind:        kind,
		Path:        context.material.Path,
		Detail:      detail,
		Executable:  executable,
		Instruction: instruction,
		Decoded:     context.material.Decoded,
		Archive:     context.material.FromArchive,
		Strong:      strong,
	}
}

func ExtractFacts(material Material) []Fact {
	context := newFactContext(material)
	facts := make([]Fact, 0, 16)
	facts = append(facts, context.sourceAndSinkFacts()...)
	facts = append(facts, context.executionFacts()...)
	facts = append(facts, context.metadataFacts()...)
	return facts
}
