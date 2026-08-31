package v39

type factLookup struct {
	facts []Fact
}

func (lookup factLookup) first(kind FactKind, predicate func(Fact) bool) (Fact, bool) {
	for _, fact := range lookup.facts {
		if fact.Kind == kind && (predicate == nil || predicate(fact)) {
			return fact, true
		}
	}
	return Fact{}, false
}

func strongActive(fact Fact) bool {
	return fact.Strong && (fact.Executable || fact.Instruction)
}

func strongExecutable(fact Fact) bool {
	return fact.Strong && fact.Executable
}

func instructionOnly(fact Fact) bool {
	return fact.Instruction && !fact.Executable
}

func ClassifyFacts(facts []Fact) Chain {
	lookup := factLookup{facts: facts}
	for _, classifier := range []func(factLookup) Chain{
		classifyPrimaryOutcomes,
		classifyRiskMechanisms,
		classifyMetadataBehaviors,
	} {
		if chain := classifier(lookup); chain.Verdict != "" {
			return chain
		}
	}
	return Chain{}
}
