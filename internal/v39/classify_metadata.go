package v39

func classifyMetadataBehaviors(lookup factLookup) Chain {
	execFact, hasExec := lookup.first(FactCommandExec, strongActive)
	outbound, hasOutbound := lookup.first(FactOutboundSink, strongExecutable)
	fetch, hasFetch := lookup.first(FactRemoteFetch, strongActive)
	dynamic, hasDynamic := lookup.first(FactDynamicLoad, strongActive)
	hidden, hasHidden := lookup.first(FactHiddenPrompt, nil)

	instructionSecret, hasInstructionSecret := lookup.first(FactSecretSource, instructionOnly)
	instructionWorkspace, hasInstructionWorkspace := lookup.first(FactWorkspaceSource, instructionOnly)
	instructionOutbound, hasInstructionOutbound := lookup.first(FactOutboundSink, instructionOnly)
	instructionSource := Fact{}
	hasInstructionSource := false
	if hasInstructionSecret {
		instructionSource, hasInstructionSource = instructionSecret, true
	} else if hasInstructionWorkspace {
		instructionSource, hasInstructionSource = instructionWorkspace, true
	}
	instructionChain := hasInstructionSource && hasInstructionOutbound &&
		relatedFacts(hidden, instructionSource) && relatedFacts(hidden, instructionOutbound)
	promptExecChain := hasExec && relatedFacts(hidden, execFact)
	if hasHidden && (instructionChain || promptExecChain) {
		facts := []Fact{hidden}
		if instructionChain {
			facts = append(facts, instructionSource, instructionOutbound)
		} else {
			facts = append(facts, execFact)
		}
		return Chain{Name: "metadata-prompt-injection", Verdict: "malicious", Category: "ast04", Confidence: 0.97, Facts: facts}
	}

	instructionFetch, hasInstructionFetch := lookup.first(FactRemoteFetch, instructionOnly)
	instructionExec, hasInstructionExec := lookup.first(FactCommandExec, instructionOnly)
	if hasInstructionFetch && hasInstructionExec {
		return chain("social-engineering-payload", "malicious", "ast01", 0.97, instructionFetch, instructionExec)
	}

	safeClaim, hasSafeClaim := lookup.first(FactSafeClaim, nil)
	if hasSafeClaim && (hasOutbound || hasExec || hasFetch) {
		facts := []Fact{safeClaim}
		if hasOutbound {
			facts = append(facts, outbound)
		} else if hasExec {
			facts = append(facts, execFact)
		} else {
			facts = append(facts, fetch)
		}
		return Chain{Name: "metadata-runtime-mismatch", Verdict: "malicious", Category: "ast04", Confidence: 0.95, Facts: facts}
	}

	obfuscation, hasObfuscation := lookup.first(FactObfuscation, strongActive)
	if hasObfuscation && (hasExec || hasOutbound || hasDynamic) {
		facts := []Fact{obfuscation}
		if hasExec {
			facts = append(facts, execFact)
		} else if hasOutbound {
			facts = append(facts, outbound)
		} else {
			facts = append(facts, dynamic)
		}
		return Chain{Name: "decoded-evasion-payload", Verdict: "malicious", Category: "ast08", Confidence: 0.94, Facts: facts}
	}

	if broad, ok := lookup.first(FactBroadPermission, nil); ok {
		return chain("over-privileged-manifest", "suspicious", "ast03", 0.78, broad)
	}
	if hasHidden {
		return chain("hidden-instruction", "suspicious", "ast04", 0.76, hidden)
	}
	return Chain{}
}
