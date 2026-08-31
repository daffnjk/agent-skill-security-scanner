package v39

func classifyPrimaryOutcomes(lookup factLookup) Chain {
	install, hasInstall := lookup.first(FactInstallTrigger, strongActive)
	fetch, hasFetch := lookup.first(FactRemoteFetch, strongActive)
	execFact, hasExec := lookup.first(FactCommandExec, strongActive)
	if hasInstall && hasFetch && hasExec {
		return chain("lifecycle-remote-exec", "malicious", "ast02", 0.99, install, fetch, execFact)
	}

	secret, hasSecret := lookup.first(FactSecretSource, strongExecutable)
	outbound, hasOutbound := lookup.first(FactOutboundSink, strongExecutable)
	if hasSecret && hasOutbound {
		return chain("credential-exfiltration", "malicious", "ast01", 0.99, secret, outbound)
	}
	workspace, hasWorkspace := lookup.first(FactWorkspaceSource, strongExecutable)
	if hasWorkspace && hasOutbound {
		return chain("workspace-exfiltration", "malicious", "ast01", 0.98, workspace, outbound)
	}

	persistence, hasPersistence := lookup.first(FactPersistence, strongActive)
	if hasPersistence && (hasExec || hasFetch) {
		facts := []Fact{persistence}
		if hasFetch {
			facts = append(facts, fetch)
		}
		if hasExec {
			facts = append(facts, execFact)
		}
		return Chain{Name: "persistence-payload", Verdict: "malicious", Category: "ast01", Confidence: 0.98, Facts: facts}
	}
	return Chain{}
}
