package v39

func classifyRiskMechanisms(lookup factLookup) Chain {
	execFact, hasExec := lookup.first(FactCommandExec, strongActive)
	outbound, hasOutbound := lookup.first(FactOutboundSink, strongExecutable)
	fetch, hasFetch := lookup.first(FactRemoteFetch, strongActive)

	unsafe, hasUnsafe := lookup.first(FactUnsafeDeserialize, strongActive)
	untrusted, hasUntrusted := lookup.first(FactUntrustedInput, strongActive)
	if hasUnsafe && (hasUntrusted || hasExec) {
		facts := []Fact{unsafe}
		if hasUntrusted {
			facts = append(facts, untrusted)
		}
		if hasExec {
			facts = append(facts, execFact)
		}
		return Chain{Name: "unsafe-deserialization", Verdict: "malicious", Category: "ast05", Confidence: 0.98, Facts: facts}
	}

	host, hasHost := lookup.first(FactHostControl, strongActive)
	broad, hasBroad := lookup.first(FactBroadPermission, nil)
	if hasHost && (hasExec || hasOutbound || hasBroad) {
		facts := []Fact{host}
		if hasExec {
			facts = append(facts, execFact)
		} else if hasOutbound {
			facts = append(facts, outbound)
		} else {
			facts = append(facts, broad)
		}
		return Chain{Name: "isolation-boundary-control", Verdict: "malicious", Category: "ast06", Confidence: 0.97, Facts: facts}
	}

	update, hasUpdate := lookup.first(FactUpdateTrigger, strongActive)
	dynamic, hasDynamic := lookup.first(FactDynamicLoad, strongActive)
	if hasUpdate && hasFetch && hasDynamic {
		return chain("remote-update-drift", "malicious", "ast07", 0.97, update, fetch, dynamic)
	}
	return Chain{}
}
