package v39

func (context factContext) metadataFacts() []Fact {
	lower := context.lower
	hiddenPrompt := containsAny(lower, []string{
		"ignore previous", "ignore all previous", "system prompt", "developer message", "hidden prompt", "do not disclose",
		"display:none", "visibility:hidden", "zero width", "\u200b", "\u202e",
	})
	safeClaim := context.metadata && containsAny(lower, []string{
		"network\":false", "network: false", "shell\":false", "shell: false", "risk_tier\":\"l0", "risk_tier: l0",
		"passed clean", "scan_status\":\"passed", "no network", "local only",
	})
	broadPermission := context.metadata && detectBroadPermission(lower)
	persistence := containsAny(lower, []string{
		"soul.md", "memory.md", "claude.md", "agents.md", "crontab", "systemd", "runatload", "launchagents", "startup", "authorized_keys",
	}) && containsAny(lower, []string{"write", "append", ">>", "install", "copy", "create", "echo"})
	obfuscation := context.material.Decoded || containsAny(lower, []string{
		"base64.b64decode", "atob(", "fromcharcode", "charcodeat", "decodehex", "url decode", "gzip", "zlib",
	})
	commandExec := containsAny(lower, []string{"os.system(", "subprocess.", "child_process", "eval(", "exec(", "| bash", "| sh"})
	outboundCode := detectOutboundSink(lower)

	facts := make([]Fact, 0, 5)
	if hiddenPrompt {
		facts = append(facts, context.fact(FactHiddenPrompt, "hidden or policy-overriding instruction is present", context.executable, context.instruction || context.metadata, true))
	}
	if safeClaim {
		facts = append(facts, context.fact(FactSafeClaim, "metadata claims a safe, local, or clean execution profile", false, true, true))
	}
	if broadPermission {
		facts = append(facts, context.fact(FactBroadPermission, "manifest grants broad network, file, root, shell, or auto-approval capability", false, true, true))
	}
	if persistence {
		facts = append(facts, context.fact(FactPersistence, "agent identity or host startup persistence is modified", context.executable, context.instruction, true))
	}
	if obfuscation {
		facts = append(facts, context.fact(FactObfuscation, "encoded or reconstructed material requires normalization", context.executable, context.instruction, context.material.Decoded || commandExec || outboundCode))
	}
	return facts
}
