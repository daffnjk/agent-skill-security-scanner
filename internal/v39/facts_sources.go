package v39

func (context factContext) sourceAndSinkFacts() []Fact {
	lower := context.lower
	secretMarker := containsAny(lower, []string{
		"aws_secret_access_key", "aws_access_key_id", "github_token", "gh_token", "api_key", "apikey", "access_token", "refresh_token",
		"session_token", "id_rsa", ".ssh/", "credentials", ".env", "cookie", "login data", "local state", "wallet.dat", "seed phrase",
		"mnemonic", "private key", ".npmrc", ".pypirc", ".netrc", ".vault-token", "kubernetes.io/serviceaccount/token",
	})
	secretRead := containsAny(lower, []string{
		"open(\".env", "open('.env", "readfile", "read_file", "read_to_string", "read_text(", ".read_text(", "fs.readfile",
		"os.getenv(", "getenv(", "os.environ", "process.env", "env::var", "std::env", "chrome.cookies.get", "cookies.getall",
		"keychain", "credential_process", "login data", "local state", "wallet.dat",
	}) || context.instruction && containsAny(lower, []string{"read ", "collect ", "extract ", "access ", "steal ", "harvest "})
	secret := secretMarker && secretRead
	workspace := containsAny(lower, []string{
		"workspace files", "source code", "project files", "findfiles(", "read all files", "glob(\"**/*", "walkdir", "filepath.walk",
	})
	outboundCode := detectOutboundSink(lower)
	outboundInstruction := containsAny(lower, []string{"send ", "upload ", "transmit ", "report ", "post "}) &&
		containsAny(lower, []string{"http://", "https://", "webhook", "external server", "remote endpoint"})
	outboundPayload := containsAny(lower, []string{
		"data=secret", "data = secret", "json=secret", "json = secret", "body: secret", "body=secret", "body(secret", ".body(s)",
		"json.stringify(process.env", "json.stringify({cookie", "json.stringify(cookies", "credentials", ".env", "seed phrase", "private key",
	})
	outboundStrong := outboundInstruction || outboundCode && (context.material.Decoded || context.material.FromArchive || containsAny(lower, []string{"webhook", "exfil", "upload"}) ||
		outboundPayload && (secretMarker || workspace))

	facts := make([]Fact, 0, 3)
	if secret {
		facts = append(facts, context.fact(FactSecretSource, "credential or secret material is actively read", context.executable, context.instruction, secretRead))
	}
	if workspace {
		facts = append(facts, context.fact(FactWorkspaceSource, "workspace or source-code material is enumerated", context.executable, context.instruction, true))
	}
	if outboundCode || outboundInstruction {
		facts = append(facts, context.fact(FactOutboundSink, "data is sent to a remote endpoint", context.executable && outboundCode, context.instruction || outboundInstruction, outboundStrong))
	}
	return facts
}
