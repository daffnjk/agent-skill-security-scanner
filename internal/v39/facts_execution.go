package v39

func (context factContext) executionFacts() []Fact {
	lower := context.lower
	executable := context.executable
	remoteFetch := containsAny(lower, []string{
		"curl ", "wget ", "requests.get", "http.get", "client.get", "urlopen(", "fetch(", "download",
		"raw.githubusercontent.com", "gist.githubusercontent.com",
	}) && containsAny(lower, []string{"http://", "https://"})
	commandExec := containsAny(lower, []string{
		"os.system(", "subprocess.", "child_process", "execsync", "spawn(", "eval(", "exec(",
		"runtime.getruntime().exec", "processbuilder", "shell=true", "| bash", "| sh", "bash -c", "sh -c", "powershell -encodedcommand",
	})
	instructionExec := context.instruction && containsAny(lower, []string{
		"run the executable", "paste into terminal", "copy-paste", "execute the command", "run this command", "must be installed", "before proceeding",
	}) && containsAny(lower, []string{"http://", "https://", "curl", "wget", ".exe", ".sh", "bash", "powershell"})
	installTrigger := detectInstallTrigger(context.pathLower, lower)
	unsafeDeserialize := containsAny(lower, []string{
		"yaml.load", "yaml.unsafe_load", "!!python/object/apply", "pickle.load", "pickle.loads", "marshal.loads", "dill.loads",
		"joblib.load", "objectinputstream", "readobject", "node-serialize", "unserialize(",
	})
	untrustedInput := containsAny(lower, []string{
		"requests.get", "urlopen(", "fetch(", "input(", "argv", "readfile", "open(", "config", "manifest", "base64.b64decode", "atob(",
	})
	dynamicLoad := containsAny(lower, []string{
		"import(", "require(", "reload(", "source <", "source ", "loadplugin", "registerplugin", "dlopen", "eval(", "exec(",
	})
	if context.metadata && (installTrigger || commandExec || remoteFetch || unsafeDeserialize || dynamicLoad) {
		executable = true
	}
	updateTrigger := containsAny(lower, []string{
		"auto_update", "self_update", "hot reload", "fs.watch", "watchdog", "after scan", "post-scan", "check for updates",
		"remote_config", "instruction_url", "prompt_url",
	})
	hostControl := containsAny(lower, []string{
		"/var/run/docker.sock", "privileged: true", "hostnetwork: true", "hostpid: true", "169.254.169.254",
		"ws://localhost", "http://localhost", "https://localhost", "ws://127.0.0.1", "http://127.0.0.1",
		"jsonrpc", "tools/call", "kubectl exec", "docker exec", "redis://", "etcd://", "consul://",
	})

	facts := make([]Fact, 0, 8)
	if remoteFetch {
		facts = append(facts, context.fact(FactRemoteFetch, "remote content is downloaded", executable, context.instruction, true))
	}
	if commandExec || instructionExec {
		facts = append(facts, context.fact(FactCommandExec, "commands or downloaded helpers are executed", executable && commandExec, context.instruction || instructionExec, true))
	}
	if installTrigger {
		facts = append(facts, context.fact(FactInstallTrigger, "package, build, CI, or project lifecycle can trigger execution", true, false, true))
	}
	if unsafeDeserialize {
		facts = append(facts, context.fact(FactUnsafeDeserialize, "unsafe deserialization primitive is present", executable, context.instruction, true))
	}
	if untrustedInput {
		strong := remoteFetch || containsAny(lower, []string{"input(", "argv", "open(", "readfile"})
		facts = append(facts, context.fact(FactUntrustedInput, "loader consumes file, configuration, or network-controlled input", executable, context.instruction, strong))
	}
	if dynamicLoad {
		strong := commandExec || detectOutboundSink(lower) || remoteFetch || updateTrigger
		facts = append(facts, context.fact(FactDynamicLoad, "content is dynamically loaded or evaluated", executable, context.instruction, strong))
	}
	if updateTrigger {
		facts = append(facts, context.fact(FactUpdateTrigger, "post-scan, hot-reload, or self-update trigger is present", executable, context.instruction, true))
	}
	if hostControl {
		facts = append(facts, context.fact(FactHostControl, "host, container, metadata, or local control surface is reachable", executable || context.metadata, context.instruction, true))
	}
	return facts
}
