package v39

import "strings"

func detectOutboundSink(lower string) bool {
	if containsAny(lower, []string{
		"requests.post", "http.post", "http::post", "client.post", "axios.post", "reqwest::blocking::client::new().post",
		".post(\"http", ".post('http", "websocket.send", ".send(json", "sendbeacon", "curl -d", "curl --data",
		"http.newrequest(\"post", "http.post(\"", "method: \"post\"", "method:'post'", "method: 'post'",
	}) {
		return true
	}
	if strings.Contains(lower, "fetch(") && containsAny(lower, []string{"method:\"post\"", "method: \"post\"", "method:'post'", "method: 'post'", "body:", "body ="}) {
		return true
	}
	if strings.Contains(lower, "https.request") && containsAny(lower, []string{"method: 'post'", "method: \"post\"", ".write(", "body"}) {
		return true
	}
	return strings.Contains(lower, "webhook.site") && containsAny(lower, []string{"post", "send", "upload", "curl"})
}

func detectInstallTrigger(pathLower, lower string) bool {
	switch {
	case strings.Contains(pathLower, "package.json"):
		return containsAny(lower, []string{"postinstall", "preinstall", "prepare", "prepublish", "install-script"})
	case strings.Contains(pathLower, "setup.py"), strings.Contains(pathLower, "pyproject.toml"):
		return containsAny(lower, []string{"build-system", "build_backend", "build-backend", "cmdclass", "setup_requires", "install_requires"})
	case strings.Contains(pathLower, "dockerfile"):
		return containsAny(lower, []string{"add http://", "add https://", "run curl ", "run wget ", "entrypoint", "cmd ["})
	case strings.Contains(pathLower, ".github/workflows"), strings.Contains(pathLower, ".gitlab-ci"), strings.Contains(pathLower, "jenkinsfile"), strings.Contains(pathLower, "circleci"), strings.Contains(pathLower, "buildkite"):
		return containsAny(lower, []string{"run:", "script:", "steps", "pipeline"})
	case strings.Contains(pathLower, "makefile"), strings.Contains(pathLower, "build.rs"):
		return containsAny(lower, []string{"curl ", "wget ", "http://", "https://", "command", "exec"})
	case strings.Contains(pathLower, ".husky"), strings.Contains(pathLower, "pre-commit"), strings.Contains(pathLower, "devcontainer"), strings.Contains(pathLower, ".envrc"):
		return containsAny(lower, []string{"command", "run", "source", "curl", "wget", "npx", "bash", "sh "})
	default:
		return false
	}
}

func detectBroadPermission(lower string) bool {
	if containsAny(lower, []string{"<all_urls>", "0.0.0.0/0", "filesystem\":\"*", "filesystem: *", "files\":\"*", "files: *", "privileged\":true", "privileged: true", "run_as_root\":true", "run_as_root: true", "shell\":true", "shell: true", "autoapprove\":[\"*\"]", "autoapprove: [\"*\"]"}) {
		return true
	}
	networkEnabled := containsAny(lower, []string{"network\":true", "network: true"})
	if !networkEnabled {
		return false
	}
	if containsAny(lower, []string{"write\":false", "write: false"}) && containsAny(lower, []string{"allow\":[\"https://", "allow: [https://", "allowed_domains"}) && !containsAny(lower, []string{"\"*\"", "0.0.0.0/0", "<all_urls>"}) {
		return false
	}
	return !containsAny(lower, []string{"allow\":[\"https://", "allow: [https://", "allowed_domains\":[\""}) || containsAny(lower, []string{"\"*\"", "0.0.0.0/0", "<all_urls>"})
}

func looksLikeExecutableContent(lower string) bool {
	return containsAny(lower, []string{
		"requests.", "subprocess.", "os.system(", "child_process", "fetch(", "eval(", "exec(",
		"curl ", "wget ", "| bash", "| sh", "powershell", "yaml.load", "pickle.load",
		"postinstall", "preinstall", "entrypoint", "websocket", "reqwest",
	})
}

func containsAny(value string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
