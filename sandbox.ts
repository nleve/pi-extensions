/**
 * Sandbox extension — prompt-driven allowed dirs plus OS-level bash sandboxing.
 *
 * Behavior:
 *   - read / write / edit auto-allow inside active dirs
 *     (current repo root + approved extra dirs)
 *   - outside-dir access prompts the user and can add the enclosing repo/dir
 *     for this command, this session, this project, or all projects
 *   - approved bash runs inside an OS-level sandbox when available
 *   - bash path prompting is best-effort UX; the OS sandbox is the hard
 *     enforcement boundary for bash
 *   - sensitive file access requires per-command confirmation
 *   - sensitive paths are handled by sandbox prompts before tool execution
 *   - high-risk bash commands require per-command or session-prefix approval
 *   - sandbox config/rules/extension writes are meta-protected
 *   - session-scoped sandbox state survives reloads via session custom entries
 *   - network/domain access can be learned at session/project/global scope
 *
 * Rule storage (project takes precedence over global):
 *   ~/.pi/agent/sandbox-rules.json          — global learned permissions
 *   <project>/.pi/sandbox-rules.json        — project-specific permissions
 *
 * OS sandbox config (project takes precedence over global):
 *   ~/.pi/agent/sandbox.json                — global execution constraints
 *   <project>/.pi/sandbox.json              — project-specific overrides
 *
 * Commands:
 *   /sandbox         — show current sandbox state
 *   /sandbox clear   — clear persisted rules (prompts for scope)
 */

import { basename, dirname, isAbsolute, relative, resolve } from "node:path";
import { existsSync, statSync } from "node:fs";
import { mkdir, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import {
	createBashTool,
	createLocalBashOperations,
	getAgentDir,
	type BashOperations,
	type ExtensionAPI,
} from "@mariozechner/pi-coding-agent";
import { showTransient, type Binding, type MenuSection } from "./sandbox/transient-menu";

// ── Constants ────────────────────────────────────────────────────────────────

const HOME = homedir();
const AGENT_DIR = getAgentDir();
const AUTH_FILE = resolve(AGENT_DIR, "auth.json");
const SANDBOX_RUNTIME_CWD = resolve(tmpdir(), "pi-sandbox-runtime");
const SANDBOX_STATE_CUSTOM_TYPE = "sandbox-state";
const SANDBOX_AGENT_CONSTRAINTS_EVENT = "sandbox:agent-constraints";

const SENSITIVE_DIRS = [
	resolve(HOME, ".ssh"),
	resolve(HOME, ".aws"),
	resolve(HOME, ".gnupg"),
	resolve(HOME, ".config", "gcloud"),
	resolve(HOME, ".config", "gh"),
	resolve(HOME, ".kube"),
];

const SENSITIVE_EXACT_FILES = new Set([
	resolve(HOME, ".netrc"),
	resolve(HOME, ".npmrc"),
	resolve(HOME, ".pypirc"),
	resolve(HOME, ".docker", "config.json"),
	resolve(HOME, ".kube", "config"),
	AUTH_FILE,
]);

const DANGEROUS_PATTERNS = [
	/\brm\s+(-rf?|--recursive)/i,
	/\bsudo\b/i,
	/\b(chmod|chown)\b.*777/i,
];

const CURL_UPLOAD_FLAGS = /(^|\s)(-T|--upload-file|-F|--form|--data(?:-ascii|-binary|-raw|-urlencode)?|--json)(\s|=|$)/;
const WGET_UPLOAD_FLAGS = /(^|\s)(--post-data|--post-file|--body-data|--body-file)(\s|=|$)/;
const DIRECT_WRITE_COMMANDS = new Set([
	"cp", "mv", "rm", "touch", "tee", "chmod", "chown", "ln", "install", "truncate", "dd",
]);
const SENSITIVE_SCAN_PRUNE_DIRS = [".git", "node_modules", ".next", "dist", "build", "target", ".venv", "venv"];
const IMPLICIT_BASH_READ_PATHS = ["/dev/null", "/dev/tty", "/dev/stdin", "/dev/stdout", "/dev/stderr"];

// ── Types ────────────────────────────────────────────────────────────────────

interface AgentConstraints {
	bash?: {
		allowPrefixes?: string[];
	};
}

interface AgentConstraintsEventData {
	agentName?: string;
	constraints?: AgentConstraints;
}

interface RulesFile {
	dirs: string[];
	readDirs?: string[];
	protectedDirs?: string[];
	protectedReadDirs?: string[];
	allowedDomains?: string[];
}

interface SandboxConfig extends SandboxRuntimeConfig {
	enabled?: boolean;
}

type Scope = "project" | "global";
type AllowScope = Scope | "session";
type AccessLevel = "read" | "full";

interface ProtectedPathInfo {
	id: string;
	label: string;
}

interface LoadedRulesFile {
	rules: RulesFile;
	exists: boolean;
	parseError?: string;
}

interface LoadedSandboxConfigPart {
	config: Partial<SandboxConfig>;
	exists: boolean;
	parseError?: string;
}

interface SessionStateData {
	version: 1;
	dirs: string[];
	readDirs: string[];
	protectedDirs: string[];
	protectedReadDirs: string[];
	highRiskPrefixes: string[];
	allowedDomains: string[];
}

type AccessBoundaryKind = "package" | "repo" | "directory";
type AccessBoundary = {
	dir: string;
	kind: AccessBoundaryKind;
	suggestions: Array<{ dir: string; kind: AccessBoundaryKind; label: string }>;
};

// ── Generic helpers ──────────────────────────────────────────────────────────

function unique<T>(items: T[]): T[] {
	return [...new Set(items)];
}

function expandHome(value: string): string {
	if (value === "~") return HOME;
	if (value.startsWith("~/")) return resolve(HOME, value.slice(2));
	return value;
}

function resolvePath(raw: string, cwd: string): string {
	const cleaned = expandHome(raw.startsWith("@") ? raw.slice(1) : raw);
	return isAbsolute(cleaned) ? cleaned : resolve(cwd, cleaned);
}

function isInsideDir(filePath: string, root: string): boolean {
	const rel = relative(root, filePath);
	return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function stripEnvAssignments(command: string): string {
	return command.replace(/^(\s*\w+=\S*\s*)*\s*/, "");
}

function stripOuterQuotes(token: string): string {
	const trimmed = token.trim();
	if (
		(trimmed.startsWith("\"") && trimmed.endsWith("\""))
		|| (trimmed.startsWith("'") && trimmed.endsWith("'"))
	) {
		return trimmed.slice(1, -1);
	}
	return trimmed;
}

function firstCommand(cmd: string): string {
	const stripped = stripEnvAssignments(cmd);
	return stripped.split(/[\s;|&<>]/)[0] ?? "";
}

function normalizePrefix(prefix: string): string {
	return prefix.trim().replace(/\s+/g, " ");
}

function matchesCommandPrefix(command: string, prefix: string): boolean {
	const normalized = normalizePrefix(prefix);
	const trimmed = normalizePrefix(stripEnvAssignments(command));
	return trimmed === normalized || trimmed.startsWith(normalized + " ");
}

function tokenize(command: string): string[] {
	return stripEnvAssignments(command).trim().split(/\s+/).filter(Boolean);
}

function stripHeredocBodies(command: string): string {
	const lines = command.split(/\r?\n/);
	const result: string[] = [];
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		result.push(line);

		const matches = [...line.matchAll(/<<(-)?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/g)];
		for (const match of matches) {
			const allowIndent = !!match[1];
			const delimiter = match[3];
			i += 1;
			while (i < lines.length) {
				const candidate = allowIndent ? lines[i].replace(/^\t+/, "") : lines[i];
				if (candidate.trimEnd() === delimiter) break;
				i += 1;
			}
		}
	}
	return result.join("\n");
}

function shellTokenize(command: string): string[] {
	const tokens: string[] = [];
	let current = "";
	let inSingle = false;
	let inDouble = false;
	let i = 0;

	while (i < command.length) {
		const ch = command[i];
		if (ch === "'" && !inDouble) {
			inSingle = !inSingle;
			current += ch;
			i++;
			continue;
		}
		if (ch === '"' && !inSingle) {
			inDouble = !inDouble;
			current += ch;
			i++;
			continue;
		}
		if (ch === "\\" && !inSingle && i + 1 < command.length) {
			current += ch + command[i + 1];
			i += 2;
			continue;
		}
		if (!inSingle && !inDouble && /\s/.test(ch)) {
			if (current) tokens.push(current);
			current = "";
			i++;
			continue;
		}
		current += ch;
		i++;
	}

	if (current) tokens.push(current);
	return tokens;
}

function inspectionTokens(command: string): string[] {
	const sanitized = stripHeredocBodies(stripEnvAssignments(command));
	const rawTokens = shellTokenize(sanitized);
	if (rawTokens.length === 0) return rawTokens;

	const interpreter = rawTokens[0] === "env"
		? rawTokens.find((token, index) => index > 0 && !token.startsWith("-"))
		: rawTokens[0];
	if (!interpreter) return rawTokens;

	const skipNextArgFlags = new Set(["-e", "--eval", "-c", "--command"]);
	const interpretersWithInlineScriptFlags = new Set([
		"node", "python", "python3", "ruby", "perl", "php", "lua", "bash", "sh", "zsh", "fish",
	]);
	if (!interpretersWithInlineScriptFlags.has(interpreter)) return rawTokens;

	const filtered: string[] = [];
	for (let i = 0; i < rawTokens.length; i++) {
		const token = rawTokens[i];
		filtered.push(token);
		if (skipNextArgFlags.has(token)) i += 1;
	}
	return filtered;
}

function splitCompound(cmd: string): string[] {
	const segments: string[] = [];
	let current = "";
	let inSingle = false;
	let inDouble = false;
	let i = 0;

	while (i < cmd.length) {
		const ch = cmd[i];
		if (ch === "'" && !inDouble) { inSingle = !inSingle; current += ch; i++; continue; }
		if (ch === '"' && !inSingle) { inDouble = !inDouble; current += ch; i++; continue; }
		if (ch === "\\" && !inSingle && i + 1 < cmd.length) { current += ch + cmd[i + 1]; i += 2; continue; }
		if (!inSingle && !inDouble) {
			if (cmd[i] === "&" && cmd[i + 1] === "&") { segments.push(current); current = ""; i += 2; continue; }
			if (cmd[i] === "|" && cmd[i + 1] === "|") { segments.push(current); current = ""; i += 2; continue; }
			if (cmd[i] === ";") { segments.push(current); current = ""; i++; continue; }
			if (cmd[i] === "|") { segments.push(current); current = ""; i++; continue; }
		}
		current += ch;
		i++;
	}

	if (current.trim()) segments.push(current);
	return segments.map((s) => s.trim()).filter(Boolean);
}

function parseGitSubcommand(segment: string): { sub?: string; args: string[] } {
	const tokens = tokenize(segment);
	if (tokens[0] !== "git") return { args: [] };

	let i = 1;
	while (i < tokens.length && tokens[i].startsWith("-")) {
		const flag = tokens[i];
		if (
			flag === "-c"
			|| flag === "-C"
			|| flag === "--git-dir"
			|| flag === "--work-tree"
			|| flag === "--namespace"
			|| flag === "--config-env"
		) {
			i += 2;
			continue;
		}
		i += 1;
	}

	return { sub: tokens[i], args: tokens.slice(i + 1) };
}

function isSensitiveBasename(name: string): boolean {
	const lower = name.toLowerCase();
	return lower === ".env" || lower.startsWith(".env.") || lower.endsWith(".pem") || lower.endsWith(".key");
}

function isSensitivePath(path: string): boolean {
	const absolute = isAbsolute(path) ? expandHome(path) : resolve(process.cwd(), expandHome(path));
	if (isSensitiveBasename(basename(absolute))) return true;
	if (SENSITIVE_EXACT_FILES.has(absolute)) return true;
	return SENSITIVE_DIRS.some((dir) => isInsideDir(absolute, dir));
}

function looksLikePathToken(token: string): boolean {
	if (!token) return false;
	if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(token)) return false;
	if (token === "." || token === "..") return true;
	if (token === "~" || token.startsWith("~/")) return true;
	if (token.startsWith("./") || token.startsWith("../")) return true;
	if (token.startsWith("/")) return true;
	if (token.startsWith(".")) return true;
	if (token.includes("/")) return true;
	if (isSensitiveBasename(token)) return true;
	return false;
}

function normalizePathLikeToken(rawToken: string): string | undefined {
	let token = stripOuterQuotes(rawToken);
	if (!token) return undefined;
	if (token.startsWith("-") && token.includes("=")) {
		token = stripOuterQuotes(token.slice(token.indexOf("=") + 1));
	}
	const redirected = token.match(/^\d*(>>?|<)(.+)$/);
	if (redirected?.[2]) token = stripOuterQuotes(redirected[2]);
	return looksLikePathToken(token) ? token : undefined;
}

function extractPathLikeTokens(command: string): string[] {
	const result: string[] = [];
	for (const rawToken of inspectionTokens(command)) {
		const token = normalizePathLikeToken(rawToken);
		if (token) result.push(token);
	}
	return unique(result);
}

function positionalArgs(tokens: string[]): string[] {
	const result: string[] = [];
	let afterDoubleDash = false;
	for (let i = 1; i < tokens.length; i++) {
		const token = stripOuterQuotes(tokens[i]);
		if (!token) continue;
		if (!afterDoubleDash && token === "--") {
			afterDoubleDash = true;
			continue;
		}
		if (!afterDoubleDash && token.startsWith("-")) continue;
		result.push(token);
	}
	return result;
}

function extractSegmentWriteTargetTokens(segment: string): string[] {
	const tokens = inspectionTokens(segment);
	if (tokens.length === 0) return [];

	const targets: string[] = [];
	for (let i = 0; i < tokens.length; i++) {
		const token = stripOuterQuotes(tokens[i]);
		if (!token) continue;

		if (/^\d*>>?$/.test(token)) {
			const next = normalizePathLikeToken(tokens[i + 1] ?? "");
			if (next) targets.push(next);
			continue;
		}

		const inlineRedirect = token.match(/^\d*>>?(.+)$/);
		if (inlineRedirect?.[1]) {
			const inline = normalizePathLikeToken(inlineRedirect[1]);
			if (inline) targets.push(inline);
		}
	}

	const cmd = firstCommand(segment);
	const args = positionalArgs(tokens);
	if (DIRECT_WRITE_COMMANDS.has(cmd)) {
		if (cmd === "cp" || cmd === "mv" || cmd === "install" || cmd === "ln") {
			const target = args.at(-1);
			if (target) targets.push(target);
		} else if (cmd === "dd") {
			for (const token of tokens.slice(1)) {
				const output = stripOuterQuotes(token);
				if (output.startsWith("of=")) {
					const path = normalizePathLikeToken(output.slice(3));
					if (path) targets.push(path);
				}
			}
		} else {
			targets.push(...args);
		}
	}

	if ((cmd === "sed" || cmd === "perl") && /(^|\s)-i(?:\S*)?(?:\s|$)/.test(segment)) {
		targets.push(...extractPathLikeTokens(segment));
	}

	if (cmd === "tee") {
		targets.push(...args);
	}

	return unique(targets.filter((token) => looksLikePathToken(token)));
}

function normalizeDomainPattern(value: string): string | undefined {
	let candidate = stripOuterQuotes(value).trim().toLowerCase();
	if (!candidate) return undefined;

	if (candidate.startsWith("http://") || candidate.startsWith("https://") || candidate.startsWith("ws://") || candidate.startsWith("wss://")) {
		try {
			candidate = new URL(candidate).hostname.toLowerCase();
		} catch {
			return undefined;
		}
	} else {
		candidate = candidate.replace(/^[a-z]+:\/\//, "");
		candidate = candidate.split(/[/?#:]/)[0] ?? candidate;
	}

	if (!candidate) return undefined;
	if (candidate.startsWith("*.")) {
		const rest = candidate.slice(2).replace(/^\.+/, "");
		return rest ? `*.${rest}` : undefined;
	}
	return candidate;
}

function domainMatchesPattern(domain: string, pattern: string): boolean {
	const normalizedDomain = normalizeDomainPattern(domain);
	const normalizedPattern = normalizeDomainPattern(pattern);
	if (!normalizedDomain || !normalizedPattern) return false;
	if (normalizedPattern.startsWith("*.")) {
		const suffix = normalizedPattern.slice(2);
		return normalizedDomain.endsWith(`.${suffix}`);
	}
	return normalizedDomain === normalizedPattern;
}

function extractCommandDomains(command: string): string[] {
	const domains: string[] = [];
	for (const rawToken of inspectionTokens(command)) {
		const candidates = [stripOuterQuotes(rawToken)];
		if (rawToken.startsWith("-") && rawToken.includes("=")) {
			candidates.push(stripOuterQuotes(rawToken.slice(rawToken.indexOf("=") + 1)));
		}
		for (const candidate of candidates) {
			const normalized = normalizeDomainPattern(candidate);
			if (!normalized) continue;
			if (candidate.startsWith("http://") || candidate.startsWith("https://") || candidate.startsWith("ws://") || candidate.startsWith("wss://")) {
				domains.push(normalized);
			}
		}
	}
	return unique(domains);
}

function defaultHighRiskPrefix(segment: string): string {
	const tokens = tokenize(segment);
	const cmd = tokens[0] ?? "";
	if (!cmd) return normalizePrefix(segment);

	if (cmd === "git") {
		const { sub } = parseGitSubcommand(segment);
		return normalizePrefix(sub ? `git ${sub}` : "git");
	}

	if (cmd === "gh") {
		if (["pr", "release", "repo", "workflow", "issue"].includes(tokens[1] ?? "")) {
			return normalizePrefix(["gh", tokens[1], tokens[2]].filter(Boolean).join(" "));
		}
		return normalizePrefix(["gh", tokens[1]].filter(Boolean).join(" "));
	}

	if (cmd === "docker") {
		if (tokens[1] === "compose") return normalizePrefix(["docker", "compose", tokens[2]].filter(Boolean).join(" "));
		return normalizePrefix(["docker", tokens[1]].filter(Boolean).join(" "));
	}

	if (cmd === "kubectl") {
		return normalizePrefix(["kubectl", tokens[1]].filter(Boolean).join(" "));
	}

	if (cmd === "terraform" || cmd === "pulumi") {
		return normalizePrefix([cmd, tokens[1]].filter(Boolean).join(" "));
	}

	if (cmd === "helm") {
		return normalizePrefix(["helm", tokens[1]].filter(Boolean).join(" "));
	}

	if (cmd === "curl") {
		const flag = tokens.slice(1).find((token) => /^(-T|--upload-file|-F|--form|--data(?:-ascii|-binary|-raw|-urlencode)?|--json)(=|$)/.test(token));
		return normalizePrefix(flag ? `curl ${flag.split("=")[0]}` : "curl");
	}

	if (cmd === "wget") {
		const flag = tokens.slice(1).find((token) => /^(--post-data|--post-file|--body-data|--body-file)(=|$)/.test(token));
		return normalizePrefix(flag ? `wget ${flag.split("=")[0]}` : "wget");
	}

	return normalizePrefix(cmd);
}

function segmentHighRiskReasons(segment: string): string[] {
	const reasons = new Set<string>();
	const cmd = firstCommand(segment);
	if (!cmd) return [];

	if (DANGEROUS_PATTERNS.some((p) => p.test(segment))) reasons.add("run a destructive or privileged command");
	if (cmd === "env" || cmd === "printenv") reasons.add("expose environment variables (sent to LLM provider)");

	if (["scp", "sftp", "ssh", "rsync"].includes(cmd)) reasons.add(`use ${cmd} for remote access or data transfer`);
	if (cmd === "curl" && CURL_UPLOAD_FLAGS.test(segment)) reasons.add("upload data with curl");
	if (cmd === "wget" && WGET_UPLOAD_FLAGS.test(segment)) reasons.add("upload data with wget");

	if (cmd === "docker") {
		if (/\bdocker\s+compose\s+down\b/.test(segment)) reasons.add("tear down Docker Compose services");
		if (/\bdocker\s+compose\s+down\b/.test(segment) && (/\s-v(\s|$)/.test(segment) || /\s--volumes(\s|$)/.test(segment))) {
			reasons.add("remove Docker Compose volumes and their data");
		}
		if (/\bdocker\s+compose\s+rm\b/.test(segment)) reasons.add("remove Docker Compose service containers");
		if (/\bdocker\s+(rm|rmi)\b/.test(segment)) reasons.add("remove Docker containers or images");
		if (/\bdocker\s+(system|volume|image|container|network)\s+prune\b/.test(segment)) reasons.add("prune Docker resources");
		if (/\bdocker\s+volume\s+rm\b/.test(segment)) reasons.add("remove Docker volumes and their data");
	}

	if (cmd === "kubectl") {
		if (/\bkubectl\s+delete\b/.test(segment)) reasons.add("delete Kubernetes resources");
		if (/\bkubectl\s+(apply|replace|patch)\b/.test(segment)) reasons.add("modify Kubernetes resources");
		if (/\bkubectl\s+scale\b/.test(segment)) reasons.add("scale Kubernetes workloads");
		if (/\bkubectl\s+rollout\s+restart\b/.test(segment)) reasons.add("restart Kubernetes workloads");
	}

	if (["shutdown", "reboot", "halt", "poweroff"].includes(cmd)) reasons.add("change system power state");
	if (cmd === "systemctl" || cmd === "service" || cmd === "launchctl") reasons.add("modify system services");

	if (cmd === "npm" && /\bnpm\s+publish\b/.test(segment)) reasons.add("publish package to npm");
	if (cmd === "yarn" && /\byarn\s+publish\b/.test(segment)) reasons.add("publish package to npm");
	if (cmd === "pnpm" && /\bpnpm\s+publish\b/.test(segment)) reasons.add("publish package to npm");
	if (cmd === "cargo" && /\bcargo\s+publish\b/.test(segment)) reasons.add("publish crate");
	if (cmd === "gem" && /\bgem\s+push\b/.test(segment)) reasons.add("publish gem");
	if (cmd === "twine" && /\btwine\s+upload\b/.test(segment)) reasons.add("publish Python package");

	if (cmd === "terraform" && /\bterraform\s+(apply|destroy)\b/.test(segment)) reasons.add("modify cloud infrastructure");
	if (cmd === "pulumi" && /\bpulumi\s+(up|destroy|update)\b/.test(segment)) reasons.add("modify cloud infrastructure");
	if (cmd === "helm" && /\bhelm\s+(install|upgrade|uninstall|delete|rollback)\b/.test(segment)) reasons.add("modify Kubernetes cluster");

	if (cmd === "gh") {
		if (/\bgh\s+api\b/.test(segment)) reasons.add("call the GitHub API");
		if (/\bgh\s+pr\s+(create|comment|merge|review)\b/.test(segment)) reasons.add("modify GitHub pull request state");
		if (/\bgh\s+issue\s+comment\b/.test(segment)) reasons.add("comment on a GitHub issue");
		if (/\bgh\s+release\s+(create|edit|upload)\b/.test(segment)) reasons.add("publish or edit a GitHub release");
		if (/\bgh\s+repo\s+create\b/.test(segment)) reasons.add("create a GitHub repository");
		if (/\bgh\s+workflow\s+run\b/.test(segment)) reasons.add("trigger a GitHub workflow");
	}

	if (cmd === "git") {
		const { sub, args } = parseGitSubcommand(segment);
		if (sub === "commit") reasons.add("create a git commit");
		if (sub === "tag" && args.length > 0) reasons.add("create or move a git tag");
		if (sub === "push") reasons.add("push git changes to a remote");
		if (sub === "reset" && args.includes("--hard")) reasons.add("discard work with git reset --hard");
		if (sub === "clean" && args.some((arg) => arg === "-f" || arg === "--force" || /^-[^-]*f/.test(arg))) {
			reasons.add("delete files with git clean");
		}
	}

	return [...reasons];
}

function highRiskSegments(command: string): Array<{ segment: string; reasons: string[] }> {
	return splitCompound(command)
		.map((segment) => ({ segment, reasons: segmentHighRiskReasons(segment) }))
		.filter(({ reasons }) => reasons.length > 0);
}

// ── Sandbox config helpers ───────────────────────────────────────────────────

function createDefaultSandboxConfig(projectRoot: string): SandboxConfig {
	// Keep the OS sandbox coarse on Linux/macOS: writable roots + network.
	// Fine-grained file policy (including protected paths like .env, keys, auth,
	// sandbox config, and extension files) is enforced in this extension before
	// tool execution, so we don't need path-shaped deny targets in the OS layer.
	return {
		enabled: true,
		network: {
			allowLocalBinding: true,
			allowedDomains: [
				"localhost",
				"127.0.0.1",
				"github.com",
				"*.github.com",
				"api.github.com",
				"raw.githubusercontent.com",
				"objects.githubusercontent.com",
				"npmjs.org",
				"*.npmjs.org",
				"registry.npmjs.org",
				"registry.yarnpkg.com",
				"pypi.org",
				"*.pypi.org",
				"files.pythonhosted.org",
				"go.dev",
				"pkg.go.dev",
				"proxy.golang.org",
				"sum.golang.org",
				"crates.io",
				"*.crates.io",
				"index.crates.io",
				"static.crates.io",
				"rubygems.org",
				"*.rubygems.org",
				"repo.maven.apache.org",
				"repo1.maven.org",
				"plugins.gradle.org",
				"services.gradle.org",
				"maven.google.com",
				"dl.google.com",
				"registry-1.docker.io",
				"auth.docker.io",
				"production.cloudflare.docker.com",
			],
			deniedDomains: [],
		},
		filesystem: {
			denyRead: [],
			allowWrite: [projectRoot, "/tmp", "/private/tmp"],
			denyWrite: [],
		},
	};
}

function deepMergeSandboxConfig(base: SandboxConfig, overrides: Partial<SandboxConfig>): SandboxConfig {
	const result: SandboxConfig = { ...base };
	if (overrides.enabled !== undefined) result.enabled = overrides.enabled;
	if (overrides.network) result.network = { ...(base.network ?? {}), ...overrides.network };
	if (overrides.filesystem) result.filesystem = { ...(base.filesystem ?? {}), ...overrides.filesystem };

	const extOverrides = overrides as {
		ignoreViolations?: Record<string, string[]>;
		enableWeakerNestedSandbox?: boolean;
	};
	const extResult = result as {
		ignoreViolations?: Record<string, string[]>;
		enableWeakerNestedSandbox?: boolean;
	};

	if (extOverrides.ignoreViolations) extResult.ignoreViolations = extOverrides.ignoreViolations;
	if (extOverrides.enableWeakerNestedSandbox !== undefined) {
		extResult.enableWeakerNestedSandbox = extOverrides.enableWeakerNestedSandbox;
	}
	return result;
}

async function loadSandboxConfigPart(path: string): Promise<LoadedSandboxConfigPart> {
	if (!existsSync(path)) return { config: {}, exists: false };
	try {
		return {
			config: JSON.parse(await readFile(path, "utf-8")),
			exists: true,
		};
	} catch (error) {
		return {
			config: {},
			exists: true,
			parseError: error instanceof Error ? error.message : String(error),
		};
	}
}

// ── Rules persistence ────────────────────────────────────────────────────────

function emptyRules(): RulesFile {
	return { dirs: [], readDirs: [], protectedDirs: [], protectedReadDirs: [], allowedDomains: [] };
}

async function loadRulesFromPath(path: string): Promise<LoadedRulesFile> {
	if (!existsSync(path)) return { rules: emptyRules(), exists: false };
	try {
		const parsed = JSON.parse(await readFile(path, "utf-8"));
		return {
			rules: {
				dirs: Array.isArray(parsed.dirs) ? parsed.dirs.filter((v: unknown) => typeof v === "string") : [],
				readDirs: Array.isArray(parsed.readDirs) ? parsed.readDirs.filter((v: unknown) => typeof v === "string") : [],
				protectedDirs: Array.isArray(parsed.protectedDirs) ? parsed.protectedDirs.filter((v: unknown) => typeof v === "string") : [],
				protectedReadDirs: Array.isArray(parsed.protectedReadDirs) ? parsed.protectedReadDirs.filter((v: unknown) => typeof v === "string") : [],
				allowedDomains: Array.isArray(parsed.allowedDomains)
					? parsed.allowedDomains.filter((v: unknown) => typeof v === "string")
					: [],
			},
			exists: true,
		};
	} catch (error) {
		return {
			rules: emptyRules(),
			exists: true,
			parseError: error instanceof Error ? error.message : String(error),
		};
	}
}

async function saveRulesToPath(path: string, rules: RulesFile): Promise<void> {
	const dir = dirname(path);
	if (!existsSync(dir)) await mkdir(dir, { recursive: true });
	const normalized: RulesFile = {
		dirs: unique(rules.dirs).sort(),
		readDirs: unique(rules.readDirs ?? []).sort(),
		protectedDirs: unique(rules.protectedDirs ?? []).sort(),
		protectedReadDirs: unique(rules.protectedReadDirs ?? []).sort(),
		allowedDomains: unique(rules.allowedDomains ?? []).sort(),
	};
	const content = JSON.stringify(normalized, null, 2) + "\n";
	if (existsSync(path)) {
		try {
			const current = await readFile(path, "utf-8");
			if (current === content) return;
		} catch {
			// Fall through to write attempt.
		}
	}
	await writeFile(path, content, "utf-8");
}

// ── Extension ────────────────────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
	const sessionDirs = new Set<string>();
	const sessionReadDirs = new Set<string>();
	const sessionProtectedDirs = new Set<string>();
	const sessionProtectedReadDirs = new Set<string>();
	const sessionHighRiskPrefixes = new Set<string>();
	const sessionAllowedDomains = new Set<string>();
	const pendingOneShotAllowedDomains = new Map<string, Set<string>>();
	const localBash = createBashTool(process.cwd());
	const localBashOps = createLocalBashOperations();

	let projectRoot = process.cwd();
	let projectRules: RulesFile = emptyRules();
	let globalRules: RulesFile = emptyRules();
	let projectRulesPath = "";
	let globalRulesPath = "";
	let projectConfigPath = "";
	let globalConfigPath = "";
	let cwd = process.cwd();

	let protectedPaths = new Map<string, ProtectedPathInfo>();
	let sensitiveFilePaths: string[] = [];
	let osSandboxConfig: SandboxConfig | undefined;
	let osSandboxEnabled = false;
	let osSandboxInitialized = false;
	let osSandboxReason = "not initialized";
	let currentAgentConstraints: AgentConstraints | undefined;
	let currentAgentName: string | undefined;
	let lastPersistedSessionStateJson = "";

	function defaultSessionReadDirs(): string[] {
		return [AGENT_DIR, ...IMPLICIT_BASH_READ_PATHS];
	}

	function isOsSandboxActive(): boolean {
		return osSandboxEnabled && osSandboxInitialized;
	}

	async function prepareSandboxRuntimeCwd(): Promise<void> {
		await mkdir(SANDBOX_RUNTIME_CWD, { recursive: true });
		for (const name of [".git", ".claude"]) {
			const path = resolve(SANDBOX_RUNTIME_CWD, name);
			if (existsSync(path) && !statSync(path).isDirectory()) await rm(path, { force: true });
			await mkdir(path, { recursive: true });
		}
	}

	async function withSandboxRuntimeCwd<T>(fn: () => Promise<T> | T): Promise<T> {
		await prepareSandboxRuntimeCwd();
		const previousCwd = process.cwd();
		process.chdir(SANDBOX_RUNTIME_CWD);
		try {
			return await fn();
		} finally {
			process.chdir(previousCwd);
		}
	}

	function syncRuntimeBaseConfig(execCwd = cwd): void {
		if (!isOsSandboxActive()) return;
		void withSandboxRuntimeCwd(() => SandboxManager.updateConfig(effectiveRuntimeConfig(execCwd)));
	}

	function currentExtraDirs(): string[] {
		return unique([...globalRules.dirs, ...projectRules.dirs, ...sessionDirs]);
	}

	function currentReadOnlyDirs(): string[] {
		return unique([...(globalRules.readDirs ?? []), ...(projectRules.readDirs ?? []), ...sessionReadDirs]);
	}

	function currentProtectedDirs(): string[] {
		return unique([...(globalRules.protectedDirs ?? []), ...(projectRules.protectedDirs ?? []), ...sessionProtectedDirs]);
	}

	function currentProtectedReadOnlyDirs(): string[] {
		return unique([...(globalRules.protectedReadDirs ?? []), ...(projectRules.protectedReadDirs ?? []), ...sessionProtectedReadDirs]);
	}

	function activeDirs(): string[] {
		return unique([projectRoot, ...currentExtraDirs()]);
	}

	function readableDirs(): string[] {
		return unique([...activeDirs(), ...currentReadOnlyDirs()]);
	}

	function currentRuleDomains(): string[] {
		return unique([...(globalRules.allowedDomains ?? []), ...(projectRules.allowedDomains ?? []), ...sessionAllowedDomains]);
	}

	function configuredAllowedDomains(): string[] | undefined {
		return osSandboxConfig?.network?.allowedDomains;
	}

	function effectiveAllowedDomains(extraPatterns: Iterable<string> = []): string[] | undefined {
		const configured = configuredAllowedDomains();
		if (configured === undefined) return undefined;
		return unique([...configured, ...currentRuleDomains(), ...extraPatterns])
			.map((pattern) => normalizeDomainPattern(pattern) ?? pattern)
			.filter(Boolean)
			.sort();
	}

	function effectiveDeniedDomains(): string[] {
		return unique(osSandboxConfig?.network?.deniedDomains ?? [])
			.map((pattern) => normalizeDomainPattern(pattern) ?? pattern)
			.filter(Boolean)
			.sort();
	}

	function effectiveRuntimeConfig(
		execCwd: string,
		exemptProtectedIds: Iterable<string> = [],
		extraDomains: Iterable<string> = [],
	): SandboxRuntimeConfig {
		const base = osSandboxConfig ?? createDefaultSandboxConfig(projectRoot);
		const extended = base as SandboxConfig & {
			ignoreViolations?: Record<string, string[]>;
			enableWeakerNestedSandbox?: boolean;
			ripgrep?: { command: string; args?: string[] };
			mandatoryDenySearchDepth?: number;
			allowPty?: boolean;
			seccomp?: { bpfPath?: string; applyPath?: string };
		};
		const networkConfig = {
			...(base.network ?? { allowedDomains: [], deniedDomains: [] }),
			allowLocalBinding: base.network?.allowLocalBinding,
			allowedDomains: effectiveAllowedDomains(extraDomains) ?? [],
			deniedDomains: effectiveDeniedDomains(),
			allowUnixSockets: undefined,
			allowAllUnixSockets: true,
		};

		return {
			network: networkConfig as SandboxRuntimeConfig["network"],
			filesystem: {
				...(base.filesystem ?? { denyRead: [], allowWrite: [], denyWrite: [] }),
				denyRead: effectiveDenyRead(),
				allowWrite: effectiveWriteRoots(execCwd),
				denyWrite: effectiveDenyWrite(exemptProtectedIds),
				allowGitConfig: base.filesystem?.allowGitConfig,
			},
			ignoreViolations: extended.ignoreViolations,
			enableWeakerNestedSandbox: extended.enableWeakerNestedSandbox,
			ripgrep: extended.ripgrep,
			mandatoryDenySearchDepth: extended.mandatoryDenySearchDepth,
			allowPty: extended.allowPty,
			seccomp: extended.seccomp,
		};
	}

	function isDomainDenied(domain: string): boolean {
		return effectiveDeniedDomains().some((pattern) => domainMatchesPattern(domain, pattern));
	}

	function isDomainAllowed(domain: string, extraPatterns: Iterable<string> = []): boolean {
		if (isDomainDenied(domain)) return false;
		const allowed = effectiveAllowedDomains(extraPatterns);
		if (allowed === undefined) return true;
		return allowed.some((pattern) => domainMatchesPattern(domain, pattern));
	}

	function isInsideAllowedDir(path: string): boolean {
		return activeDirs().some((dir) => isInsideDir(path, dir));
	}

	function isInsideReadableDir(path: string): boolean {
		return readableDirs().some((dir) => isInsideDir(path, dir));
	}

	function buildSessionStateData(): SessionStateData {
		return {
			version: 1,
			dirs: [...sessionDirs].sort(),
			readDirs: [...sessionReadDirs].filter((dir) => !defaultSessionReadDirs().includes(dir)).sort(),
			protectedDirs: [...sessionProtectedDirs].sort(),
			protectedReadDirs: [...sessionProtectedReadDirs].sort(),
			highRiskPrefixes: [...sessionHighRiskPrefixes].sort(),
			allowedDomains: [...sessionAllowedDomains].sort(),
		};
	}

	function persistSessionState(): void {
		const payload = buildSessionStateData();
		const json = JSON.stringify(payload);
		if (json === lastPersistedSessionStateJson) return;
		pi.appendEntry(SANDBOX_STATE_CUSTOM_TYPE, payload);
		lastPersistedSessionStateJson = json;
	}

	function resetSessionState(): void {
		sessionDirs.clear();
		sessionReadDirs.clear();
		sessionProtectedDirs.clear();
		sessionProtectedReadDirs.clear();
		sessionHighRiskPrefixes.clear();
		sessionAllowedDomains.clear();
		pendingOneShotAllowedDomains.clear();
		for (const dir of defaultSessionReadDirs()) sessionReadDirs.add(dir);
	}

	async function reconstructSessionState(ctx: { sessionManager: any; ui: any }): Promise<void> {
		resetSessionState();

		let latest: SessionStateData | undefined;
		for (const entry of ctx.sessionManager.getBranch()) {
			if (entry.type !== "custom" || entry.customType !== SANDBOX_STATE_CUSTOM_TYPE) continue;
			const data = entry.data as Partial<SessionStateData> | undefined;
			if (!data || data.version !== 1) continue;
			latest = {
				version: 1,
				dirs: Array.isArray(data.dirs) ? data.dirs.filter((v): v is string => typeof v === "string") : [],
				readDirs: Array.isArray(data.readDirs) ? data.readDirs.filter((v): v is string => typeof v === "string") : [],
				protectedDirs: Array.isArray(data.protectedDirs) ? data.protectedDirs.filter((v): v is string => typeof v === "string") : [],
				protectedReadDirs: Array.isArray(data.protectedReadDirs) ? data.protectedReadDirs.filter((v): v is string => typeof v === "string") : [],
				highRiskPrefixes: Array.isArray(data.highRiskPrefixes)
					? data.highRiskPrefixes.filter((v): v is string => typeof v === "string")
					: [],
				allowedDomains: Array.isArray(data.allowedDomains)
					? data.allowedDomains.filter((v): v is string => typeof v === "string")
					: [],
			};
		}

		if (latest) {
			for (const dir of await Promise.all(latest.dirs.map((dir) => normalizeDir(dir)))) sessionDirs.add(dir);
			for (const dir of await Promise.all(latest.readDirs.map((dir) => normalizeDir(dir)))) sessionReadDirs.add(dir);
			for (const dir of await Promise.all(latest.protectedDirs.map((dir) => normalizeDir(dir)))) sessionProtectedDirs.add(dir);
			for (const dir of await Promise.all(latest.protectedReadDirs.map((dir) => normalizeDir(dir)))) sessionProtectedReadDirs.add(dir);
			for (const prefix of latest.highRiskPrefixes.map((value) => normalizePrefix(value)).filter(Boolean)) {
				sessionHighRiskPrefixes.add(prefix);
			}
			for (const pattern of latest.allowedDomains.map((value) => normalizeDomainPattern(value)).filter(Boolean) as string[]) {
				sessionAllowedDomains.add(pattern);
			}
		}

		await refreshSensitiveFilePaths();
		lastPersistedSessionStateJson = JSON.stringify(buildSessionStateData());
		updateStatus(ctx);
	}

	function updateStatus(ctx: { ui: any }) {
		const parts = [`${projectRoot}`];
		const extraCount = currentExtraDirs().length;
		const readCount = currentReadOnlyDirs().length;
		const protectedCount = currentProtectedDirs().length + currentProtectedReadOnlyDirs().length;
		const domainCount = currentRuleDomains().length;
		if (extraCount > 0) parts.push(`+${extraCount} dirs`);
		if (readCount > 0) parts.push(`+${readCount} read-only`);
		if (protectedCount > 0) parts.push(`+${protectedCount} protected`);
		if (domainCount > 0) parts.push(`+${domainCount} domains`);
		parts.push("sockets unrestricted");
		parts.push(isOsSandboxActive() ? "os sandbox" : `os off (${osSandboxReason})`);
		ctx.ui.setStatus("sandbox", ctx.ui.theme.fg("accent", parts.join(" · ")));
	}

	function configuredWriteRoots(): string[] {
		return osSandboxConfig?.filesystem?.allowWrite ?? [];
	}

	function effectiveWriteRoots(execCwd: string): string[] {
		return unique([...configuredWriteRoots(), ...activeDirs(), execCwd, "/tmp", "/private/tmp"]);
	}

	function parentIsDir(p: string): boolean {
		if (!isAbsolute(p)) return true;
		const parent = dirname(p);
		try {
			return statSync(parent).isDirectory();
		} catch {
			return false;
		}
	}

	function effectiveDenyRead(): string[] {
		return unique([...(osSandboxConfig?.filesystem?.denyRead ?? [])]).filter(parentIsDir);
	}

	function effectiveDenyWrite(_exemptProtectedIds: Iterable<string> = []): string[] {
		return unique([
			...(osSandboxConfig?.filesystem?.denyWrite ?? []),
		]).filter(parentIsDir);
	}

	async function addProtectedPath(
		targets: Map<string, ProtectedPathInfo>,
		id: string,
		label: string,
		path: string,
	): Promise<void> {
		targets.set(path, { id, label });
		try { targets.set(await realpath(path), { id, label }); } catch { /* path may not exist */ }
	}

	async function rebuildProtectedPaths(): Promise<void> {
		const next = new Map<string, ProtectedPathInfo>();
		const candidates = [
			{ id: projectRulesPath, label: "sandbox rules", path: projectRulesPath },
			{ id: globalRulesPath, label: "sandbox rules", path: globalRulesPath },
			{ id: projectConfigPath, label: "sandbox config", path: projectConfigPath },
			{ id: globalConfigPath, label: "sandbox config", path: globalConfigPath },
			{ id: resolve(projectRoot, ".pi", "extensions", "sandbox.ts"), label: "sandbox extension", path: resolve(projectRoot, ".pi", "extensions", "sandbox.ts") },
			{ id: resolve(cwd, ".pi", "extensions", "sandbox.ts"), label: "sandbox extension", path: resolve(cwd, ".pi", "extensions", "sandbox.ts") },
			{ id: resolve(AGENT_DIR, "extensions", "sandbox.ts"), label: "sandbox extension", path: resolve(AGENT_DIR, "extensions", "sandbox.ts") },
			{ id: resolve(AGENT_DIR, "extensions", "sandbox", "index.ts"), label: "sandbox extension", path: resolve(AGENT_DIR, "extensions", "sandbox", "index.ts") },
			{ id: resolve(AGENT_DIR, "extensions", "sandbox", "transient-menu.ts"), label: "sandbox extension", path: resolve(AGENT_DIR, "extensions", "sandbox", "transient-menu.ts") },
			{ id: resolve(AGENT_DIR, "extensions", "agents.ts"), label: "agent extension", path: resolve(AGENT_DIR, "extensions", "agents.ts") },
			{ id: resolve(AGENT_DIR, "extensions", "package.json"), label: "extension package manifest", path: resolve(AGENT_DIR, "extensions", "package.json") },
			{ id: resolve(AGENT_DIR, "extensions", "package-lock.json"), label: "extension package lockfile", path: resolve(AGENT_DIR, "extensions", "package-lock.json") },
		];
		for (const candidate of candidates) await addProtectedPath(next, candidate.id, candidate.label, candidate.path);
		protectedPaths = next;
	}

	async function findSensitiveFilesUnderRoot(root: string): Promise<string[]> {
		const pruneArgs = SENSITIVE_SCAN_PRUNE_DIRS.flatMap((name) => ["-name", name, "-o"]).slice(0, -1);
		const args = [
			root,
			"(", "-type", "d", "(", ...pruneArgs, ")", "-prune", ")",
			"-o",
			"(", "-type", "f", "(",
			"-name", ".env",
			"-o", "-name", ".env.*",
			"-o", "-name", "*.pem",
			"-o", "-name", "*.key",
			")", "-print", ")",
		];
		try {
			const result = await pi.exec("find", args, { timeout: 5000 });
			if (result.code !== 0 || !result.stdout.trim()) return [];
			return unique(result.stdout
				.split("\n")
				.map((line) => line.trim())
				.filter(Boolean)
				.map((line) => isAbsolute(line) ? line : resolve(root, line)));
		} catch {
			return [];
		}
	}

	async function refreshSensitiveFilePaths(): Promise<void> {
		const discovered = await Promise.all(activeDirs().map((dir) => findSensitiveFilesUnderRoot(dir)));
		sensitiveFilePaths = unique(discovered.flat()).sort();
	}

	function protectedInfoForPath(path: string): ProtectedPathInfo | undefined {
		return protectedPaths.get(path);
	}

	function protectedInfosForPaths(paths: string[]): ProtectedPathInfo[] {
		const infos = new Map<string, ProtectedPathInfo>();
		for (const path of paths) {
			const info = protectedInfoForPath(path);
			if (info) infos.set(info.id, info);
		}
		return [...infos.values()];
	}

	function protectedControlFiles(): string[] {
		return unique([...protectedPaths.values()].map((info) => info.id)).sort();
	}

	function noteSensitivePath(path: string): void {
		if (!isSensitivePath(path)) return;
		sensitiveFilePaths = unique([...sensitiveFilePaths, path]).sort();
	}

	function createSandboxedBashOps(toolCallId?: string): BashOperations {
		return {
			async exec(command, execCwd, options) {
				if (!existsSync(execCwd)) throw new Error(`Working directory does not exist: ${execCwd}`);

				const oneShotDomains = toolCallId
					? pendingOneShotAllowedDomains.get(toolCallId) ?? new Set<string>()
					: new Set<string>();
				if (toolCallId) {
					pendingOneShotAllowedDomains.delete(toolCallId);
				}

				const baseRuntimeConfig = effectiveRuntimeConfig(execCwd);
				const runtimeConfig = effectiveRuntimeConfig(execCwd, [], oneShotDomains);
				return await withSandboxRuntimeCwd(async () => {
					SandboxManager.updateConfig(runtimeConfig);

					try {
						const wrappedCommand = await SandboxManager.wrapWithSandbox(command, undefined, runtimeConfig);
						return await localBashOps.exec(wrappedCommand, execCwd, options);
					} finally {
						SandboxManager.updateConfig(baseRuntimeConfig);
					}
				});
			},
		};
	}

	async function saveProjectRules(ctx?: { ui: any }): Promise<boolean> {
		try {
			await saveRulesToPath(projectRulesPath, projectRules);
			return true;
		} catch (error) {
			ctx?.ui.notify(`Could not save ${projectRulesPath}: ${error instanceof Error ? error.message : error}`, "warning");
			return false;
		}
	}

	async function saveGlobalRules(ctx?: { ui: any }): Promise<boolean> {
		try {
			await saveRulesToPath(globalRulesPath, globalRules);
			return true;
		} catch (error) {
			ctx?.ui.notify(`Could not save ${globalRulesPath}: ${error instanceof Error ? error.message : error}`, "warning");
			return false;
		}
	}

	function saveForScope(scope: Scope, ctx?: { ui: any }) {
		return scope === "project" ? saveProjectRules(ctx) : saveGlobalRules(ctx);
	}

	function rulesForScope(scope: Scope) {
		return scope === "project" ? projectRules : globalRules;
	}

	async function normalizeDir(input: string): Promise<string> {
		const base = projectRoot || cwd || process.cwd();
		const raw = isAbsolute(input) ? expandHome(input) : resolve(base, expandHome(input));
		try {
			return await realpath(raw);
		} catch {
			return raw;
		}
	}

	async function normalizeRules(rules: RulesFile): Promise<void> {
		rules.dirs = unique(await Promise.all(rules.dirs.map((dir) => normalizeDir(dir)))).sort();
		rules.readDirs = unique(await Promise.all((rules.readDirs ?? []).map((dir) => normalizeDir(dir)))).sort();
		rules.protectedDirs = unique(await Promise.all((rules.protectedDirs ?? []).map((dir) => normalizeDir(dir)))).sort();
		rules.protectedReadDirs = unique(await Promise.all((rules.protectedReadDirs ?? []).map((dir) => normalizeDir(dir)))).sort();
		rules.allowedDomains = unique((rules.allowedDomains ?? []).map((domain) => normalizeDomainPattern(domain)).filter(Boolean) as string[]).sort();
	}

	async function addAllowedDir(dir: string, scope: AllowScope, level: AccessLevel, ctx?: { ui: any }): Promise<boolean> {
		const normalized = await normalizeDir(dir);
		let changed = false;
		if (scope === "session") {
			if (level === "full") {
				sessionReadDirs.delete(normalized);
				if (!sessionDirs.has(normalized)) {
					sessionDirs.add(normalized);
					changed = true;
				}
			} else if (!sessionDirs.has(normalized) && !sessionReadDirs.has(normalized)) {
				sessionReadDirs.add(normalized);
				changed = true;
			}
			if (changed) {
				persistSessionState();
				syncRuntimeBaseConfig();
			}
		} else {
			const rules = rulesForScope(scope);
			if (level === "full") {
				rules.readDirs = (rules.readDirs ?? []).filter((d) => d !== normalized);
				if (!rules.dirs.includes(normalized)) {
					const previous = {
						dirs: [...rules.dirs],
						readDirs: [...(rules.readDirs ?? [])],
						allowedDomains: [...(rules.allowedDomains ?? [])],
					};
					rules.dirs.push(normalized);
					rules.dirs = unique(rules.dirs).sort();
					const saved = await saveForScope(scope, ctx);
					if (!saved) {
						rules.dirs = previous.dirs;
						rules.readDirs = previous.readDirs;
						rules.allowedDomains = previous.allowedDomains;
						return false;
					}
					changed = true;
				}
			} else if (!rules.dirs.includes(normalized) && !(rules.readDirs ?? []).includes(normalized)) {
				const previous = {
					dirs: [...rules.dirs],
					readDirs: [...(rules.readDirs ?? [])],
					allowedDomains: [...(rules.allowedDomains ?? [])],
				};
				rules.readDirs = rules.readDirs ?? [];
				rules.readDirs.push(normalized);
				rules.readDirs = unique(rules.readDirs).sort();
				const saved = await saveForScope(scope, ctx);
				if (!saved) {
					rules.dirs = previous.dirs;
					rules.readDirs = previous.readDirs;
					rules.allowedDomains = previous.allowedDomains;
					return false;
				}
				changed = true;
			}
		}
		if (changed) {
			await refreshSensitiveFilePaths();
			syncRuntimeBaseConfig();
		}
		return true;
	}

	async function addProtectedAllowedDir(dir: string, scope: AllowScope, level: AccessLevel, ctx?: { ui: any }): Promise<boolean> {
		const normalized = await normalizeDir(dir);
		let changed = false;
		if (scope === "session") {
			if (level === "full") {
				sessionProtectedReadDirs.delete(normalized);
				if (!sessionProtectedDirs.has(normalized)) {
					sessionProtectedDirs.add(normalized);
					changed = true;
				}
			} else if (!sessionProtectedDirs.has(normalized) && !sessionProtectedReadDirs.has(normalized)) {
				sessionProtectedReadDirs.add(normalized);
				changed = true;
			}
			if (changed) persistSessionState();
		} else {
			const rules = rulesForScope(scope);
			if (level === "full") {
				rules.protectedReadDirs = (rules.protectedReadDirs ?? []).filter((d) => d !== normalized);
				if (!(rules.protectedDirs ?? []).includes(normalized)) {
					const previous = {
						dirs: [...rules.dirs],
						readDirs: [...(rules.readDirs ?? [])],
						protectedDirs: [...(rules.protectedDirs ?? [])],
						protectedReadDirs: [...(rules.protectedReadDirs ?? [])],
						allowedDomains: [...(rules.allowedDomains ?? [])],
					};
					rules.protectedDirs = rules.protectedDirs ?? [];
					rules.protectedDirs.push(normalized);
					rules.protectedDirs = unique(rules.protectedDirs).sort();
					const saved = await saveForScope(scope, ctx);
					if (!saved) {
						rules.dirs = previous.dirs;
						rules.readDirs = previous.readDirs;
						rules.protectedDirs = previous.protectedDirs;
						rules.protectedReadDirs = previous.protectedReadDirs;
						rules.allowedDomains = previous.allowedDomains;
						return false;
					}
					changed = true;
				}
			} else if (!(rules.protectedDirs ?? []).includes(normalized) && !(rules.protectedReadDirs ?? []).includes(normalized)) {
				const previous = {
					dirs: [...rules.dirs],
					readDirs: [...(rules.readDirs ?? [])],
					protectedDirs: [...(rules.protectedDirs ?? [])],
					protectedReadDirs: [...(rules.protectedReadDirs ?? [])],
					allowedDomains: [...(rules.allowedDomains ?? [])],
				};
				rules.protectedReadDirs = rules.protectedReadDirs ?? [];
				rules.protectedReadDirs.push(normalized);
				rules.protectedReadDirs = unique(rules.protectedReadDirs).sort();
				const saved = await saveForScope(scope, ctx);
				if (!saved) {
					rules.dirs = previous.dirs;
					rules.readDirs = previous.readDirs;
					rules.protectedDirs = previous.protectedDirs;
					rules.protectedReadDirs = previous.protectedReadDirs;
					rules.allowedDomains = previous.allowedDomains;
					return false;
				}
				changed = true;
			}
		}
		return true;
	}

	function isProtectedPath(path: string): boolean {
		return isSensitivePath(path) || protectedInfoForPath(path) !== undefined;
	}

	function isInsideProtectedAllowedDir(path: string): boolean {
		return currentProtectedDirs().some((dir) => isInsideDir(path, dir));
	}

	function isInsideProtectedReadableDir(path: string): boolean {
		return [...currentProtectedDirs(), ...currentProtectedReadOnlyDirs()].some((dir) => isInsideDir(path, dir));
	}

	async function addAllowedDomain(domain: string, scope: AllowScope, ctx?: { ui: any }): Promise<boolean> {
		const normalized = normalizeDomainPattern(domain);
		if (!normalized) {
			ctx?.ui.notify(`Invalid domain or pattern: ${domain}`, "warning");
			return false;
		}
		if (scope === "session") {
			if (sessionAllowedDomains.has(normalized)) return true;
			sessionAllowedDomains.add(normalized);
			persistSessionState();
			syncRuntimeBaseConfig();
			return true;
		}

		const rules = rulesForScope(scope);
		if ((rules.allowedDomains ?? []).includes(normalized)) return true;
		const previous = {
			dirs: [...rules.dirs],
			readDirs: [...(rules.readDirs ?? [])],
			allowedDomains: [...(rules.allowedDomains ?? [])],
		};
		rules.allowedDomains = rules.allowedDomains ?? [];
		rules.allowedDomains.push(normalized);
		rules.allowedDomains = unique(rules.allowedDomains).sort();
		const saved = await saveForScope(scope, ctx);
		if (!saved) {
			rules.dirs = previous.dirs;
			rules.readDirs = previous.readDirs;
			rules.allowedDomains = previous.allowedDomains;
			return false;
		}
		syncRuntimeBaseConfig();
		return true;
	}


	function boundaryKindLabel(kind: AccessBoundaryKind): string {
		if (kind === "package") return "package directory";
		if (kind === "repo") return "repo";
		return "directory";
	}

	function hasProjectMarker(dir: string): boolean {
		return ["package.json", "pyproject.toml", "Cargo.toml", "go.mod", "Gemfile", "composer.json"]
			.some((name) => existsSync(resolve(dir, name)));
	}

	async function normalizeAllowedDir(input: string): Promise<string> {
		const normalized = await normalizeDir(input);
		try {
			const info = await stat(normalized);
			return info.isDirectory() ? normalized : await normalizeDir(dirname(normalized));
		} catch {
			return normalized;
		}
	}

	async function findRepoRoot(dir: string): Promise<string | undefined> {
		try {
			const result = await pi.exec("git", ["-C", dir, "rev-parse", "--show-toplevel"], { timeout: 1500 });
			if (result.code === 0 && result.stdout.trim()) return await normalizeDir(result.stdout.trim());
		} catch {
			// not a git repo
		}
		return undefined;
	}

	async function findNearestProjectLikeRoot(dir: string, stopAt?: string): Promise<string | undefined> {
		let current = await normalizeDir(dir);
		const normalizedStopAt = stopAt ? await normalizeDir(stopAt) : undefined;
		while (true) {
			if (hasProjectMarker(current)) return current;
			if (normalizedStopAt && current === normalizedStopAt) break;
			const parent = dirname(current);
			if (parent === current) break;
			current = parent;
		}
		return undefined;
	}

	async function accessBoundary(path: string): Promise<AccessBoundary> {
		let dir = path;
		try {
			const info = await stat(path);
			if (!info.isDirectory()) dir = dirname(path);
		} catch {
			dir = dirname(path);
		}
		dir = await normalizeDir(dir);

		const repo = await findRepoRoot(dir);
		const packageRoot = await findNearestProjectLikeRoot(dir, repo);
		const suggestions = unique([
			packageRoot ? `${packageRoot}::package` : undefined,
			repo ? `${repo}::repo` : undefined,
			`${dir}::directory`,
		].filter(Boolean) as string[]).map((entry) => {
			const [suggestedDir, kind] = entry.split("::") as [string, AccessBoundaryKind];
			return { dir: suggestedDir, kind, label: boundaryKindLabel(kind) };
		});

		if (packageRoot) return { dir: packageRoot, kind: "package", suggestions };
		if (repo) return { dir: repo, kind: "repo", suggestions };
		return { dir, kind: "directory", suggestions };
	}

	// ── Transient menu helpers for prompt functions ──────────────────────────

	type PathResult = "once" | "sr" | "Sf" | "pr" | "Pf" | "gr" | "Gf" | "custom" | "deny";
	type DomainResult = "once" | "session" | "project" | "global" | "custom" | "deny";

	function pathScopeLevel(result: string): { scope: AllowScope; level: AccessLevel } | undefined {
		const map: Record<string, { scope: AllowScope; level: AccessLevel }> = {
			sr: { scope: "session", level: "read" }, Sf: { scope: "session", level: "full" },
			pr: { scope: "project", level: "read" }, Pf: { scope: "project", level: "full" },
			gr: { scope: "global", level: "read" },  Gf: { scope: "global", level: "full" },
		};
		return map[result];
	}

	function domainScope(result: string): AllowScope | undefined {
		const map: Record<string, AllowScope> = { session: "session", project: "project", global: "global" };
		return map[result];
	}

	function buildPathSections(showReadColumn: boolean): MenuSection<PathResult>[] {
		const sections: MenuSection<PathResult>[] = [
			{ type: "row", bindings: [{ key: "y", label: "once", value: "once" }] },
			{ type: "spacer" },
		];
		if (showReadColumn) {
			sections.push({
				type: "matrix",
				columns: ["read", "full"],
				rows: [
					{ label: "session", cells: [{ key: "s", label: "", value: "sr" }, { key: "S", label: "", value: "Sf" }] },
					{ label: "project", cells: [{ key: "p", label: "", value: "pr" }, { key: "P", label: "", value: "Pf" }] },
					{ label: "global",  cells: [{ key: "g", label: "", value: "gr" }, { key: "G", label: "", value: "Gf" }] },
				],
			});
		} else {
			sections.push({
				type: "row",
				bindings: [
					{ key: "S", label: "session", value: "Sf" },
					{ key: "P", label: "project", value: "Pf" },
					{ key: "G", label: "global", value: "Gf" },
				],
			});
		}
		return sections;
	}

	function buildPathSubSections(showReadColumn: boolean): MenuSection<PathResult>[] {
		if (showReadColumn) {
			return [{
				type: "matrix",
				columns: ["read", "full"],
				rows: [
					{ label: "session", cells: [{ key: "s", label: "", value: "sr" }, { key: "S", label: "", value: "Sf" }] },
					{ label: "project", cells: [{ key: "p", label: "", value: "pr" }, { key: "P", label: "", value: "Pf" }] },
					{ label: "global",  cells: [{ key: "g", label: "", value: "gr" }, { key: "G", label: "", value: "Gf" }] },
				],
			}];
		}
		return [{
			type: "row",
			bindings: [
				{ key: "S", label: "session", value: "Sf" },
				{ key: "P", label: "project", value: "Pf" },
				{ key: "G", label: "global", value: "Gf" },
			],
		}];
	}

	async function promptBoundaryAccess(
		ctx: { ui: any; hasUI?: boolean },
		operation: string,
		path: string,
		boundary: AccessBoundary,
		allowPersistent = true,
		protectedMode = false,
	): Promise<{ block: boolean; reason?: string } | undefined> {
		if (!ctx.hasUI) return { block: true, reason: `${boundary.kind} access blocked (no UI): ${boundary.dir}` };

		const suggested = boundary.suggestions[0];
		const showRead = operation === "READ" || operation === "BASH";

		if (!allowPersistent) {
			const result = await showTransient(ctx, {
				title: "Sandbox",
				context: [`${operation}  ${path}`, `→  ${suggested.dir}  (${suggested.label})`, "sensitive — once only"],
				sections: [{ type: "row", bindings: [{ key: "y", label: "allow this command", value: "allow" as const }] }],
				cancelValue: "deny" as const,
			});
			return result === "allow" ? undefined : { block: true, reason: `User denied access to ${boundary.dir}` };
		}

		let grace = 500;
		while (true) {
			const result = await showTransient<PathResult>(ctx, {
				title: "Sandbox",
				context: protectedMode
					? [`${operation}  ${path}`, `→  ${suggested.dir}  (${suggested.label})`, "protected path"]
					: [`${operation}  ${path}`, `→  ${suggested.dir}  (${suggested.label})`],
				sections: buildPathSections(showRead),
				footer: [{ key: "e", label: "custom path", value: "custom" }],
				cancelValue: "deny",
				grace,
			});
			grace = 0;

			if (result === "once") return undefined;
			if (result === "deny") return { block: true, reason: `User denied access to ${boundary.dir}` };

			const sl = pathScopeLevel(result);
			if (sl) {
				const saved = protectedMode
					? await addProtectedAllowedDir(suggested.dir, sl.scope, sl.level, ctx)
					: await addAllowedDir(suggested.dir, sl.scope, sl.level, ctx);
				if (!saved) return { block: true, reason: "Could not persist sandbox access" };
				updateStatus(ctx);
				return undefined;
			}

			if (result === "custom") {
				const entered = await ctx.ui.input("Path:", suggested.dir);
				if (!entered?.trim()) continue;
				const dir = await normalizeAllowedDir(entered.trim());

				const subResult = await showTransient<PathResult>(ctx, {
					title: "Sandbox",
					context: protectedMode ? [`custom  ${dir}`, "protected path"] : [`custom  ${dir}`],
					sections: buildPathSubSections(showRead),
					cancelLabel: "back",
					cancelValue: "deny",
					grace: 0,
				});
				if (subResult === "deny") continue;

				const subSl = pathScopeLevel(subResult);
				if (subSl) {
					const saved = protectedMode
						? await addProtectedAllowedDir(dir, subSl.scope, subSl.level, ctx)
						: await addAllowedDir(dir, subSl.scope, subSl.level, ctx);
					if (!saved) return { block: true, reason: "Could not persist sandbox access" };
					updateStatus(ctx);
					return undefined;
				}
			}
		}
	}

	async function promptDomainAccess(
		ctx: { ui: any; hasUI?: boolean },
		domain: string,
		command: string,
	): Promise<{ block: boolean; reason?: string; oneShotPatterns?: string[] } | undefined> {
		if (isDomainDenied(domain)) {
			return {
				block: true,
				reason: `Domain ${domain} is denied by sandbox config (${projectConfigPath} or ${globalConfigPath})`,
			};
		}
		if (!ctx.hasUI) return { block: true, reason: `Domain blocked (no UI): ${domain}` };

		async function handleDomainResult(result: DomainResult, target: string): Promise<{ block: boolean; reason?: string; oneShotPatterns?: string[] } | undefined> {
			if (result === "once") return { block: false, oneShotPatterns: [target] };
			const scope = domainScope(result);
			if (scope) {
				const saved = await addAllowedDomain(target, scope, ctx);
				if (!saved) return { block: true, reason: `Could not persist domain access for ${target}` };
				updateStatus(ctx);
				return { block: false };
			}
			return { block: true, reason: `User denied domain access to ${domain}` };
		}

		const domainBindings: Binding<DomainResult>[] = [
			{ key: "y", label: "once", value: "once" },
			{ key: "s", label: "session", value: "session" },
			{ key: "p", label: "project", value: "project" },
			{ key: "g", label: "global", value: "global" },
		];

		let grace = 500;
		while (true) {
			const result = await showTransient<DomainResult>(ctx, {
				title: "Sandbox",
				context: [`BASH  ${domain}`, `in  ${command}`],
				sections: [{ type: "row", bindings: domainBindings }],
				footer: [{ key: "e", label: "custom pattern", value: "custom" }],
				cancelValue: "deny",
				grace,
			});
			grace = 0;

			if (result !== "custom") return handleDomainResult(result, domain);

			const entered = await ctx.ui.input("Domain or pattern:", domain);
			const normalized = normalizeDomainPattern(entered?.trim() ?? "");
			if (!normalized) { if (!entered?.trim()) continue; ctx.ui.notify("Invalid domain or pattern", "warning"); continue; }

			const subResult = await showTransient<DomainResult>(ctx, {
				title: "Sandbox",
				context: [`custom  ${normalized}`],
				sections: [{ type: "row", bindings: domainBindings }],
				cancelLabel: "back",
				cancelValue: "deny",
				grace: 0,
			});
			if (subResult === "deny") continue;
			return handleDomainResult(subResult, normalized);
		}
	}


	async function ensureProtectedPathAccess(
		ctx: { ui: any; hasUI?: boolean },
		kind: string,
		path: string,
	): Promise<{ block: boolean; reason?: string } | undefined> {
		if (!isProtectedPath(path)) return undefined;
		const operation = kind.toUpperCase();
		if ((operation === "READ" || operation === "BASH") && isInsideProtectedReadableDir(path)) return undefined;
		if (operation !== "READ" && operation !== "BASH" && isInsideProtectedAllowedDir(path)) return undefined;
		const boundary = await accessBoundary(path);
		return promptBoundaryAccess(ctx, operation, path, boundary, true, true);
	}

	async function ensureFileAccess(
		toolName: "read" | "write" | "edit",
		resolved: string,
		ctx: { ui: any; hasUI?: boolean },
	): Promise<{ block: boolean; reason?: string } | undefined> {
		if (isInsideAllowedDir(resolved)) return undefined;
		if (toolName === "read" && isInsideReadableDir(resolved)) return undefined;

		const boundary = await accessBoundary(resolved);
		if (isInsideAllowedDir(boundary.dir)) return undefined;
		if (toolName === "read" && isInsideReadableDir(boundary.dir)) return undefined;

		return promptBoundaryAccess(
			ctx,
			toolName.toUpperCase(),
			resolved,
			boundary,
			true,
		);
	}

	async function resolveCommandPathCandidates(command: string, commandCwd: string): Promise<string[]> {
		const tokens = extractPathLikeTokens(command);
		const resolved = await Promise.all(tokens.map(async (token) => {
			const path = resolvePath(token, commandCwd);
			try {
				return await realpath(path);
			} catch {
				return path;
			}
		}));
		return unique(resolved);
	}

	async function resolveWriteTargetCandidates(command: string, commandCwd: string): Promise<string[]> {
		const targets = unique(splitCompound(command).flatMap((segment) => extractSegmentWriteTargetTokens(segment)));
		const resolved = await Promise.all(targets.map(async (token) => {
			const path = resolvePath(token, commandCwd);
			try {
				return await realpath(path);
			} catch {
				return path;
			}
		}));
		return unique(resolved);
	}


	async function ensureBashPathsAllowed(
		command: string,
		ctx: { ui: any; hasUI?: boolean; cwd: string },
	): Promise<{ block: boolean; reason?: string } | undefined> {
		const exempt = new Set<string>();
		const candidates = await resolveCommandPathCandidates(command, ctx.cwd);
		const promptedBoundaries = new Set<string>();

		for (const path of candidates) {
			const protectedInfo = protectedInfoForPath(path);
			if (protectedInfo && exempt.has(protectedInfo.id)) continue;
			const protectedAccess = await ensureProtectedPathAccess(ctx, "bash", path);
			if (protectedAccess?.block) return protectedAccess;
		}

		for (const path of candidates) {
			const protectedInfo = protectedInfoForPath(path);
			if (protectedInfo && exempt.has(protectedInfo.id)) continue;
			if (isProtectedPath(path)) continue;
			if (isInsideReadableDir(path)) continue;
			const boundary = await accessBoundary(path);
			if (isInsideReadableDir(boundary.dir) || promptedBoundaries.has(boundary.dir)) continue;
			const result = await promptBoundaryAccess(
				ctx,
				"BASH",
				boundary.dir,
				boundary,
			);
			if (result?.block) return result;
			promptedBoundaries.add(boundary.dir);
		}

		return undefined;
	}

	async function ensureBashDomainsAllowed(
		toolCallId: string,
		command: string,
		ctx: { ui: any; hasUI?: boolean },
	): Promise<{ block: boolean; reason?: string } | undefined> {
		const domains = extractCommandDomains(command);
		if (domains.length === 0) return undefined;

		const oneShotPatterns = new Set<string>();
		for (const domain of domains) {
			if (isDomainAllowed(domain, oneShotPatterns)) continue;
			const result = await promptDomainAccess(ctx, domain, command);
			if (result?.block) return result;
			for (const pattern of result?.oneShotPatterns ?? []) oneShotPatterns.add(pattern);
		}

		if (oneShotPatterns.size > 0) pendingOneShotAllowedDomains.set(toolCallId, oneShotPatterns);
		return undefined;
	}

	function isHighRiskApprovedForSession(segment: string): boolean {
		for (const prefix of sessionHighRiskPrefixes) {
			if (matchesCommandPrefix(segment, prefix)) return true;
		}
		return false;
	}

	async function confirmHighRiskBash(
		command: string,
		ctx: { ui: any; hasUI?: boolean },
	): Promise<{ block: boolean; reason?: string } | undefined> {
		const risks = highRiskSegments(command);
		if (risks.length === 0) return undefined;
		if (!ctx.hasUI) return { block: true, reason: `High-risk bash blocked (no UI): ${command}` };

		type HRResult = "once" | "approve" | "edit" | "deny";

		for (const { segment, reasons } of risks) {
			if (isHighRiskApprovedForSession(segment)) continue;
			const suggestedPrefix = defaultHighRiskPrefix(segment);

			const result = await showTransient<HRResult>(ctx, {
				title: "Sandbox",
				context: [
					`BASH  ${segment}`,
					...reasons.map((r) => `·  ${r}`),
				],
				sections: [
					{ type: "row", bindings: [{ key: "y", label: "allow once", value: "once" }] },
					{ type: "row", bindings: [{ key: "a", label: `approve "${suggestedPrefix}" for session`, value: "approve" }] },
					{ type: "row", bindings: [{ key: "e", label: "edit prefix to approve", value: "edit" }] },
				],
				cancelValue: "deny",
			});

			if (result === "once") continue;
			if (result === "approve") {
				sessionHighRiskPrefixes.add(suggestedPrefix);
				persistSessionState();
				continue;
			}
			if (result === "edit") {
				const entered = await ctx.ui.editor("Edit prefix:", suggestedPrefix);
				const prefix = normalizePrefix(entered?.trim() ?? "");
				if (!prefix) return { block: true, reason: "Blocked by user" };
				sessionHighRiskPrefixes.add(prefix);
				persistSessionState();
				continue;
			}
			return { block: true, reason: "Blocked by user" };
		}
		return undefined;
	}

	pi.events.on(SANDBOX_AGENT_CONSTRAINTS_EVENT, (data) => {
		const payload = data as AgentConstraintsEventData;
		currentAgentConstraints = payload?.constraints;
		currentAgentName = payload?.agentName;
	});

	pi.registerFlag("no-os-sandbox", {
		description: "Disable OS-level sandboxing for bash commands",
		type: "boolean",
		default: false,
	});

	pi.registerTool({
		...localBash,
		label: "bash (sandboxed)",
		async execute(id, params, signal, onUpdate, ctx) {
			const toolCwd = ctx?.cwd ?? cwd ?? process.cwd();
			if (!isOsSandboxActive()) {
				const plainBash = createBashTool(toolCwd);
				return plainBash.execute(id, params, signal, onUpdate, ctx);
			}

			const sandboxedBash = createBashTool(toolCwd, { operations: createSandboxedBashOps(id) });
			return sandboxedBash.execute(id, params, signal, onUpdate, ctx);
		},
	});

	pi.on("user_bash", () => {
		if (!isOsSandboxActive()) return;
		return { operations: createSandboxedBashOps() };
	});

	async function initializeProjectState(ctx: { cwd: string; ui: any; sessionManager: any }) {
		cwd = ctx.cwd;
		globalRulesPath = resolve(AGENT_DIR, "sandbox-rules.json");
		globalConfigPath = resolve(AGENT_DIR, "sandbox.json");
		projectRoot = ctx.cwd;

		try {
			const result = await pi.exec("git", ["-C", ctx.cwd, "rev-parse", "--show-toplevel"], { timeout: 3000 });
			if (result.code === 0 && result.stdout.trim()) projectRoot = result.stdout.trim();
		} catch {
			projectRoot = ctx.cwd;
		}
		try { projectRoot = await realpath(projectRoot); } catch { /* keep unresolved root */ }

		projectRulesPath = resolve(projectRoot, ".pi", "sandbox-rules.json");
		projectConfigPath = resolve(projectRoot, ".pi", "sandbox.json");

		const globalRulesLoaded = await loadRulesFromPath(globalRulesPath);
		const projectRulesLoaded = await loadRulesFromPath(projectRulesPath);
		globalRules = globalRulesLoaded.rules;
		projectRules = projectRulesLoaded.rules;
		await normalizeRules(globalRules);
		await normalizeRules(projectRules);
		if (globalRulesLoaded.parseError) {
			ctx.ui.notify(`Could not parse ${globalRulesPath}: ${globalRulesLoaded.parseError}`, "warning");
		} else if (globalRulesLoaded.exists) {
			await saveGlobalRules(ctx);
		}
		if (projectRulesLoaded.parseError) {
			ctx.ui.notify(`Could not parse ${projectRulesPath}: ${projectRulesLoaded.parseError}`, "warning");
		} else if (projectRulesLoaded.exists) {
			await saveProjectRules(ctx);
		}

		const globalConfigLoaded = await loadSandboxConfigPart(globalConfigPath);
		const projectConfigLoaded = await loadSandboxConfigPart(projectConfigPath);
		if (globalConfigLoaded.parseError) ctx.ui.notify(`Could not parse ${globalConfigPath}: ${globalConfigLoaded.parseError}`, "warning");
		if (projectConfigLoaded.parseError) ctx.ui.notify(`Could not parse ${projectConfigPath}: ${projectConfigLoaded.parseError}`, "warning");
		osSandboxConfig = deepMergeSandboxConfig(
			deepMergeSandboxConfig(createDefaultSandboxConfig(projectRoot), globalConfigLoaded.config),
			projectConfigLoaded.config,
		);

		await rebuildProtectedPaths();
		await reconstructSessionState(ctx);
	}

	pi.on("session_start", async (_event, ctx) => {
		await initializeProjectState(ctx);

		const noOsSandbox = pi.getFlag("no-os-sandbox") as boolean;
		if (noOsSandbox) {
			osSandboxEnabled = false;
			osSandboxInitialized = false;
			osSandboxReason = "--no-os-sandbox";
		} else if (!osSandboxConfig?.enabled) {
			osSandboxEnabled = false;
			osSandboxInitialized = false;
			osSandboxReason = "config disabled";
		} else if (process.platform !== "darwin" && process.platform !== "linux") {
			osSandboxEnabled = false;
			osSandboxInitialized = false;
			osSandboxReason = process.platform;
			ctx.ui.notify(`OS sandbox not supported on ${process.platform}`, "warning");
		} else {
			try {
				await withSandboxRuntimeCwd(async () => {
					try { await SandboxManager.reset(); } catch { /* ignore stale state */ }
					await SandboxManager.initialize(effectiveRuntimeConfig(cwd));
				});
				osSandboxEnabled = true;
				osSandboxInitialized = true;
				osSandboxReason = "active";
				ctx.ui.notify("OS sandbox initialized for bash", "info");
			} catch (err) {
				osSandboxEnabled = false;
				osSandboxInitialized = false;
				osSandboxReason = "init failed";
				ctx.ui.notify(`OS sandbox initialization failed: ${err instanceof Error ? err.message : err}`, "warning");
			}
		}

		updateStatus(ctx);
	});

	for (const eventName of ["session_switch", "session_fork", "session_tree"] as const) {
		pi.on(eventName, async (_event, ctx) => {
			await reconstructSessionState(ctx);
			syncRuntimeBaseConfig(ctx.cwd);
		});
	}

	pi.on("session_shutdown", async () => {
		pendingOneShotAllowedDomains.clear();
		if (!osSandboxInitialized) return;
		try {
			await withSandboxRuntimeCwd(() => SandboxManager.reset());
		} catch {
			// Ignore cleanup errors
		} finally {
			osSandboxInitialized = false;
		}
	});

	pi.on("tool_call", async (event, ctx) => {
		const { toolName } = event;

		if (toolName === "read" || toolName === "write" || toolName === "edit") {
			const rawPath = event.input.path as string;
			if (!rawPath) return undefined;

			let resolved = resolvePath(rawPath, ctx.cwd);
			try { resolved = await realpath(resolved); } catch { /* new file */ }

			const protectedAccess = await ensureProtectedPathAccess(ctx, toolName, resolved);
			if (protectedAccess?.block) return protectedAccess;
			noteSensitivePath(resolved);
			if (isProtectedPath(resolved)) return undefined;

			const access = await ensureFileAccess(toolName, resolved, ctx);
			if (access?.block) return access;
			return undefined;
		}

		if (toolName === "bash") {
			const command = event.input.command as string;
			if (!command) return undefined;

			const bc = currentAgentConstraints?.bash;
			if (bc?.allowPrefixes) {
				for (const segment of splitCompound(command)) {
					const segCmd = firstCommand(segment);
					const allowed = bc.allowPrefixes.some((prefix) => matchesCommandPrefix(segment, prefix));
					if (!allowed) {
						const agentName = currentAgentName?.toUpperCase() ?? "CURRENT AGENT";
						return { block: true, reason: `${agentName} mode: "${segCmd}" not allowed (permitted: ${bc.allowPrefixes.join(", ")})` };
					}
				}
			}

			const pathAccess = await ensureBashPathsAllowed(command, ctx);
			if (pathAccess?.block) return pathAccess;

			const domainAccess = await ensureBashDomainsAllowed(event.toolCallId, command, ctx);
			if (domainAccess?.block) return domainAccess;

			const highRisk = await confirmHighRiskBash(command, ctx);
			if (highRisk?.block) return highRisk;
			return undefined;
		}

		return undefined;
	});

	pi.registerCommand("sandbox", {
		description: "Show sandbox status. Usage: /sandbox [clear]",
		handler: async (args, ctx) => {
			const sub = args?.trim();

			if (sub === "clear") {
				const scope = await ctx.ui.select("Clear which approved sandbox access?", [
					"Project rules only",
					"Global rules only",
					"Both",
					"Cancel",
				]);
				if (scope === "Project rules only" || scope === "Both") {
					projectRules = emptyRules();
					await saveProjectRules(ctx);
				}
				if (scope === "Global rules only" || scope === "Both") {
					globalRules = emptyRules();
					await saveGlobalRules(ctx);
				}
				if (scope !== "Cancel") {
					resetSessionState();
					persistSessionState();
					await refreshSensitiveFilePaths();
					syncRuntimeBaseConfig(ctx.cwd);
					updateStatus(ctx);
					ctx.ui.notify("Sandbox access cleared.", "info");
				}
				return;
			}

			function formatSection(label: string, values: string[]): string[] {
				if (values.length === 0) return [`${label}: (none)`];
				return [label + ":", ...values.map((value) => `  - ${value}`)];
			}

			const configuredDomains = configuredAllowedDomains();
			const effectiveDomains = effectiveAllowedDomains();
			const configuredDomainsLabel = configuredDomains === undefined
				? "(unrestricted)"
				: configuredDomains.length > 0
					? configuredDomains.join(", ")
					: "(blocked unless explicitly allowed)";
			const effectiveDomainsLabel = effectiveDomains === undefined
				? "(unrestricted)"
				: effectiveDomains.length > 0
					? effectiveDomains.join(", ")
					: "(blocked)";

			const lines: string[] = [
				`Project root: ${projectRoot}`,
				`OS sandbox: ${isOsSandboxActive() ? "enabled" : `off (${osSandboxReason})`}`,
				`Global rules:  ${globalRulesPath}`,
				`Project rules: ${projectRulesPath}`,
				`Global config: ${globalConfigPath}`,
				`Project config: ${projectConfigPath}`,
				"",
				...formatSection("Full access dirs", activeDirs()),
				"",
				...formatSection("Read-only dirs", currentReadOnlyDirs()),
				"",
				...formatSection("Session full access", [...sessionDirs].sort()),
				"",
				...formatSection("Session read-only", [...sessionReadDirs].sort()),
				"",
				...formatSection("Project full access", projectRules.dirs),
				"",
				...formatSection("Project read-only", projectRules.readDirs ?? []),
				"",
				...formatSection("Global full access", globalRules.dirs),
				"",
				...formatSection("Global read-only", globalRules.readDirs ?? []),
				"",
				...formatSection("Protected full access", currentProtectedDirs()),
				"",
				...formatSection("Protected read-only", currentProtectedReadOnlyDirs()),
				"",
				...formatSection("Session protected full", [...sessionProtectedDirs].sort()),
				"",
				...formatSection("Session protected read-only", [...sessionProtectedReadDirs].sort()),
				"",
				...formatSection("Project protected full", projectRules.protectedDirs ?? []),
				"",
				...formatSection("Project protected read-only", projectRules.protectedReadDirs ?? []),
				"",
				...formatSection("Global protected full", globalRules.protectedDirs ?? []),
				"",
				...formatSection("Global protected read-only", globalRules.protectedReadDirs ?? []),
				"",
				...formatSection("Session allowed domains", [...sessionAllowedDomains].sort()),
				"",
				...formatSection("Project allowed domains", projectRules.allowedDomains ?? []),
				"",
				...formatSection("Global allowed domains", globalRules.allowedDomains ?? []),
				"",
				"Filesystem:",
				`  Base deny read: ${osSandboxConfig?.filesystem?.denyRead?.join(", ") || "(none)"}`,
				`  Effective deny read: ${effectiveDenyRead().join(", ") || "(none)"}`,
				`  Discovered sensitive files: ${sensitiveFilePaths.length}`,
				`  Configured allow write: ${configuredWriteRoots().join(", ") || "(none)"}`,
				`  Effective allow write roots: ${effectiveWriteRoots(cwd).join(", ")}`,
				`  Effective deny write: ${effectiveDenyWrite().join(", ") || "(none)"}`,
				`  Protected sandbox control files: ${protectedControlFiles().join(", ") || "(none)"}`,
				"",
				"Network:",
				`  Configured allowed domains: ${configuredDomainsLabel}`,
				`  Effective allowed domains: ${effectiveDomainsLabel}`,
				"  Unix sockets: unrestricted",
				`  Denied domains: ${effectiveDeniedDomains().join(", ") || "(none)"}`,
				`  Local binding: ${osSandboxConfig?.network?.allowLocalBinding ? "allowed" : "blocked"}`,
			];

			if (sessionHighRiskPrefixes.size > 0) {
				lines.push("", `Session high-risk prefixes (${sessionHighRiskPrefixes.size}):`);
				for (const prefix of [...sessionHighRiskPrefixes].sort()) lines.push(`  ${prefix}`);
			}

			ctx.ui.notify(lines.join("\n"), "info");
		},
	});
}
