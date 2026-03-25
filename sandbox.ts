/**
 * Sandbox extension — prompt-driven allowed dirs plus OS-level bash sandboxing.
 *
 * Behavior:
 *   - read / write / edit auto-allow inside active dirs
 *     (current repo root + approved extra dirs)
 *   - outside-dir access prompts the user and can add the enclosing repo/dir
 *     for the session, this project, or all projects
 *   - approved bash runs inside an OS-level sandbox when available
 *   - bash path prompting is best-effort UX; the OS sandbox is the hard
 *     enforcement boundary for bash
 *   - sensitive file access requires one-time confirmation
 *   - sensitive paths are blocked in bash and denied by the OS sandbox
 *   - high-risk bash commands require one-time or session-prefix approval
 *   - sandbox config/rules/extension writes are meta-protected
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
import { existsSync } from "node:fs";
import { mkdir, readFile, realpath, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import {
	createBashTool,
	createLocalBashOperations,
	getAgentDir,
	type BashOperations,
	type ExtensionAPI,
} from "@mariozechner/pi-coding-agent";

// ── Constants ────────────────────────────────────────────────────────────────

const HOME = homedir();
const AGENT_DIR = getAgentDir();
const AUTH_FILE = resolve(AGENT_DIR, "auth.json");

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

// ── Agent constraints (set by agents extension via globalThis) ───────────────

interface AgentConstraints {
	bash?: {
		allowPrefixes?: string[];
	};
}

declare global {
	var __piAgentConstraints: AgentConstraints | undefined;
	var __piAgentName: string | undefined;
}

function agentConstraints(): AgentConstraints | undefined {
	return globalThis.__piAgentConstraints;
}

// ── Types ────────────────────────────────────────────────────────────────────

interface RulesFile {
	dirs: string[];
	readDirs?: string[];
}

interface SandboxConfig extends SandboxRuntimeConfig {
	enabled?: boolean;
}

type Scope = "project" | "global";
type AllowScope = Scope | "session";

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
	for (const rawToken of tokenize(command)) {
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
	const tokens = tokenize(segment);
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

	// Destructive / privileged local commands
	if (DANGEROUS_PATTERNS.some((p) => p.test(segment))) {
		reasons.add("run a destructive or privileged command");
	}

	// Data exfiltration — env vars sent to LLM provider
	if (cmd === "env" || cmd === "printenv") {
		reasons.add("expose environment variables (sent to LLM provider)");
	}

	// Remote access / data transfer
	if (["scp", "sftp", "ssh", "rsync"].includes(cmd)) {
		reasons.add(`use ${cmd} for remote access or data transfer`);
	}
	if (cmd === "curl" && CURL_UPLOAD_FLAGS.test(segment)) {
		reasons.add("upload data with curl");
	}
	if (cmd === "wget" && WGET_UPLOAD_FLAGS.test(segment)) {
		reasons.add("upload data with wget");
	}

	// Docker — destructive operations
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

	// Kubernetes — mutating operations
	if (cmd === "kubectl") {
		if (/\bkubectl\s+delete\b/.test(segment)) reasons.add("delete Kubernetes resources");
		if (/\bkubectl\s+(apply|replace|patch)\b/.test(segment)) reasons.add("modify Kubernetes resources");
		if (/\bkubectl\s+scale\b/.test(segment)) reasons.add("scale Kubernetes workloads");
		if (/\bkubectl\s+rollout\s+restart\b/.test(segment)) reasons.add("restart Kubernetes workloads");
	}

	// System power / services
	if (["shutdown", "reboot", "halt", "poweroff"].includes(cmd)) {
		reasons.add("change system power state");
	}
	if (cmd === "systemctl" || cmd === "service" || cmd === "launchctl") {
		reasons.add("modify system services");
	}

	// Publishing — irreversible remote side effects
	if (cmd === "npm" && /\bnpm\s+publish\b/.test(segment)) reasons.add("publish package to npm");
	if (cmd === "yarn" && /\byarn\s+publish\b/.test(segment)) reasons.add("publish package to npm");
	if (cmd === "pnpm" && /\bpnpm\s+publish\b/.test(segment)) reasons.add("publish package to npm");
	if (cmd === "cargo" && /\bcargo\s+publish\b/.test(segment)) reasons.add("publish crate");
	if (cmd === "gem" && /\bgem\s+push\b/.test(segment)) reasons.add("publish gem");
	if (cmd === "twine" && /\btwine\s+upload\b/.test(segment)) reasons.add("publish Python package");

	// Infrastructure — can modify or destroy cloud resources
	if (cmd === "terraform") {
		if (/\bterraform\s+(apply|destroy)\b/.test(segment)) reasons.add("modify cloud infrastructure");
	}
	if (cmd === "pulumi") {
		if (/\bpulumi\s+(up|destroy|update)\b/.test(segment)) reasons.add("modify cloud infrastructure");
	}
	if (cmd === "helm") {
		if (/\bhelm\s+(install|upgrade|uninstall|delete|rollback)\b/.test(segment)) reasons.add("modify Kubernetes cluster");
	}

	// GitHub CLI — mutating operations
	if (cmd === "gh") {
		if (/\bgh\s+api\b/.test(segment)) reasons.add("call the GitHub API");
		if (/\bgh\s+pr\s+(create|comment|merge|review)\b/.test(segment)) reasons.add("modify GitHub pull request state");
		if (/\bgh\s+issue\s+comment\b/.test(segment)) reasons.add("comment on a GitHub issue");
		if (/\bgh\s+release\s+(create|edit|upload)\b/.test(segment)) reasons.add("publish or edit a GitHub release");
		if (/\bgh\s+repo\s+create\b/.test(segment)) reasons.add("create a GitHub repository");
		if (/\bgh\s+workflow\s+run\b/.test(segment)) reasons.add("trigger a GitHub workflow");
	}

	// Git — commits and remote operations
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
			denyRead: [
				...SENSITIVE_DIRS,
				...SENSITIVE_EXACT_FILES,
			],
			allowWrite: [projectRoot, "/tmp", "/private/tmp"],
			denyWrite: [
				".env",
				".env.*",
				"*.pem",
				"*.key",
				AUTH_FILE,
			],
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
	return { dirs: [], readDirs: [] };
}

async function loadRulesFromPath(path: string): Promise<LoadedRulesFile> {
	if (!existsSync(path)) return { rules: emptyRules(), exists: false };
	try {
		const parsed = JSON.parse(await readFile(path, "utf-8"));
		return {
			rules: {
				dirs: Array.isArray(parsed.dirs) ? parsed.dirs.filter((v: unknown) => typeof v === "string") : [],
				readDirs: Array.isArray(parsed.readDirs) ? parsed.readDirs.filter((v: unknown) => typeof v === "string") : [],
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
	const sessionApproved = new Set<string>();
	const sessionDirs = new Set<string>();
	const sessionReadDirs = new Set<string>();
	const sessionHighRiskPrefixes = new Set<string>();
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
	const pendingProtectedBashWriteApprovals = new Map<string, Set<string>>();
	let osSandboxConfig: SandboxConfig | undefined;
	let osSandboxEnabled = false;
	let osSandboxInitialized = false;
	let osSandboxReason = "not initialized";

	function isOsSandboxActive(): boolean {
		return osSandboxEnabled && osSandboxInitialized;
	}

	function currentExtraDirs(): string[] {
		return unique([
			...globalRules.dirs,
			...projectRules.dirs,
			...sessionDirs,
		]);
	}

	function currentReadOnlyDirs(): string[] {
		return unique([
			...(globalRules.readDirs ?? []),
			...(projectRules.readDirs ?? []),
			...sessionReadDirs,
		]);
	}

	function activeDirs(): string[] {
		return unique([projectRoot, ...currentExtraDirs()]);
	}

	function readableDirs(): string[] {
		return unique([...activeDirs(), ...currentReadOnlyDirs()]);
	}

	function isInsideAllowedDir(path: string): boolean {
		return activeDirs().some((dir) => isInsideDir(path, dir));
	}

	function isInsideReadableDir(path: string): boolean {
		return readableDirs().some((dir) => isInsideDir(path, dir));
	}

	function updateStatus(ctx: { ui: any }) {
		const parts = [`${projectRoot}`];
		const extraCount = currentExtraDirs().length;
		const readCount = currentReadOnlyDirs().length;
		if (extraCount > 0) parts.push(`+${extraCount} dirs`);
		if (readCount > 0) parts.push(`+${readCount} read-only`);
		parts.push(isOsSandboxActive() ? "os sandbox" : `os off (${osSandboxReason})`);
		ctx.ui.setStatus("sandbox", ctx.ui.theme.fg("accent", parts.join(" · ")));
	}

	function configuredWriteRoots(): string[] {
		return osSandboxConfig?.filesystem?.allowWrite ?? [];
	}

	function effectiveWriteRoots(execCwd: string): string[] {
		return unique([
			...configuredWriteRoots(),
			...activeDirs(),
			execCwd,
			"/tmp",
			"/private/tmp",
		]);
	}

	function effectiveDenyRead(): string[] {
		return unique([
			...(osSandboxConfig?.filesystem?.denyRead ?? []),
			...sensitiveFilePaths,
		]);
	}

	function effectiveDenyWrite(exemptProtectedIds: Iterable<string> = []): string[] {
		const exempt = new Set(exemptProtectedIds);
		return unique([
			...(osSandboxConfig?.filesystem?.denyWrite ?? []),
			...sensitiveFilePaths,
			...[...protectedPaths.entries()]
				.filter(([, info]) => !exempt.has(info.id))
				.map(([path]) => path),
		]);
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
		];
		for (const candidate of candidates) {
			await addProtectedPath(next, candidate.id, candidate.label, candidate.path);
		}
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

	function createSandboxedBashOps(): BashOperations {
		return {
			async exec(command, execCwd, options) {
				if (!existsSync(execCwd)) {
					throw new Error(`Working directory does not exist: ${execCwd}`);
				}

				const approvedProtectedWrites = pendingProtectedBashWriteApprovals.get(command) ?? new Set<string>();
				pendingProtectedBashWriteApprovals.delete(command);

				const customConfig: Partial<SandboxRuntimeConfig> = {
					filesystem: {
						denyRead: effectiveDenyRead(),
						allowWrite: effectiveWriteRoots(execCwd),
						denyWrite: effectiveDenyWrite(approvedProtectedWrites),
						allowGitConfig: osSandboxConfig?.filesystem?.allowGitConfig,
					},
				};

				const wrappedCommand = await SandboxManager.wrapWithSandbox(command, undefined, customConfig);
				return localBashOps.exec(wrappedCommand, execCwd, options);
			},
		};
	}

	async function saveProjectRules(ctx?: { ui: any }): Promise<boolean> {
		try {
			await saveRulesToPath(projectRulesPath, projectRules);
			return true;
		} catch (error) {
			ctx?.ui.notify(
				`Could not save ${projectRulesPath}: ${error instanceof Error ? error.message : error}`,
				"warning",
			);
			return false;
		}
	}

	async function saveGlobalRules(ctx?: { ui: any }): Promise<boolean> {
		try {
			await saveRulesToPath(globalRulesPath, globalRules);
			return true;
		} catch (error) {
			ctx?.ui.notify(
				`Could not save ${globalRulesPath}: ${error instanceof Error ? error.message : error}`,
				"warning",
			);
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

	async function normalizeRulesDirs(rules: RulesFile): Promise<void> {
		rules.dirs = unique(await Promise.all(rules.dirs.map((dir) => normalizeDir(dir)))).sort();
		rules.readDirs = unique(await Promise.all((rules.readDirs ?? []).map((dir) => normalizeDir(dir)))).sort();
	}

	type AccessLevel = "read" | "full";

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
			} else {
				if (!sessionDirs.has(normalized) && !sessionReadDirs.has(normalized)) {
					sessionReadDirs.add(normalized);
					changed = true;
				}
			}
		} else {
			const rules = rulesForScope(scope);
			if (level === "full") {
				rules.readDirs = (rules.readDirs ?? []).filter((d) => d !== normalized);
				if (!rules.dirs.includes(normalized)) {
					const previous = { dirs: [...rules.dirs], readDirs: [...(rules.readDirs ?? [])] };
					rules.dirs.push(normalized);
					rules.dirs = unique(rules.dirs).sort();
					const saved = await saveForScope(scope, ctx);
					if (!saved) {
						rules.dirs = previous.dirs;
						rules.readDirs = previous.readDirs;
						return false;
					}
					changed = true;
				}
			} else {
				if (!rules.dirs.includes(normalized) && !(rules.readDirs ?? []).includes(normalized)) {
					const previous = [...(rules.readDirs ?? [])];
					rules.readDirs = rules.readDirs ?? [];
					rules.readDirs.push(normalized);
					rules.readDirs = unique(rules.readDirs).sort();
					const saved = await saveForScope(scope, ctx);
					if (!saved) {
						rules.readDirs = previous;
						return false;
					}
					changed = true;
				}
			}
		}
		if (changed) await refreshSensitiveFilePaths();
		return true;
	}

	type AccessBoundaryKind = "package" | "repo" | "directory";
	type AccessBoundary = {
		dir: string;
		kind: AccessBoundaryKind;
		suggestions: Array<{ dir: string; kind: AccessBoundaryKind; label: string }>;
	};

	function boundaryKindLabel(kind: AccessBoundaryKind): string {
		if (kind === "package") return "package directory";
		if (kind === "repo") return "repo";
		return "directory";
	}

	function hasProjectMarker(dir: string): boolean {
		return [
			"package.json",
			"pyproject.toml",
			"Cargo.toml",
			"go.mod",
			"Gemfile",
			"composer.json",
		].some((name) => existsSync(resolve(dir, name)));
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
			if (result.code === 0 && result.stdout.trim()) {
				return await normalizeDir(result.stdout.trim());
			}
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

	async function selectScope(ctx: { ui: any }, label: string): Promise<AllowScope | undefined> {
		const choice = await ctx.ui.select(label, [
			"This session",
			"This project (persisted)",
			"All projects (persisted)",
			"Cancel",
		]);
		if (!choice || choice === "Cancel") return undefined;
		return choice.startsWith("All") ? "global" : choice.startsWith("This project") ? "project" : "session";
	}

	async function chooseDifferentPath(
		ctx: { ui: any; hasUI?: boolean },
		boundary: AccessBoundary,
	): Promise<{ dir: string; level: AccessLevel; scope: AllowScope } | undefined> {
		const pathOptions = [
			...boundary.suggestions.map((s) => `${s.label}: ${s.dir}`),
			"Enter a custom path",
			"Cancel",
		];
		const pathChoice = await ctx.ui.select("Choose a path:", pathOptions);
		if (!pathChoice || pathChoice === "Cancel") return undefined;

		let dir: string;
		if (pathChoice === "Enter a custom path") {
			const entered = await ctx.ui.input("Directory to allow:", boundary.dir);
			if (!entered?.trim()) return undefined;
			dir = await normalizeAllowedDir(entered.trim());
		} else {
			const matched = boundary.suggestions.find((s) => pathChoice === `${s.label}: ${s.dir}`);
			if (!matched) return undefined;
			dir = matched.dir;
		}

		const levelChoice = await ctx.ui.select(`Access level for ${dir}:`, [
			"Read only",
			"Full access (read + write)",
			"Cancel",
		]);
		if (!levelChoice || levelChoice === "Cancel") return undefined;
		const level: AccessLevel = levelChoice.startsWith("Full") ? "full" : "read";

		const scope = await selectScope(ctx, `Allow ${level === "full" ? "full access to" : "reading"} ${dir} for:`);
		if (!scope) return undefined;
		return { dir, level, scope };
	}

	async function promptBoundaryAccess(
		ctx: { ui: any; hasUI?: boolean },
		header: string,
		boundary: AccessBoundary,
		onceKey?: string,
		allowPersistent = true,
	): Promise<{ block: boolean; reason?: string } | undefined> {
		if (!ctx.hasUI) return { block: true, reason: `${boundary.kind} access blocked (no UI): ${boundary.dir}` };

		const suggested = boundary.suggestions[0];
		const suggestedLabel = `${suggested.label}: ${suggested.dir}`;
		const READ_OPT = `Allow reading ${suggestedLabel}...`;
		const FULL_OPT = `Allow full access to ${suggestedLabel}...`;
		const DIFFERENT_OPT = "Choose a different path...";
		const options = allowPersistent
			? [
				"Allow once",
				READ_OPT,
				FULL_OPT,
				DIFFERENT_OPT,
				"Deny",
			]
			: ["Allow once", "Deny"];
		const choice = await ctx.ui.select(
			allowPersistent
				? `${header}\n\nSuggested ${suggestedLabel}`
				: `${header}\n\nSuggested ${suggestedLabel}\n\nSensitive paths can only be allowed once.`,
			options,
		);

		if (choice === "Allow once") {
			if (onceKey) sessionApproved.add(onceKey);
			return undefined;
		}

		let selectedDir: string | undefined;
		let selectedScope: AllowScope | undefined;
		let selectedLevel: AccessLevel | undefined;

		if (choice === READ_OPT || choice === FULL_OPT) {
			selectedLevel = choice === FULL_OPT ? "full" : "read";
			const scopeLabel = selectedLevel === "full"
				? `Allow full access to ${suggestedLabel} for:`
				: `Allow reading ${suggestedLabel} for:`;
			selectedScope = await selectScope(ctx, scopeLabel);
			if (!selectedScope) return { block: true, reason: "User cancelled scope selection" };
			selectedDir = suggested.dir;
		} else if (choice === DIFFERENT_OPT) {
			const result = await chooseDifferentPath(ctx, boundary);
			if (!result) return { block: true, reason: "User cancelled path selection" };
			selectedDir = result.dir;
			selectedScope = result.scope;
			selectedLevel = result.level;
		}

		if (selectedDir && selectedScope && selectedLevel) {
			const saved = await addAllowedDir(selectedDir, selectedScope, selectedLevel, ctx);
			if (!saved) return { block: true, reason: "Could not persist sandbox access" };
			updateStatus(ctx);
			return undefined;
		}

		return { block: true, reason: `User denied access to ${boundary.dir}` };
	}

	async function confirmSensitiveAccess(
		ctx: { ui: any; hasUI?: boolean },
		kind: string,
		path: string,
		context?: string,
	): Promise<{ block: boolean; reason?: string } | undefined> {
		if (!isSensitivePath(path)) return undefined;
		if (!ctx.hasUI) return { block: true, reason: `${kind} sensitive path blocked (no UI): ${path}` };

		const header = context
			? `Sensitive ${kind} request:\n\n  ${path}\n\n(in: ${context})\n\nThis may expose credentials or secrets. Allow once?`
			: `Sensitive ${kind} request:\n\n  ${path}\n\nThis may expose credentials or secrets. Allow once?`;

		const choice = await ctx.ui.select(header, ["Yes (once)", "No"]);
		if (choice === "Yes (once)") return undefined;
		return { block: true, reason: `Blocked sensitive ${kind}: ${path}` };
	}

	async function ensureFileAccess(
		toolName: "read" | "write" | "edit",
		resolved: string,
		ctx: { ui: any; hasUI?: boolean },
	): Promise<{ block: boolean; reason?: string } | undefined> {
		const onceKey = `file:${toolName}:${resolved}`;
		if (sessionApproved.has(onceKey)) return undefined;
		if (isInsideAllowedDir(resolved)) return undefined;
		if (toolName === "read" && isInsideReadableDir(resolved)) return undefined;

		const boundary = await accessBoundary(resolved);
		if (isInsideAllowedDir(boundary.dir)) return undefined;
		if (toolName === "read" && isInsideReadableDir(boundary.dir)) return undefined;

		return promptBoundaryAccess(
			ctx,
			`${toolName.toUpperCase()} outside allowed dirs:\n\n  ${resolved}`,
			boundary,
			onceKey,
			!isSensitivePath(resolved),
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

	async function confirmProtectedWriteAccess(
		ctx: { ui: any; hasUI?: boolean },
		kind: string,
		path: string,
		label: string,
		context?: string,
	): Promise<{ block: boolean; reason?: string } | undefined> {
		if (!ctx.hasUI) return { block: true, reason: `${kind} protected path blocked (no UI): ${path}` };

		const header = context
			? `The model wants to modify the ${label} via ${kind.toUpperCase()}:\n\n  ${path}\n\n(in: ${context})\n\nThis controls what the model is allowed to do. Allow once?`
			: `The model wants to modify the ${label}:\n\n  ${path}\n\nThis controls what the model is allowed to do. Allow once?`;

		const choice = await ctx.ui.select(header, ["Yes (once)", "No"]);
		if (choice === "Yes (once)") return undefined;
		return { block: true, reason: `Blocked modification of ${label}` };
	}

	// Best effort only: catches explicit path usage in common shell commands, while
	// the OS sandbox remains the real filesystem enforcement boundary for bash.
	async function ensureBashPathsAllowed(
		command: string,
		ctx: { ui: any; hasUI?: boolean; cwd: string },
		exemptProtectedIds: Iterable<string> = [],
	): Promise<{ block: boolean; reason?: string } | undefined> {
		const exempt = new Set(exemptProtectedIds);
		const candidates = await resolveCommandPathCandidates(command, ctx.cwd);
		const promptedBoundaries = new Set<string>();

		for (const path of candidates) {
			const protectedInfo = protectedInfoForPath(path);
			if (protectedInfo && exempt.has(protectedInfo.id)) continue;
			const sensitive = await confirmSensitiveAccess(ctx, "bash", path, command);
			if (sensitive?.block) return sensitive;
		}

		for (const path of candidates) {
			const protectedInfo = protectedInfoForPath(path);
			if (protectedInfo && exempt.has(protectedInfo.id)) continue;
			if (isInsideReadableDir(path)) continue;
			const boundary = await accessBoundary(path);
			if (isInsideReadableDir(boundary.dir) || promptedBoundaries.has(boundary.dir)) continue;
			const result = await promptBoundaryAccess(
				ctx,
				`Bash wants to access a ${boundary.kind} outside allowed dirs:\n\n  ${boundary.dir}\n\n(in: ${command})`,
				boundary,
			);
			if (result?.block) return result;
			promptedBoundaries.add(boundary.dir);
		}

		return undefined;
	}

	async function confirmProtectedBashWrites(
		command: string,
		ctx: { ui: any; hasUI?: boolean; cwd: string },
	): Promise<{ block: boolean; reason?: string; approvedIds?: string[] } | undefined> {
		const targets = await resolveWriteTargetCandidates(command, ctx.cwd);
		const infos = protectedInfosForPaths(targets);
		if (infos.length === 0) return undefined;

		for (const info of infos) {
			const ok = await confirmProtectedWriteAccess(ctx, "bash", info.id, info.label, command);
			if (ok?.block) return ok;
		}

		return { block: false, approvedIds: infos.map((info) => info.id) };
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

		for (const { segment, reasons } of risks) {
			if (isHighRiskApprovedForSession(segment)) continue;
			const suggestedPrefix = defaultHighRiskPrefix(segment);
			const ALLOW_PREFIX_OPT = `Allow "${suggestedPrefix}" for this session`;
			const CUSTOM_PREFIX_OPT = "Allow a different prefix for this session...";
			const choice = await ctx.ui.select(
				`High-risk bash command:\n\n  ${segment}\n\n(in: ${command})\n\nWhy this needs approval:\n  - ${reasons.join("\n  - ")}`,
				["Yes (once)", ALLOW_PREFIX_OPT, CUSTOM_PREFIX_OPT, "No"],
			);
			if (choice === "Yes (once)") continue;
			if (choice === ALLOW_PREFIX_OPT) {
				sessionHighRiskPrefixes.add(suggestedPrefix);
				continue;
			}
			if (choice === CUSTOM_PREFIX_OPT) {
				const entered = await ctx.ui.editor(
					"Edit the prefix to allow for this session (single line):",
					suggestedPrefix,
				);
				const prefix = normalizePrefix(entered?.trim() ?? "");
				if (!prefix) return { block: true, reason: "Blocked by user" };
				sessionHighRiskPrefixes.add(prefix);
				continue;
			}
			return { block: true, reason: "Blocked by user" };
		}
		return undefined;
	}

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

			const sandboxedBash = createBashTool(toolCwd, {
				operations: createSandboxedBashOps(),
			});
			return sandboxedBash.execute(id, params, signal, onUpdate, ctx);
		},
	});

	pi.on("user_bash", () => {
		if (!isOsSandboxActive()) return;
		return { operations: createSandboxedBashOps() };
	});

	pi.on("session_start", async (_event, ctx) => {
		cwd = ctx.cwd;
		globalRulesPath = resolve(AGENT_DIR, "sandbox-rules.json");
		globalConfigPath = resolve(AGENT_DIR, "sandbox.json");
		projectRoot = ctx.cwd;

		try {
			const result = await pi.exec("git", ["-C", ctx.cwd, "rev-parse", "--show-toplevel"], { timeout: 3000 });
			if (result.code === 0 && result.stdout.trim()) {
				projectRoot = result.stdout.trim();
			}
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
		await normalizeRulesDirs(globalRules);
		await normalizeRulesDirs(projectRules);
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
		if (globalConfigLoaded.parseError) {
			ctx.ui.notify(`Could not parse ${globalConfigPath}: ${globalConfigLoaded.parseError}`, "warning");
		}
		if (projectConfigLoaded.parseError) {
			ctx.ui.notify(`Could not parse ${projectConfigPath}: ${projectConfigLoaded.parseError}`, "warning");
		}
		osSandboxConfig = deepMergeSandboxConfig(
			deepMergeSandboxConfig(createDefaultSandboxConfig(projectRoot), globalConfigLoaded.config),
			projectConfigLoaded.config,
		);
		await rebuildProtectedPaths();
		await refreshSensitiveFilePaths();

		// AGENT_DIR is readable by default — writes require explicit approval.
		sessionReadDirs.add(AGENT_DIR);

		const noOsSandbox = pi.getFlag("no-os-sandbox") as boolean;
		if (noOsSandbox) {
			osSandboxEnabled = false;
			osSandboxInitialized = false;
			osSandboxReason = "--no-os-sandbox";
		} else if (!osSandboxConfig.enabled) {
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
				const configExt = osSandboxConfig as SandboxConfig & {
					ignoreViolations?: Record<string, string[]>;
					enableWeakerNestedSandbox?: boolean;
				};
				try { await SandboxManager.reset(); } catch { /* ignore stale state */ }
				await SandboxManager.initialize({
					network: osSandboxConfig.network,
					filesystem: osSandboxConfig.filesystem,
					ignoreViolations: configExt.ignoreViolations,
					enableWeakerNestedSandbox: configExt.enableWeakerNestedSandbox,
				});
				osSandboxEnabled = true;
				osSandboxInitialized = true;
				osSandboxReason = "active";
				ctx.ui.notify("OS sandbox initialized for bash", "info");
			} catch (err) {
				osSandboxEnabled = false;
				osSandboxInitialized = false;
				osSandboxReason = "init failed";
				ctx.ui.notify(
					`OS sandbox initialization failed: ${err instanceof Error ? err.message : err}`,
					"warning",
				);
			}
		}

		updateStatus(ctx);
	});

	pi.on("session_shutdown", async () => {
		pendingProtectedBashWriteApprovals.clear();
		sessionHighRiskPrefixes.clear();
		if (!osSandboxInitialized) return;
		try {
			await SandboxManager.reset();
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

			if (toolName === "write" || toolName === "edit") {
				const protectedInfo = protectedInfoForPath(resolved);
				if (protectedInfo) {
					return confirmProtectedWriteAccess(ctx, toolName, resolved, protectedInfo.label);
				}
			}

			const sensitive = await confirmSensitiveAccess(ctx, toolName, resolved);
			if (sensitive?.block) return sensitive;
			noteSensitivePath(resolved);

			const access = await ensureFileAccess(toolName, resolved, ctx);
			if (access?.block) return access;

			return undefined;
		}

		if (toolName === "bash") {
			const command = event.input.command as string;
			if (!command) return undefined;

			const bc = agentConstraints()?.bash;
			if (bc?.allowPrefixes) {
				for (const segment of splitCompound(command)) {
					const segCmd = firstCommand(segment);
					const allowed = bc.allowPrefixes.some((prefix) => matchesCommandPrefix(segment, prefix));
					if (!allowed) {
						const agentName = globalThis.__piAgentName?.toUpperCase() ?? "Current agent";
						return { block: true, reason: `${agentName} mode: "${segCmd}" not allowed (permitted: ${bc.allowPrefixes.join(", ")})` };
					}
				}
			}

			const protectedWrite = await confirmProtectedBashWrites(command, ctx);
			if (protectedWrite?.block) return protectedWrite;
			const approvedProtectedIds = protectedWrite?.approvedIds ?? [];

			const pathAccess = await ensureBashPathsAllowed(command, ctx, approvedProtectedIds);
			if (pathAccess?.block) return pathAccess;

			const highRisk = await confirmHighRiskBash(command, ctx);
			if (highRisk?.block) return highRisk;

			if (approvedProtectedIds.length > 0) {
				pendingProtectedBashWriteApprovals.set(command, new Set(approvedProtectedIds));
			}
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
					sessionApproved.clear();
					sessionDirs.clear();
					sessionReadDirs.clear();
					sessionHighRiskPrefixes.clear();
					pendingProtectedBashWriteApprovals.clear();
					// Re-add default read-only dirs after clear.
					sessionReadDirs.add(AGENT_DIR);
					await refreshSensitiveFilePaths();
					updateStatus(ctx);
					ctx.ui.notify("Sandbox access cleared.", "info");
				}
				return;
			}

			function formatDirSection(label: string, dirs: string[]): string[] {
				if (dirs.length === 0) return [`${label}: (none)`];
				return [label + ":", ...dirs.map((dir) => `  - ${dir}`)];
			}

			const allowedDomains = osSandboxConfig?.network?.allowedDomains;
			const allowedDomainsLabel = allowedDomains === undefined
				? "(unrestricted)"
				: allowedDomains.length > 0
					? allowedDomains.join(", ")
					: "(blocked)";

			const lines: string[] = [
				`Project root: ${projectRoot}`,
				`OS sandbox: ${isOsSandboxActive() ? "enabled" : `off (${osSandboxReason})`}`,
				`Global rules:  ${globalRulesPath}`,
				`Project rules: ${projectRulesPath}`,
				`Global config: ${globalConfigPath}`,
				`Project config: ${projectConfigPath}`,
				"",
				...formatDirSection("Full access dirs", activeDirs()),
				"",
				...formatDirSection("Read-only dirs", currentReadOnlyDirs()),
				"",
				...formatDirSection("Session full access", [...sessionDirs]),
				"",
				...formatDirSection("Session read-only", [...sessionReadDirs]),
				"",
				...formatDirSection("Project full access", projectRules.dirs),
				"",
				...formatDirSection("Project read-only", projectRules.readDirs ?? []),
				"",
				...formatDirSection("Global full access", globalRules.dirs),
				"",
				...formatDirSection("Global read-only", globalRules.readDirs ?? []),
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
				`  Allowed domains: ${allowedDomainsLabel}`,
				`  Denied domains: ${osSandboxConfig?.network?.deniedDomains?.join(", ") || "(none)"}`,
				`  Local binding: ${osSandboxConfig?.network?.allowLocalBinding ? "allowed" : "blocked"}`,
			];

			if (sessionApproved.size > 0) {
				lines.push("", `Session one-off approvals (${sessionApproved.size}):`);
				for (const approval of sessionApproved) lines.push(`  ${approval}`);
			}
			if (sessionHighRiskPrefixes.size > 0) {
				lines.push("", `Session high-risk prefixes (${sessionHighRiskPrefixes.size}):`);
				for (const prefix of sessionHighRiskPrefixes) lines.push(`  ${prefix}`);
			}

			ctx.ui.notify(lines.join("\n"), "info");
		},
	});
}
