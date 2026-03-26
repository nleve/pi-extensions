import { basename, dirname, isAbsolute, relative, resolve } from "node:path";
import { existsSync } from "node:fs";
import { realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";

const HOME = homedir();
const SENSITIVE_DIRS = [
	resolve(HOME, ".ssh"),
	resolve(HOME, ".aws"),
	resolve(HOME, ".gnupg"),
	resolve(HOME, ".config", "gcloud"),
	resolve(HOME, ".config", "gh"),
	resolve(HOME, ".kube"),
];

export interface AccessBoundary {
	dir: string;
	kind: "package" | "repo" | "directory";
	suggestions: Array<{ dir: string; kind: AccessBoundary["kind"]; label: string }>;
}

export function unique<T>(items: Iterable<T>): T[] {
	return [...new Set(items)];
}

export function expandHome(value: string): string {
	if (value === "~") return HOME;
	if (value.startsWith("~/")) return resolve(HOME, value.slice(2));
	return value;
}

export function resolvePath(raw: string, cwd: string): string {
	const cleaned = expandHome(raw.startsWith("@") ? raw.slice(1) : raw);
	return isAbsolute(cleaned) ? cleaned : resolve(cwd, cleaned);
}

export async function realpathIfExists(path: string): Promise<string> {
	try {
		return await realpath(path);
	} catch {
		return path;
	}
}

export function isInsideDir(filePath: string, root: string): boolean {
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
	) return trimmed.slice(1, -1);
	return trimmed;
}

export function firstCommand(cmd: string): string {
	return stripEnvAssignments(cmd).split(/[\s;|&<>]/)[0] ?? "";
}

export function normalizePrefix(prefix: string): string {
	return prefix.trim().replace(/\s+/g, " ");
}

export function matchesCommandPrefix(command: string, prefix: string): boolean {
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
		for (const match of line.matchAll(/<<(-)?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/g)) {
			const delimiter = match[3];
			const allowIndent = !!match[1];
			for (i += 1; i < lines.length; i++) {
				const candidate = allowIndent ? lines[i].replace(/^\t+/, "") : lines[i];
				if (candidate.trimEnd() === delimiter) break;
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
	for (let i = 0; i < command.length; i++) {
		const ch = command[i];
		if (ch === "'" && !inDouble) {
			inSingle = !inSingle;
			current += ch;
			continue;
		}
		if (ch === '"' && !inSingle) {
			inDouble = !inDouble;
			current += ch;
			continue;
		}
		if (ch === "\\" && !inSingle && i + 1 < command.length) {
			current += ch + command[++i];
			continue;
		}
		if (!inSingle && !inDouble && /\s/.test(ch)) {
			if (current) tokens.push(current);
			current = "";
			continue;
		}
		current += ch;
	}
	if (current) tokens.push(current);
	return tokens;
}

function inspectionTokens(command: string): string[] {
	const rawTokens = shellTokenize(stripHeredocBodies(stripEnvAssignments(command)));
	if (rawTokens.length === 0) return rawTokens;
	const interpreter = rawTokens[0] === "env"
		? rawTokens.find((token, index) => index > 0 && !token.startsWith("-"))
		: rawTokens[0];
	if (!interpreter) return rawTokens;
	const inlineFlagInterpreters = new Set(["node", "python", "python3", "ruby", "perl", "php", "lua", "bash", "sh", "zsh", "fish"]);
	if (!inlineFlagInterpreters.has(interpreter)) return rawTokens;
	const skipNextArgFlags = new Set(["-e", "--eval", "-c", "--command"]);
	const filtered: string[] = [];
	for (let i = 0; i < rawTokens.length; i++) {
		filtered.push(rawTokens[i]);
		if (skipNextArgFlags.has(rawTokens[i])) i += 1;
	}
	return filtered;
}

export function splitCompound(cmd: string): string[] {
	const segments: string[] = [];
	let current = "";
	let inSingle = false;
	let inDouble = false;
	for (let i = 0; i < cmd.length; i++) {
		const ch = cmd[i];
		if (ch === "'" && !inDouble) { inSingle = !inSingle; current += ch; continue; }
		if (ch === '"' && !inSingle) { inDouble = !inDouble; current += ch; continue; }
		if (ch === "\\" && !inSingle && i + 1 < cmd.length) { current += ch + cmd[++i]; continue; }
		if (!inSingle && !inDouble) {
			if ((ch === "&" && cmd[i + 1] === "&") || (ch === "|" && cmd[i + 1] === "|")) {
				segments.push(current);
				current = "";
				i += 1;
				continue;
			}
			if (ch === ";" || ch === "|") {
				segments.push(current);
				current = "";
				continue;
			}
		}
		current += ch;
	}
	if (current.trim()) segments.push(current);
	return segments.map((s) => s.trim()).filter(Boolean);
}

function parseGitSubcommand(segment: string): { sub?: string; args: string[] } {
	const tokens = tokenize(segment);
	if (tokens[0] !== "git") return { args: [] };
	let i = 1;
	while (i < tokens.length && tokens[i].startsWith("-")) {
		if (["-c", "-C", "--git-dir", "--work-tree", "--namespace", "--config-env"].includes(tokens[i])) i += 2;
		else i += 1;
	}
	return { sub: tokens[i], args: tokens.slice(i + 1) };
}

export function isSensitiveBasename(name: string): boolean {
	const lower = name.toLowerCase();
	return lower === ".env" || lower.startsWith(".env.") || lower.endsWith(".pem") || lower.endsWith(".key");
}

export function isSensitivePath(path: string, sensitiveExactFiles: Set<string>): boolean {
	const absolute = isAbsolute(path) ? expandHome(path) : resolve(process.cwd(), expandHome(path));
	if (isSensitiveBasename(basename(absolute))) return true;
	if (sensitiveExactFiles.has(absolute)) return true;
	return SENSITIVE_DIRS.some((dir) => isInsideDir(absolute, dir));
}

function looksLikePathToken(token: string): boolean {
	if (!token || /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(token)) return false;
	return token === "."
		|| token === ".."
		|| token === "~"
		|| token.startsWith("~/")
		|| token.startsWith("./")
		|| token.startsWith("../")
		|| token.startsWith("/")
		|| token.startsWith(".")
		|| token.includes("/")
		|| isSensitiveBasename(token);
}

function normalizePathLikeToken(rawToken: string): string | undefined {
	let token = stripOuterQuotes(rawToken);
	if (!token) return;
	if (token.startsWith("-") && token.includes("=")) token = stripOuterQuotes(token.slice(token.indexOf("=") + 1));
	const redirected = token.match(/^\d*(>>?|<)(.+)$/);
	if (redirected?.[2]) token = stripOuterQuotes(redirected[2]);
	return looksLikePathToken(token) ? token : undefined;
}

export function extractPathLikeTokens(command: string): string[] {
	return unique(inspectionTokens(command).map(normalizePathLikeToken).filter(Boolean) as string[]);
}

export function normalizeDomainPattern(value: string): string | undefined {
	let candidate = stripOuterQuotes(value).trim().toLowerCase();
	if (!candidate) return;
	if (/^(https?|wss?):\/\//.test(candidate)) {
		try {
			candidate = new URL(candidate).hostname.toLowerCase();
		} catch {
			return;
		}
	} else {
		candidate = candidate.replace(/^[a-z]+:\/\//, "").split(/[/?#:]/)[0] ?? candidate;
	}
	if (!candidate) return;
	if (!candidate.startsWith("*.")) return candidate;
	const rest = candidate.slice(2).replace(/^\.+/, "");
	return rest ? `*.${rest}` : undefined;
}

export function domainMatchesPattern(domain: string, pattern: string): boolean {
	const normalizedDomain = normalizeDomainPattern(domain);
	const normalizedPattern = normalizeDomainPattern(pattern);
	if (!normalizedDomain || !normalizedPattern) return false;
	return normalizedPattern.startsWith("*.")
		? normalizedDomain.endsWith(`.${normalizedPattern.slice(2)}`)
		: normalizedDomain === normalizedPattern;
}

export function extractCommandDomains(command: string): string[] {
	const domains: string[] = [];
	for (const rawToken of inspectionTokens(command)) {
		for (const candidate of [stripOuterQuotes(rawToken), ...(rawToken.startsWith("-") && rawToken.includes("=") ? [stripOuterQuotes(rawToken.slice(rawToken.indexOf("=") + 1))] : [])]) {
			const normalized = normalizeDomainPattern(candidate);
			if (normalized && /^(https?|wss?):\/\//.test(candidate)) domains.push(normalized);
		}
	}
	return unique(domains);
}

const DANGEROUS_PATTERNS = [/\brm\s+(-rf?|--recursive)/i, /\bsudo\b/i, /\b(chmod|chown)\b.*777/i];
const CURL_UPLOAD_FLAGS = /(^|\s)(-T|--upload-file|-F|--form|--data(?:-ascii|-binary|-raw|-urlencode)?|--json)(\s|=|$)/;
const WGET_UPLOAD_FLAGS = /(^|\s)(--post-data|--post-file|--body-data|--body-file)(\s|=|$)/;

export function defaultHighRiskPrefix(segment: string): string {
	const tokens = tokenize(segment);
	const cmd = tokens[0] ?? "";
	if (!cmd) return normalizePrefix(segment);
	if (cmd === "git") return normalizePrefix(parseGitSubcommand(segment).sub ? `git ${parseGitSubcommand(segment).sub}` : "git");
	if (cmd === "gh") return normalizePrefix(["gh", tokens[1], ["pr", "release", "repo", "workflow", "issue"].includes(tokens[1] ?? "") ? tokens[2] : undefined].filter(Boolean).join(" "));
	if (cmd === "docker") return normalizePrefix(["docker", tokens[1] === "compose" ? "compose" : tokens[1], tokens[1] === "compose" ? tokens[2] : undefined].filter(Boolean).join(" "));
	if (["kubectl", "helm", "terraform", "pulumi"].includes(cmd)) return normalizePrefix([cmd, tokens[1]].filter(Boolean).join(" "));
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
		if (/\bdocker\s+compose\s+down\b/.test(segment) && (/\s-v(\s|$)/.test(segment) || /\s--volumes(\s|$)/.test(segment))) reasons.add("remove Docker Compose volumes and their data");
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
	if (["systemctl", "service", "launchctl"].includes(cmd)) reasons.add("modify system services");
	if (["npm", "yarn", "pnpm"].includes(cmd) && new RegExp(`\\b${cmd}\\s+publish\\b`).test(segment)) reasons.add("publish package to npm");
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
		if (sub === "clean" && args.some((arg) => arg === "-f" || arg === "--force" || /^-[^-]*f/.test(arg))) reasons.add("delete files with git clean");
	}
	return [...reasons];
}

export function highRiskSegments(command: string): Array<{ segment: string; reasons: string[] }> {
	return splitCompound(command)
		.map((segment) => ({ segment, reasons: segmentHighRiskReasons(segment) }))
		.filter(({ reasons }) => reasons.length > 0);
}

function boundaryKindLabel(kind: AccessBoundary["kind"]): string {
	return kind === "package" ? "package directory" : kind === "repo" ? "repo" : "directory";
}

function hasProjectMarker(dir: string): boolean {
	return ["package.json", "pyproject.toml", "Cargo.toml", "go.mod", "Gemfile", "composer.json"].some((name) => existsSync(resolve(dir, name)));
}

async function findNearestProjectLikeRoot(dir: string, normalizeDir: (path: string) => Promise<string>, stopAt?: string): Promise<string | undefined> {
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

export async function accessBoundary(
	path: string,
	deps: {
		normalizeDir: (path: string) => Promise<string>;
		findRepoRoot: (dir: string) => Promise<string | undefined>;
	},
): Promise<AccessBoundary> {
	let dir = path;
	try {
		if (!(await stat(path)).isDirectory()) dir = dirname(path);
	} catch {
		dir = dirname(path);
	}
	dir = await deps.normalizeDir(dir);
	const repo = await deps.findRepoRoot(dir);
	const packageRoot = await findNearestProjectLikeRoot(dir, deps.normalizeDir, repo);
	const suggestions = unique([
		packageRoot ? `${packageRoot}::package` : undefined,
		repo ? `${repo}::repo` : undefined,
		`${dir}::directory`,
	].filter(Boolean) as string[]).map((entry) => {
		const [suggestedDir, kind] = entry.split("::") as [string, AccessBoundary["kind"]];
		return { dir: suggestedDir, kind, label: boundaryKindLabel(kind) };
	});
	return packageRoot ? { dir: packageRoot, kind: "package", suggestions }
		: repo ? { dir: repo, kind: "repo", suggestions }
		: { dir, kind: "directory", suggestions };
}
