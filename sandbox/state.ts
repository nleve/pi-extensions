import { dirname, isAbsolute, resolve } from "node:path";
import { existsSync } from "node:fs";
import { mkdir, readFile, realpath, stat, writeFile } from "node:fs/promises";
import type { SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { expandHome, normalizeDomainPattern, realpathIfExists, unique } from "./policy";

export interface RulesFile {
	dirs: string[];
	readDirs?: string[];
	protectedDirs?: string[];
	protectedReadDirs?: string[];
	allowedDomains?: string[];
}

export interface SandboxConfig extends SandboxRuntimeConfig {
	enabled?: boolean;
}

export type Scope = "project" | "global";
export type AllowScope = Scope | "session";
export type AccessLevel = "read" | "full";

export interface ProtectedPathInfo {
	id: string;
	label: string;
}

export interface LoadedRulesFile {
	rules: RulesFile;
	exists: boolean;
	parseError?: string;
}

export interface LoadedSandboxConfigPart {
	config: Partial<SandboxConfig>;
	parseError?: string;
}

export interface SessionStateData {
	version: 1;
	dirs: string[];
	readDirs: string[];
	protectedDirs: string[];
	protectedReadDirs: string[];
	highRiskPrefixes: string[];
	allowedDomains: string[];
}

export interface SessionSets {
	dirs: Set<string>;
	readDirs: Set<string>;
	protectedDirs: Set<string>;
	protectedReadDirs: Set<string>;
	highRiskPrefixes: Set<string>;
	allowedDomains: Set<string>;
}

export const IMPLICIT_BASH_READ_PATHS = ["/dev/null", "/dev/tty", "/dev/stdin", "/dev/stdout", "/dev/stderr"];
export const SENSITIVE_SCAN_PRUNE_DIRS = [".git", "node_modules", ".next", "dist", "build", "target", ".venv", "venv"];

export function createDefaultSandboxConfig(projectRoot: string): SandboxConfig {
	return {
		enabled: true,
		network: {
			allowLocalBinding: true,
			allowedDomains: [
				"localhost", "127.0.0.1", "github.com", "*.github.com", "api.github.com", "raw.githubusercontent.com",
				"objects.githubusercontent.com", "npmjs.org", "*.npmjs.org", "registry.npmjs.org", "registry.yarnpkg.com",
				"pypi.org", "*.pypi.org", "files.pythonhosted.org", "go.dev", "pkg.go.dev", "proxy.golang.org",
				"sum.golang.org", "crates.io", "*.crates.io", "index.crates.io", "static.crates.io", "rubygems.org",
				"*.rubygems.org", "repo.maven.apache.org", "repo1.maven.org", "plugins.gradle.org", "services.gradle.org",
				"maven.google.com", "dl.google.com", "registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com",
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

export function deepMergeSandboxConfig(base: SandboxConfig, overrides: Partial<SandboxConfig>): SandboxConfig {
	const result: SandboxConfig = { ...base };
	if (overrides.enabled !== undefined) result.enabled = overrides.enabled;
	if (overrides.network) result.network = { ...(base.network ?? {}), ...overrides.network };
	if (overrides.filesystem) result.filesystem = { ...(base.filesystem ?? {}), ...overrides.filesystem };
	const extOverrides = overrides as { ignoreViolations?: Record<string, string[]>; enableWeakerNestedSandbox?: boolean };
	const extResult = result as { ignoreViolations?: Record<string, string[]>; enableWeakerNestedSandbox?: boolean };
	if (extOverrides.ignoreViolations) extResult.ignoreViolations = extOverrides.ignoreViolations;
	if (extOverrides.enableWeakerNestedSandbox !== undefined) extResult.enableWeakerNestedSandbox = extOverrides.enableWeakerNestedSandbox;
	return result;
}

export async function loadSandboxConfigPart(path: string): Promise<LoadedSandboxConfigPart> {
	if (!existsSync(path)) return { config: {} };
	try {
		return { config: JSON.parse(await readFile(path, "utf-8")) };
	} catch (error) {
		return { config: {}, parseError: error instanceof Error ? error.message : String(error) };
	}
}

export function emptyRules(): RulesFile {
	return { dirs: [], readDirs: [], protectedDirs: [], protectedReadDirs: [], allowedDomains: [] };
}

export async function loadRulesFromPath(path: string): Promise<LoadedRulesFile> {
	if (!existsSync(path)) return { rules: emptyRules(), exists: false };
	try {
		const parsed = JSON.parse(await readFile(path, "utf-8"));
		const strings = (value: unknown) => Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
		return {
			rules: {
				dirs: strings(parsed.dirs),
				readDirs: strings(parsed.readDirs),
				protectedDirs: strings(parsed.protectedDirs),
				protectedReadDirs: strings(parsed.protectedReadDirs),
				allowedDomains: strings(parsed.allowedDomains),
			},
			exists: true,
		};
	} catch (error) {
		return { rules: emptyRules(), exists: true, parseError: error instanceof Error ? error.message : String(error) };
	}
}

export async function saveRulesToPath(path: string, rules: RulesFile): Promise<void> {
	if (!existsSync(dirname(path))) await mkdir(dirname(path), { recursive: true });
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
			if (await readFile(path, "utf-8") === content) return;
		} catch {}
	}
	await writeFile(path, content, "utf-8");
}

export async function normalizeDir(input: string, base: string): Promise<string> {
	const raw = isAbsolute(input) ? expandHome(input) : resolve(base, expandHome(input));
	return realpathIfExists(raw);
}

export async function normalizeAllowedDir(input: string, base: string): Promise<string> {
	const normalized = await normalizeDir(input, base);
	try {
		return (await stat(normalized)).isDirectory() ? normalized : await normalizeDir(dirname(normalized), base);
	} catch {
		return normalized;
	}
}

export async function normalizeRules(rules: RulesFile, normalize: (path: string) => Promise<string>): Promise<void> {
	rules.dirs = unique(await Promise.all(rules.dirs.map(normalize))).sort();
	rules.readDirs = unique(await Promise.all((rules.readDirs ?? []).map(normalize))).sort();
	rules.protectedDirs = unique(await Promise.all((rules.protectedDirs ?? []).map(normalize))).sort();
	rules.protectedReadDirs = unique(await Promise.all((rules.protectedReadDirs ?? []).map(normalize))).sort();
	rules.allowedDomains = unique((rules.allowedDomains ?? []).map(normalizeDomainPattern).filter(Boolean) as string[]).sort();
}

export function defaultSessionReadDirs(agentDir: string): string[] {
	return [agentDir, ...IMPLICIT_BASH_READ_PATHS];
}

export function buildSessionStateData(session: SessionSets, defaultReadDirs: string[]): SessionStateData {
	return {
		version: 1,
		dirs: [...session.dirs].sort(),
		readDirs: [...session.readDirs].filter((dir) => !defaultReadDirs.includes(dir)).sort(),
		protectedDirs: [...session.protectedDirs].sort(),
		protectedReadDirs: [...session.protectedReadDirs].sort(),
		highRiskPrefixes: [...session.highRiskPrefixes].sort(),
		allowedDomains: [...session.allowedDomains].sort(),
	};
}

export function resetSessionSets(session: SessionSets, defaultReadDirs: string[]): void {
	session.dirs.clear();
	session.readDirs.clear();
	session.protectedDirs.clear();
	session.protectedReadDirs.clear();
	session.highRiskPrefixes.clear();
	session.allowedDomains.clear();
	for (const dir of defaultReadDirs) session.readDirs.add(dir);
}

export async function restoreSessionState(
	branch: Iterable<any>,
	session: SessionSets,
	defaultReadDirs: string[],
	normalize: (path: string) => Promise<string>,
	normalizePrefix: (value: string) => string,
): Promise<string> {
	resetSessionSets(session, defaultReadDirs);
	let latest: Partial<SessionStateData> | undefined;
	for (const entry of branch) {
		if (entry.type === "custom" && entry.customType === "sandbox-state") latest = entry.data as Partial<SessionStateData> | undefined;
	}
	if (latest?.version === 1) {
		const strings = (value: unknown) => Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
		for (const dir of await Promise.all(strings(latest.dirs).map(normalize))) session.dirs.add(dir);
		for (const dir of await Promise.all(strings(latest.readDirs).map(normalize))) session.readDirs.add(dir);
		for (const dir of await Promise.all(strings(latest.protectedDirs).map(normalize))) session.protectedDirs.add(dir);
		for (const dir of await Promise.all(strings(latest.protectedReadDirs).map(normalize))) session.protectedReadDirs.add(dir);
		for (const prefix of strings(latest.highRiskPrefixes).map(normalizePrefix).filter(Boolean)) session.highRiskPrefixes.add(prefix);
		for (const pattern of strings(latest.allowedDomains).map(normalizeDomainPattern).filter(Boolean) as string[]) session.allowedDomains.add(pattern);
	}
	return JSON.stringify(buildSessionStateData(session, defaultReadDirs));
}

export async function addProtectedPath(targets: Map<string, ProtectedPathInfo>, id: string, label: string, path: string): Promise<void> {
	targets.set(path, { id, label });
	try { targets.set(await realpath(path), { id, label }); } catch {}
}

export async function rebuildProtectedPaths(candidates: Array<{ id: string; label: string; path: string }>): Promise<Map<string, ProtectedPathInfo>> {
	const targets = new Map<string, ProtectedPathInfo>();
	for (const candidate of candidates) await addProtectedPath(targets, candidate.id, candidate.label, candidate.path);
	return targets;
}

export async function findSensitiveFilesUnderRoot(pi: ExtensionAPI, root: string): Promise<string[]> {
	const pruneArgs = SENSITIVE_SCAN_PRUNE_DIRS.flatMap((name) => ["-name", name, "-o"]).slice(0, -1);
	const args = [
		root,
		"(", "-type", "d", "(", ...pruneArgs, ")", "-prune", ")",
		"-o",
		"(", "-type", "f", "(", "-name", ".env", "-o", "-name", ".env.*", "-o", "-name", "*.pem", "-o", "-name", "*.key", ")", "-print", ")",
	];
	try {
		const result = await pi.exec("find", args, { timeout: 5000 });
		if (result.code !== 0 || !result.stdout.trim()) return [];
		return unique(result.stdout.split("\n").map((line) => line.trim()).filter(Boolean).map((line) => isAbsolute(line) ? line : resolve(root, line)));
	} catch {
		return [];
	}
}

export async function refreshSensitiveFilePaths(pi: ExtensionAPI, activeDirs: string[]): Promise<string[]> {
	return unique((await Promise.all(activeDirs.map((dir) => findSensitiveFilesUnderRoot(pi, dir)))).flat()).sort();
}

export function protectedInfoForPath(protectedPaths: Map<string, ProtectedPathInfo>, path: string): ProtectedPathInfo | undefined {
	return protectedPaths.get(path);
}

export function protectedControlFiles(protectedPaths: Map<string, ProtectedPathInfo>): string[] {
	return unique([...protectedPaths.values()].map((info) => info.id)).sort();
}

export function noteSensitivePath(path: string, sensitiveFilePaths: string[], isSensitivePath: (path: string) => boolean): string[] {
	return isSensitivePath(path) ? unique([...sensitiveFilePaths, path]).sort() : sensitiveFilePaths;
}
