import { dirname, isAbsolute, resolve } from "node:path";
import { existsSync, statSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import {
	createBashTool,
	createLocalBashOperations,
	getAgentDir,
	type BashOperations,
	type ExtensionAPI,
} from "@mariozechner/pi-coding-agent";
import {
	accessBoundary,
	domainMatchesPattern,
	extractCommandDomains,
	extractPathLikeTokens,
	firstCommand,
	isInsideDir,
	isSensitivePath,
	matchesCommandPrefix,
	normalizeDomainPattern,
	normalizePrefix,
	realpathIfExists,
	resolvePath,
	splitCompound,
	unique,
} from "./policy";
import { confirmHighRiskBash, promptBoundaryAccess, promptDomainAccess } from "./prompts";
import { showTransient, withPanelUI, titleRule, bottomRule, pad, hintsLine, LPAD } from "./transient-menu";
import { matchesKey, Key, visibleWidth, truncateToWidth, CombinedAutocompleteProvider, Editor, Container, Text, type Focusable, type Component } from "@mariozechner/pi-tui";
import { getSelectListTheme } from "@mariozechner/pi-coding-agent";
import {
	buildSessionStateData,
	createDefaultSandboxConfig,
	deepMergeSandboxConfig,
	defaultSessionReadDirs,
	emptyRules,
	loadRulesFromPath,
	loadSandboxConfigPart,
	normalizeAllowedDir as normalizeAllowedDirInput,
	normalizeDir as normalizeDirInput,
	normalizeRules,
	noteSensitivePath,
	protectedControlFiles,
	protectedInfoForPath,
	refreshSensitiveFilePaths,
	rebuildProtectedPaths,
	resetSessionSets,
	restoreSessionState,
	saveRulesToPath,
	type AccessLevel,
	type AllowScope,
	type ProtectedPathInfo,
	type RulesFile,
	type SandboxConfig,
	type Scope,
	type SessionSets,
} from "./state";

const HOME = homedir();
const AGENT_DIR = getAgentDir();
const AUTH_FILE = resolve(AGENT_DIR, "auth.json");
const SANDBOX_RUNTIME_CWD = resolve(tmpdir(), "pi-sandbox-runtime");
const SANDBOX_STATE_CUSTOM_TYPE = "sandbox-state";
const SANDBOX_AGENT_CONSTRAINTS_EVENT = "sandbox:agent-constraints";

interface AgentConstraintsEventData {
	agentName?: string;
	constraints?: { bash?: { allowPrefixes?: string[] } };
}

const SENSITIVE_EXACT_FILES = new Set([
	resolve(HOME, ".netrc"),
	resolve(HOME, ".npmrc"),
	resolve(HOME, ".pypirc"),
	resolve(HOME, ".docker", "config.json"),
	resolve(HOME, ".kube", "config"),
	AUTH_FILE,
]);

export default function (pi: ExtensionAPI) {
	const localBash = createBashTool(process.cwd());
	const localBashOps = createLocalBashOperations();
	const pendingOneShotAllowedDomains = new Map<string, Set<string>>();
	const session: SessionSets = {
		dirs: new Set(),
		readDirs: new Set(),
		protectedDirs: new Set(),
		protectedReadDirs: new Set(),
		highRiskPrefixes: new Set(),
		allowedDomains: new Set(),
	};

	let projectRoot = process.cwd();
	let cwd = process.cwd();
	let projectRules = emptyRules();
	let globalRules = emptyRules();
	let projectRulesPath = "";
	let globalRulesPath = "";
	let projectConfigPath = "";
	let globalConfigPath = "";
	let protectedPaths = new Map<string, ProtectedPathInfo>();
	let sensitiveFilePaths: string[] = [];
	let osSandboxConfig: SandboxConfig | undefined;
	let osSandboxEnabled = false;
	let osSandboxInitialized = false;
	let osSandboxReason = "not initialized";
	let currentAgentConstraints: { bash?: { allowPrefixes?: string[] } } | undefined;
	let currentAgentName: string | undefined;
	let lastPersistedSessionStateJson = "";

	// Derived views over project/global/session sandbox state.
	const mergeUnique = (...groups: Array<Iterable<string> | undefined>) => unique(groups.flatMap((group) => group ? [...group] : []));
	const normalizeDir = (input: string) => normalizeDirInput(input, projectRoot || cwd || process.cwd());
	const normalizeAllowedDir = (input: string) => normalizeAllowedDirInput(input, projectRoot || cwd || process.cwd());
	const currentFullAccessDirs = () => mergeUnique(globalRules.dirs, projectRules.dirs, session.dirs);
	const currentReadOnlyDirs = () => mergeUnique(globalRules.readDirs, projectRules.readDirs, session.readDirs);
	const currentProtectedDirs = () => mergeUnique(globalRules.protectedDirs, projectRules.protectedDirs, session.protectedDirs);
	const currentProtectedReadOnlyDirs = () => mergeUnique(globalRules.protectedReadDirs, projectRules.protectedReadDirs, session.protectedReadDirs);
	const activeDirs = () => mergeUnique([projectRoot], currentFullAccessDirs());
	const readableDirs = () => mergeUnique(activeDirs(), currentReadOnlyDirs());
	const currentRuleDomains = () => mergeUnique(globalRules.allowedDomains, projectRules.allowedDomains, session.allowedDomains);
	const configuredAllowedDomains = () => osSandboxConfig?.network?.allowedDomains;
	const configuredWriteRoots = () => osSandboxConfig?.filesystem?.allowWrite ?? [];
	const sessionDefaultReadDirs = defaultSessionReadDirs(AGENT_DIR);
	const isProtectedPath = (path: string) => isSensitivePath(path, SENSITIVE_EXACT_FILES) || protectedInfoForPath(protectedPaths, path) !== undefined;
	const rulesForScope = (scope: Scope) => scope === "project" ? projectRules : globalRules;
	const pathsForScope = (scope: Scope) => scope === "project" ? projectRulesPath : globalRulesPath;

	function isOsSandboxActive(): boolean {
		return osSandboxEnabled && osSandboxInitialized;
	}

	async function withSandboxRuntimeCwd<T>(fn: () => Promise<T> | T): Promise<T> {
		await mkdir(SANDBOX_RUNTIME_CWD, { recursive: true });
		const previousCwd = process.cwd();
		process.chdir(SANDBOX_RUNTIME_CWD);
		try {
			return await fn();
		} finally {
			process.chdir(previousCwd);
		}
	}

	function effectiveAllowedDomains(extraPatterns: Iterable<string> = []): string[] | undefined {
		const configured = configuredAllowedDomains();
		if (configured === undefined) return undefined;
		return mergeUnique(configured, currentRuleDomains(), extraPatterns).map((pattern) => normalizeDomainPattern(pattern) ?? pattern).filter(Boolean).sort();
	}

	function effectiveDeniedDomains(): string[] {
		return mergeUnique(osSandboxConfig?.network?.deniedDomains ?? []).map((pattern) => normalizeDomainPattern(pattern) ?? pattern).filter(Boolean).sort();
	}

	function effectiveWriteRoots(execCwd: string): string[] {
		return mergeUnique(configuredWriteRoots(), activeDirs(), [execCwd, "/tmp", "/private/tmp"]);
	}

	function parentIsDir(path: string): boolean {
		if (!isAbsolute(path)) return true;
		try {
			return statSync(dirname(path)).isDirectory();
		} catch {
			return false;
		}
	}

	function effectiveDenyRead(): string[] {
		return mergeUnique(osSandboxConfig?.filesystem?.denyRead ?? []).filter(parentIsDir);
	}

	function effectiveDenyWrite(): string[] {
		return mergeUnique(osSandboxConfig?.filesystem?.denyWrite ?? []).filter(parentIsDir);
	}

	// Compose the live OS-sandbox config from static config plus learned permissions.
	function effectiveRuntimeConfig(execCwd: string, extraDomains: Iterable<string> = []): SandboxRuntimeConfig {
		const base = osSandboxConfig ?? createDefaultSandboxConfig(projectRoot);
		const extended = base as SandboxConfig & {
			ignoreViolations?: Record<string, string[]>;
			enableWeakerNestedSandbox?: boolean;
			ripgrep?: { command: string; args?: string[] };
			mandatoryDenySearchDepth?: number;
			allowPty?: boolean;
			seccomp?: { bpfPath?: string; applyPath?: string };
		};
		return {
			network: {
				...(base.network ?? { allowedDomains: [], deniedDomains: [] }),
				allowLocalBinding: base.network?.allowLocalBinding,
				allowedDomains: effectiveAllowedDomains(extraDomains) ?? [],
				deniedDomains: effectiveDeniedDomains(),
				allowUnixSockets: undefined,
				allowAllUnixSockets: true,
			} as SandboxRuntimeConfig["network"],
			filesystem: {
				...(base.filesystem ?? { denyRead: [], allowWrite: [], denyWrite: [] }),
				denyRead: effectiveDenyRead(),
				allowWrite: effectiveWriteRoots(execCwd),
				denyWrite: effectiveDenyWrite(),
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

	function syncRuntimeBaseConfig(execCwd = cwd): void {
		if (!isOsSandboxActive()) return;
		void withSandboxRuntimeCwd(() => SandboxManager.updateConfig(effectiveRuntimeConfig(execCwd)));
	}

	function isDomainDenied(domain: string): boolean {
		return effectiveDeniedDomains().some((pattern) => domainMatchesPattern(domain, pattern));
	}

	function isDomainAllowed(domain: string, extraPatterns: Iterable<string> = []): boolean {
		if (isDomainDenied(domain)) return false;
		const allowed = effectiveAllowedDomains(extraPatterns);
		return allowed === undefined || allowed.some((pattern) => domainMatchesPattern(domain, pattern));
	}

	function isInsideAllowedDir(path: string): boolean {
		return activeDirs().some((dir) => isInsideDir(path, dir));
	}

	function isInsideReadableDir(path: string): boolean {
		return readableDirs().some((dir) => isInsideDir(path, dir));
	}

	function isInsideProtectedAllowedDir(path: string): boolean {
		return currentProtectedDirs().some((dir) => isInsideDir(path, dir));
	}

	function isInsideProtectedReadableDir(path: string): boolean {
		return mergeUnique(currentProtectedDirs(), currentProtectedReadOnlyDirs()).some((dir) => isInsideDir(path, dir));
	}

	function persistSessionState(): void {
		const payload = buildSessionStateData(session, sessionDefaultReadDirs);
		const json = JSON.stringify(payload);
		if (json === lastPersistedSessionStateJson) return;
		pi.appendEntry(SANDBOX_STATE_CUSTOM_TYPE, payload);
		lastPersistedSessionStateJson = json;
	}

	function resetSessionState(): void {
		resetSessionSets(session, sessionDefaultReadDirs);
		pendingOneShotAllowedDomains.clear();
	}

	async function reconstructSessionState(ctx: { sessionManager: any; ui: any }): Promise<void> {
		resetSessionState();
		lastPersistedSessionStateJson = await restoreSessionState(
			ctx.sessionManager.getBranch(),
			session,
			sessionDefaultReadDirs,
			normalizeDir,
			normalizePrefix,
		);
		sensitiveFilePaths = await refreshSensitiveFilePaths(pi, activeDirs());
		updateStatus(ctx);
	}

	function updateStatus(ctx: { ui: any }) {
		const parts: string[] = [];
		if (currentFullAccessDirs().length) parts.push(`+${currentFullAccessDirs().length} dirs`);
		if (currentReadOnlyDirs().length) parts.push(`+${currentReadOnlyDirs().length} read-only`);
		const protectedCount = currentProtectedDirs().length + currentProtectedReadOnlyDirs().length;
		if (protectedCount) parts.push(`+${protectedCount} protected`);
		if (currentRuleDomains().length) parts.push(`+${currentRuleDomains().length} domains`);
		if (!isOsSandboxActive()) parts.push(`os sandbox off (${osSandboxReason})`);
		ctx.ui.setStatus("sandbox", parts.length ? ctx.ui.theme.fg("accent", parts.join(" · ")) : "");
	}

	function disableOsSandbox(reason: string): void {
		osSandboxEnabled = false;
		osSandboxInitialized = false;
		osSandboxReason = reason;
	}

	async function saveRulesForScope(scope: Scope, ctx?: { ui: any }): Promise<boolean> {
		const path = pathsForScope(scope);
		try {
			await saveRulesToPath(path, rulesForScope(scope));
			return true;
		} catch (error) {
			ctx?.ui.notify(`Could not save ${path}: ${error instanceof Error ? error.message : error}`, "warning");
			return false;
		}
	}

	// Apply a mutation to persisted rules and roll it back if saving fails.
	async function persistRuleMutation(
		scope: Scope,
		ctx: { ui: any } | undefined,
		mutate: (rules: RulesFile) => boolean,
	): Promise<{ ok: boolean; changed: boolean }> {
		const rules = rulesForScope(scope);
		const before: RulesFile = {
			dirs: [...rules.dirs],
			readDirs: [...(rules.readDirs ?? [])],
			protectedDirs: [...(rules.protectedDirs ?? [])],
			protectedReadDirs: [...(rules.protectedReadDirs ?? [])],
			allowedDomains: [...(rules.allowedDomains ?? [])],
		};
		if (!mutate(rules)) return { ok: true, changed: false };
		if (await saveRulesForScope(scope, ctx)) return { ok: true, changed: true };
		Object.assign(rules, before);
		return { ok: false, changed: false };
	}

	// Full access subsumes read-only; persisted scopes save atomically with rollback.
	async function addDirPermission(kind: "normal" | "protected", dir: string, scope: AllowScope, level: AccessLevel, ctx?: { ui: any }): Promise<boolean> {
		const normalized = await normalizeDir(dir);
		const sessionFull = kind === "normal" ? session.dirs : session.protectedDirs;
		const sessionRead = kind === "normal" ? session.readDirs : session.protectedReadDirs;
		const fullKey = kind === "normal" ? "dirs" : "protectedDirs";
		const readKey = kind === "normal" ? "readDirs" : "protectedReadDirs";
		let changed = false;
		if (scope === "session") {
			if (level === "full") {
				sessionRead.delete(normalized);
				if (!sessionFull.has(normalized)) { sessionFull.add(normalized); changed = true; }
			} else if (!sessionFull.has(normalized) && !sessionRead.has(normalized)) {
				sessionRead.add(normalized);
				changed = true;
			}
			if (changed) persistSessionState();
		} else {
			const result = await persistRuleMutation(scope, ctx, (rules) => {
				const full = [...(rules[fullKey] ?? [])] as string[];
				const read = [...(rules[readKey] ?? [])] as string[];
				if (level === "full") {
					if (full.includes(normalized)) return false;
					rules[readKey] = read.filter((value) => value !== normalized) as never;
					rules[fullKey] = unique([...full, normalized]).sort() as never;
					return true;
				}
				if (full.includes(normalized) || read.includes(normalized)) return false;
				rules[readKey] = unique([...read, normalized]).sort() as never;
				return true;
			});
			if (!result.ok) return false;
			changed = result.changed;
		}
		if (changed && kind === "normal") sensitiveFilePaths = await refreshSensitiveFilePaths(pi, activeDirs());
		if (changed && (kind === "normal" || scope !== "session")) syncRuntimeBaseConfig();
		return true;
	}

	const addAllowedDir = (dir: string, scope: AllowScope, level: AccessLevel, ctx?: { ui: any }) => addDirPermission("normal", dir, scope, level, ctx);
	const addProtectedAllowedDir = (dir: string, scope: AllowScope, level: AccessLevel, ctx?: { ui: any }) => addDirPermission("protected", dir, scope, level, ctx);

	async function addAllowedDomain(domain: string, scope: AllowScope, ctx?: { ui: any }): Promise<boolean> {
		const normalized = normalizeDomainPattern(domain);
		if (!normalized) {
			ctx?.ui.notify(`Invalid domain or pattern: ${domain}`, "warning");
			return false;
		}
		if (scope === "session") {
			if (session.allowedDomains.has(normalized)) return true;
			session.allowedDomains.add(normalized);
			persistSessionState();
			syncRuntimeBaseConfig();
			return true;
		}
		const result = await persistRuleMutation(scope, ctx, (rules) => {
			if ((rules.allowedDomains ?? []).includes(normalized)) return false;
			rules.allowedDomains = unique([...(rules.allowedDomains ?? []), normalized]).sort();
			return true;
		});
		if (!result.ok) return false;
		if (result.changed) syncRuntimeBaseConfig();
		return true;
	}

	async function removeDirPermission(kind: "normal" | "protected", dir: string, scope: AllowScope, level: AccessLevel, ctx?: { ui: any }): Promise<boolean> {
		const normalized = await normalizeDir(dir);
		const sessionFull = kind === "normal" ? session.dirs : session.protectedDirs;
		const sessionRead = kind === "normal" ? session.readDirs : session.protectedReadDirs;
		const fullKey = kind === "normal" ? "dirs" : "protectedDirs";
		const readKey = kind === "normal" ? "readDirs" : "protectedReadDirs";
		let changed = false;
		if (scope === "session") {
			const target = level === "full" ? sessionFull : sessionRead;
			if (!target.has(normalized)) return false;
			target.delete(normalized);
			changed = true;
			persistSessionState();
		} else {
			const result = await persistRuleMutation(scope, ctx, (rules) => {
				const key = level === "full" ? fullKey : readKey;
				const arr = [...(rules[key] ?? [])] as string[];
				const idx = arr.indexOf(normalized);
				if (idx === -1) return false;
				arr.splice(idx, 1);
				rules[key] = arr as never;
				return true;
			});
			if (!result.ok || !result.changed) return false;
			changed = true;
		}
		if (changed && kind === "normal") sensitiveFilePaths = await refreshSensitiveFilePaths(pi, activeDirs());
		if (changed) syncRuntimeBaseConfig();
		return true;
	}

	async function removeAllowedDomain(domain: string, scope: AllowScope, ctx?: { ui: any }): Promise<boolean> {
		const normalized = normalizeDomainPattern(domain);
		if (!normalized) return false;
		if (scope === "session") {
			if (!session.allowedDomains.has(normalized)) return false;
			session.allowedDomains.delete(normalized);
			persistSessionState();
			syncRuntimeBaseConfig();
			return true;
		}
		const result = await persistRuleMutation(scope, ctx, (rules) => {
			const arr = [...(rules.allowedDomains ?? [])];
			const idx = arr.indexOf(normalized);
			if (idx === -1) return false;
			arr.splice(idx, 1);
			rules.allowedDomains = arr;
			return true;
		});
		if (!result.ok || !result.changed) return false;
		syncRuntimeBaseConfig();
		return true;
	}

	// Protect sandbox config/rules and the extension's own source files from silent modification.
	async function rebuildControlPaths(): Promise<void> {
		const sandboxFiles = ["index.ts", "policy.ts", "state.ts", "prompts.ts", "transient-menu.ts"];
		const sandboxRoots = [
			resolve(projectRoot, ".pi", "extensions", "sandbox"),
			resolve(cwd, ".pi", "extensions", "sandbox"),
			resolve(AGENT_DIR, "extensions", "sandbox"),
		];
		protectedPaths = await rebuildProtectedPaths([
			{ id: projectRulesPath, label: "sandbox rules", path: projectRulesPath },
			{ id: globalRulesPath, label: "sandbox rules", path: globalRulesPath },
			{ id: projectConfigPath, label: "sandbox config", path: projectConfigPath },
			{ id: globalConfigPath, label: "sandbox config", path: globalConfigPath },
			...sandboxRoots.flatMap((root) => sandboxFiles.map((file) => {
				const path = resolve(root, file);
				return { id: path, label: "sandbox extension", path };
			})),
			{ id: resolve(AGENT_DIR, "extensions", "agents.ts"), label: "agent extension", path: resolve(AGENT_DIR, "extensions", "agents.ts") },
			{ id: resolve(AGENT_DIR, "extensions", "package.json"), label: "extension package manifest", path: resolve(AGENT_DIR, "extensions", "package.json") },
			{ id: resolve(AGENT_DIR, "extensions", "package-lock.json"), label: "extension package lockfile", path: resolve(AGENT_DIR, "extensions", "package-lock.json") },
		]);
	}

	function createSandboxedBashOps(toolCallId?: string): BashOperations {
		return {
			async exec(command, execCwd, options) {
				if (!existsSync(execCwd)) throw new Error(`Working directory does not exist: ${execCwd}`);
				const oneShotDomains = toolCallId ? pendingOneShotAllowedDomains.get(toolCallId) ?? new Set<string>() : new Set<string>();
				if (toolCallId) pendingOneShotAllowedDomains.delete(toolCallId);
				const baseRuntimeConfig = effectiveRuntimeConfig(execCwd);
				const runtimeConfig = effectiveRuntimeConfig(execCwd, oneShotDomains);
				return withSandboxRuntimeCwd(async () => {
					SandboxManager.updateConfig(runtimeConfig);
					try {
						return await localBashOps.exec(await SandboxManager.wrapWithSandbox(command, undefined, runtimeConfig), execCwd, options);
					} finally {
						SandboxManager.updateConfig(baseRuntimeConfig);
					}
				});
			},
		};
	}

	async function findRepoRoot(dir: string): Promise<string | undefined> {
		try {
			const result = await pi.exec("git", ["-C", dir, "rev-parse", "--show-toplevel"], { timeout: 1500 });
			return result.code === 0 && result.stdout.trim() ? normalizeDir(result.stdout.trim()) : undefined;
		} catch {
			return undefined;
		}
	}

	async function ensureProtectedPathAccess(ctx: { ui: any; hasUI?: boolean }, kind: string, path: string, extraContext: string[] = []) {
		if (!isProtectedPath(path)) return;
		const operation = kind.toUpperCase();
		if ((operation === "READ" || operation === "BASH") && isInsideProtectedReadableDir(path)) return;
		if (operation !== "READ" && operation !== "BASH" && isInsideProtectedAllowedDir(path)) return;
		return promptBoundaryAccess(ctx, operation, path, await accessBoundary(path, { normalizeDir, findRepoRoot }), {
			protectedMode: true,
			extraContext,
			addAllowedDir,
			addProtectedAllowedDir,
			normalizeAllowedDir,
			updateStatus,
		});
	}

	async function ensureFileAccess(toolName: "read" | "write" | "edit", resolved: string, ctx: { ui: any; hasUI?: boolean }) {
		if (isInsideAllowedDir(resolved) || (toolName === "read" && isInsideReadableDir(resolved))) return;
		const boundary = await accessBoundary(resolved, { normalizeDir, findRepoRoot });
		if (isInsideAllowedDir(boundary.dir) || (toolName === "read" && isInsideReadableDir(boundary.dir))) return;
		return promptBoundaryAccess(ctx, toolName.toUpperCase(), resolved, boundary, { addAllowedDir, addProtectedAllowedDir, normalizeAllowedDir, updateStatus });
	}

	async function resolveCommandPathCandidates(command: string, commandCwd: string): Promise<string[]> {
		return unique(await Promise.all(extractPathLikeTokens(command).map((token) => realpathIfExists(resolvePath(token, commandCwd)))));
	}

	// UX-layer path approval for bash; the OS sandbox is still the hard enforcement boundary.
	async function ensureBashPathsAllowed(command: string, ctx: { ui: any; hasUI?: boolean; cwd: string }) {
		const promptedBoundaries = new Set<string>();
		for (const path of await resolveCommandPathCandidates(command, ctx.cwd)) {
			const extraContext = [`in  ${command}`];
			const protectedAccess = await ensureProtectedPathAccess(ctx, "bash", path, extraContext);
			if (protectedAccess?.block) return protectedAccess;
			if (isProtectedPath(path) || isInsideReadableDir(path)) continue;
			const boundary = await accessBoundary(path, { normalizeDir, findRepoRoot });
			if (isInsideReadableDir(boundary.dir) || promptedBoundaries.has(boundary.dir)) continue;
			const result = await promptBoundaryAccess(ctx, "BASH", path, boundary, { extraContext, addAllowedDir, addProtectedAllowedDir, normalizeAllowedDir, updateStatus });
			if (result?.block) return result;
			promptedBoundaries.add(boundary.dir);
		}
	}

	async function ensureBashDomainsAllowed(toolCallId: string, command: string, ctx: { ui: any; hasUI?: boolean }) {
		const domains = extractCommandDomains(command);
		if (domains.length === 0) return;
		const oneShotPatterns = new Set<string>();
		for (const domain of domains) {
			if (isDomainAllowed(domain, oneShotPatterns)) continue;
			const result = await promptDomainAccess(ctx, domain, command, {
				isDomainDenied,
				deniedReason: `${projectConfigPath} or ${globalConfigPath}`,
				addAllowedDomain,
				updateStatus,
			});
			if (result?.block) return result;
			for (const pattern of result?.oneShotPatterns ?? []) oneShotPatterns.add(pattern);
		}
		if (oneShotPatterns.size) pendingOneShotAllowedDomains.set(toolCallId, oneShotPatterns);
	}

	function isHighRiskApprovedForSession(segment: string): boolean {
		return [...session.highRiskPrefixes].some((prefix) => matchesCommandPrefix(segment, prefix));
	}

	async function initializeProjectState(ctx: { cwd: string; ui: any; sessionManager: any }) {
		cwd = ctx.cwd;
		globalRulesPath = resolve(AGENT_DIR, "sandbox-rules.json");
		globalConfigPath = resolve(AGENT_DIR, "sandbox.json");
		projectRoot = ctx.cwd;
		try {
			const result = await pi.exec("git", ["-C", ctx.cwd, "rev-parse", "--show-toplevel"], { timeout: 3000 });
			if (result.code === 0 && result.stdout.trim()) projectRoot = result.stdout.trim();
		} catch {}
		projectRoot = await realpathIfExists(projectRoot);
		projectRulesPath = resolve(projectRoot, ".pi", "sandbox-rules.json");
		projectConfigPath = resolve(projectRoot, ".pi", "sandbox.json");
		const [globalRulesLoaded, projectRulesLoaded, globalConfigLoaded, projectConfigLoaded] = await Promise.all([
			loadRulesFromPath(globalRulesPath),
			loadRulesFromPath(projectRulesPath),
			loadSandboxConfigPart(globalConfigPath),
			loadSandboxConfigPart(projectConfigPath),
		]);
		globalRules = globalRulesLoaded.rules;
		projectRules = projectRulesLoaded.rules;
		await Promise.all([normalizeRules(globalRules, normalizeDir), normalizeRules(projectRules, normalizeDir)]);
		if (globalRulesLoaded.parseError) ctx.ui.notify(`Could not parse ${globalRulesPath}: ${globalRulesLoaded.parseError}`, "warning");
		else if (globalRulesLoaded.exists) await saveRulesForScope("global", ctx);
		if (projectRulesLoaded.parseError) ctx.ui.notify(`Could not parse ${projectRulesPath}: ${projectRulesLoaded.parseError}`, "warning");
		else if (projectRulesLoaded.exists) await saveRulesForScope("project", ctx);
		if (globalConfigLoaded.parseError) ctx.ui.notify(`Could not parse ${globalConfigPath}: ${globalConfigLoaded.parseError}`, "warning");
		if (projectConfigLoaded.parseError) ctx.ui.notify(`Could not parse ${projectConfigPath}: ${projectConfigLoaded.parseError}`, "warning");
		osSandboxConfig = deepMergeSandboxConfig(deepMergeSandboxConfig(createDefaultSandboxConfig(projectRoot), globalConfigLoaded.config), projectConfigLoaded.config);
		await rebuildControlPaths();
		await reconstructSessionState(ctx);
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
			if (!isOsSandboxActive()) return createBashTool(toolCwd).execute(id, params, signal, onUpdate, ctx);
			return createBashTool(toolCwd, { operations: createSandboxedBashOps(id) }).execute(id, params, signal, onUpdate, ctx);
		},
	});

	pi.on("user_bash", () => isOsSandboxActive() ? { operations: createSandboxedBashOps() } : undefined);

	pi.on("session_start", async (_event, ctx) => {
		await initializeProjectState(ctx);
		const noOsSandbox = pi.getFlag("no-os-sandbox") as boolean;
		if (noOsSandbox) disableOsSandbox("--no-os-sandbox");
		else if (!osSandboxConfig?.enabled) disableOsSandbox("config disabled");
		else if (!["darwin", "linux"].includes(process.platform)) {
			disableOsSandbox(process.platform);
			ctx.ui.notify(`OS sandbox not supported on ${process.platform}`, "warning");
		} else {
			try {
				await withSandboxRuntimeCwd(async () => {
					try { await SandboxManager.reset(); } catch {}
					await SandboxManager.initialize(effectiveRuntimeConfig(cwd));
				});
				osSandboxEnabled = true;
				osSandboxInitialized = true;
				osSandboxReason = "active";
				ctx.ui.notify("OS sandbox initialized for bash", "info");
			} catch (error) {
				disableOsSandbox("init failed");
				ctx.ui.notify(`OS sandbox initialization failed: ${error instanceof Error ? error.message : error}`, "warning");
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
		} catch {}
		finally { osSandboxInitialized = false; }
	});

	pi.on("tool_call", async (event, ctx) => {
		if (["read", "write", "edit"].includes(event.toolName)) {
			const rawPath = event.input.path as string;
			if (!rawPath) return;
			const resolved = await realpathIfExists(resolvePath(rawPath, ctx.cwd));
			const protectedAccess = await ensureProtectedPathAccess(ctx, event.toolName, resolved);
			if (protectedAccess?.block) return protectedAccess;
			sensitiveFilePaths = noteSensitivePath(resolved, sensitiveFilePaths, (path) => isSensitivePath(path, SENSITIVE_EXACT_FILES));
			if (isProtectedPath(resolved)) return;
			return ensureFileAccess(event.toolName as "read" | "write" | "edit", resolved, ctx);
		}
		if (event.toolName !== "bash") return;
		const command = event.input.command as string;
		if (!command) return;
		const bc = currentAgentConstraints?.bash;
		if (bc?.allowPrefixes) {
			for (const segment of splitCompound(command)) {
				if (bc.allowPrefixes.some((prefix) => matchesCommandPrefix(segment, prefix))) continue;
				const agentName = currentAgentName?.toUpperCase() ?? "CURRENT AGENT";
				return { block: true, reason: `${agentName} mode: "${firstCommand(segment)}" not allowed (permitted: ${bc.allowPrefixes.join(", ")})` };
			}
		}
		const pathAccess = await ensureBashPathsAllowed(command, ctx);
		if (pathAccess?.block) return pathAccess;
		const domainAccess = await ensureBashDomainsAllowed(event.toolCallId, command, ctx);
		if (domainAccess?.block) return domainAccess;
		return confirmHighRiskBash(command, ctx, {
			isApprovedForSession: isHighRiskApprovedForSession,
			approvePrefix: (prefix) => session.highRiskPrefixes.add(prefix),
			persistSessionState,
		});
	});

	// ── Sandbox management UI ────────────────────────────────────────────────

	interface MgmtEntry {
		value: string;
		displayValue: string;
		scope: AllowScope;
		isProtected: boolean;
		remove: () => Promise<boolean>;
	}

	interface MgmtCategory {
		label: string;
		entries: MgmtEntry[];
	}

	function abbreviateHome(path: string): string {
		const home = process.env.HOME || process.env.USERPROFILE;
		return home && path.startsWith(home) ? "~" + path.slice(home.length) : path;
	}

	function collectMgmtEntries(): MgmtCategory[] {
		const categories: MgmtCategory[] = [];
		const defaults = new Set(defaultSessionReadDirs(AGENT_DIR));

		const fullEntries: MgmtEntry[] = [];
		const addFull = (dirs: Iterable<string>, scope: AllowScope, prot: boolean) => {
			for (const dir of dirs) fullEntries.push({
				value: dir, displayValue: abbreviateHome(dir), scope, isProtected: prot,
				remove: () => removeDirPermission(prot ? "protected" : "normal", dir, scope, "full"),
			});
		};
		addFull(session.dirs, "session", false);
		addFull(projectRules.dirs, "project", false);
		addFull(globalRules.dirs, "global", false);
		addFull(session.protectedDirs, "session", true);
		addFull(projectRules.protectedDirs ?? [], "project", true);
		addFull(globalRules.protectedDirs ?? [], "global", true);
		if (fullEntries.length) categories.push({ label: "Full access", entries: fullEntries });

		const readEntries: MgmtEntry[] = [];
		const addRead = (dirs: Iterable<string>, scope: AllowScope, prot: boolean) => {
			for (const dir of dirs) {
				if (scope === "session" && defaults.has(dir)) continue;
				readEntries.push({
					value: dir, displayValue: abbreviateHome(dir), scope, isProtected: prot,
					remove: () => removeDirPermission(prot ? "protected" : "normal", dir, scope, "read"),
				});
			}
		};
		addRead(session.readDirs, "session", false);
		addRead(projectRules.readDirs ?? [], "project", false);
		addRead(globalRules.readDirs ?? [], "global", false);
		addRead(session.protectedReadDirs, "session", true);
		addRead(projectRules.protectedReadDirs ?? [], "project", true);
		addRead(globalRules.protectedReadDirs ?? [], "global", true);
		if (readEntries.length) categories.push({ label: "Read-only", entries: readEntries });

		const domainEntries: MgmtEntry[] = [];
		const addDom = (doms: Iterable<string>, scope: AllowScope) => {
			for (const dom of doms) domainEntries.push({
				value: dom, displayValue: dom, scope, isProtected: false,
				remove: () => removeAllowedDomain(dom, scope),
			});
		};
		addDom(session.allowedDomains, "session");
		addDom(projectRules.allowedDomains ?? [], "project");
		addDom(globalRules.allowedDomains ?? [], "global");
		if (domainEntries.length) categories.push({ label: "Domains", entries: domainEntries });

		return categories;
	}

	function flatEntries(categories: MgmtCategory[]): MgmtEntry[] {
		return categories.flatMap((c) => c.entries);
	}

	function renderMgmtEntry(entry: MgmtEntry, isSelected: boolean, width: number, theme: any): string {
		const marker = isSelected ? theme.fg("accent", "▸") + " " : "  ";
		const protTag = entry.isProtected ? theme.fg("dim", " (protected)") : "";
		const scopeStr = theme.fg("dim", entry.scope);
		const scopeVW = visibleWidth(scopeStr);

		const pathStr = isSelected ? entry.displayValue : theme.fg("muted", entry.displayValue);

		const left = " ".repeat(LPAD) + marker + pathStr + protTag;
		const leftVW = visibleWidth(left);
		const gap = Math.max(2, width - leftVW - scopeVW);
		return truncateToWidth(left + " ".repeat(gap) + scopeStr, width);
	}

	async function showSandboxManager(ctx: any): Promise<string | null> {
		return withPanelUI<string | null>(ctx, (tui: any, theme: any, _kb: any, done: (v: string | null) => void) => {
			let categories = collectMgmtEntries();
			let flat = flatEntries(categories);
			let selected = 0;
			let busy = false;
			let cachedWidth: number | undefined;
			let cachedLines: string[] | undefined;

			return {
				handleInput(data: string) {
					if (busy) return;
					if (matchesKey(data, Key.escape)) { done(null); return; }
					if ((matchesKey(data, Key.up) || data === "k" || matchesKey(data, Key.ctrl("p"))) && selected > 0) {
						selected--;
					} else if ((matchesKey(data, Key.down) || data === "j" || matchesKey(data, Key.ctrl("n"))) && selected < flat.length - 1) {
						selected++;
					} else if ((data === "d" || matchesKey(data, Key.backspace)) && flat.length > 0) {
						const entry = flat[selected];
						busy = true;
						entry.remove().then((ok) => {
							if (ok) {
								categories = collectMgmtEntries();
								flat = flatEntries(categories);
								selected = Math.min(selected, Math.max(0, flat.length - 1));
								updateStatus(ctx);
							}
							busy = false;
							cachedWidth = undefined;
							cachedLines = undefined;
							tui.requestRender();
						});
						return;
					} else if (data === "a") { done("add"); return; }
					else if (data === "c" && flat.length > 0) { done("clear"); return; }
					else { return; }
					cachedWidth = undefined;
					cachedLines = undefined;
					tui.requestRender();
				},

				render(width: number): string[] {
					if (cachedLines && cachedWidth === width) return cachedLines;

					const border = (s: string) => theme.fg("border", s);
					const title = (s: string) => theme.fg("accent", theme.bold(s));
					const accent = (s: string) => theme.fg("accent", s);
					const dim = (s: string) => theme.fg("dim", s);

					const lines: string[] = [];
					lines.push(titleRule(width, "Sandbox", border, title));

					if (flat.length === 0) {
						lines.push(pad(dim("No permissions configured."), width));
					} else {
						let idx = 0;
						for (let ci = 0; ci < categories.length; ci++) {
							const cat = categories[ci];
							lines.push(pad(theme.fg("text", cat.label), width));
							for (const entry of cat.entries) {
								lines.push(renderMgmtEntry(entry, idx === selected, width, theme));
								idx++;
							}
							if (ci < categories.length - 1) lines.push("");
						}
					}

					lines.push("");
					const osStatus = isOsSandboxActive() ? "on" : `off (${osSandboxReason})`;
					lines.push(pad(dim(`OS sandbox: ${osStatus}`), width));

					lines.push("");
					const left = flat.length > 0
						? `${accent("a")}  ${dim("add")}   ${accent("d")}  ${dim("remove")}   ${accent("c")}  ${dim("clear all")}`
						: `${accent("a")}  ${dim("add")}`;
					const right = `${accent("ESC")}  ${dim("close")}`;
					lines.push(hintsLine(left, right, width));
					lines.push(bottomRule(width, border));

					cachedWidth = width;
					cachedLines = lines;
					return lines;
				},

				invalidate() {
					cachedWidth = undefined;
					cachedLines = undefined;
				},
			};
		});
	}

	async function pathInput(ctx: any, title: string, defaultValue: string): Promise<string | undefined> {
		return withPanelUI<string | undefined>(ctx, (tui: any, theme: any, _kb: any, done: (v: string | undefined) => void) => {
			const editorTheme = { borderColor: (s: string) => theme.fg("borderMuted", s), selectList: getSelectListTheme() };
			const editor = new Editor(tui, editorTheme, { paddingX: 1 });
			// Path-only autocomplete provider — always treats input as a filesystem path,
			// bypassing the slash-command detection in CombinedAutocompleteProvider.
			const inner = new CombinedAutocompleteProvider([], cwd);
			const pathProvider = {
				getSuggestions(lines: string[], cursorLine: number, cursorCol: number) {
					const currentLine = lines[cursorLine] || "";
					const textBeforeCursor = currentLine.slice(0, cursorCol);
					const suggestions = (inner as any).getFileSuggestions(textBeforeCursor);
					if (!suggestions || suggestions.length === 0) return null;
					return { items: suggestions, prefix: textBeforeCursor };
				},
				applyCompletion(lines: string[], cursorLine: number, cursorCol: number, item: any, prefix: string) {
					return inner.applyCompletion(lines, cursorLine, cursorCol, item, prefix);
				},
				getForceFileSuggestions(lines: string[], cursorLine: number, cursorCol: number) {
					return pathProvider.getSuggestions(lines, cursorLine, cursorCol);
				},
				shouldTriggerFileCompletion() { return true; },
			};
			editor.setAutocompleteProvider(pathProvider as any);
			if (defaultValue) editor.setText(defaultValue);
			editor.onSubmit = (text: string) => done(text || undefined);

			const container = new Container();
			const titleText = new Text(theme.fg("accent", ` ${title}`), 0, 0);
			container.addChild(titleText);
			container.addChild(editor);
			const hints = new Text(theme.fg("dim", " enter submit  tab complete  esc cancel"), 0, 0);
			container.addChild(hints);

			const comp: Component & Focusable = {
				focused: false,
				render(w: number) { return container.render(w); },
				invalidate() { container.invalidate(); },
				handleInput(data: string) {
					if (matchesKey(data, Key.escape)) { done(undefined); return; }
					editor.handleInput(data);
				},
			};
			Object.defineProperty(comp, "focused", {
				get() { return editor.focused; },
				set(v: boolean) { editor.focused = v; },
			});
			return comp;
		});
	}

	async function sandboxAddFlow(ctx: any): Promise<void> {
		const type = await showTransient<string | null>(ctx, {
			title: "Add",
			context: [],
			sections: [{
				type: "row",
				bindings: [
					{ key: "f", label: "full access dir", value: "dir-full" },
					{ key: "r", label: "read-only dir", value: "dir-read" },
					{ key: "d", label: "domain", value: "domain" },
				],
			}],
			cancelValue: null,
			cancelLabel: "back",
			grace: 0,
		});
		if (!type) return;

		let entered: string | undefined;
		if (type === "domain") {
			entered = await ctx.ui.input("Domain or pattern:", "") ?? undefined;
		} else {
			entered = await pathInput(ctx, "Path:", cwd);
		}
		if (!entered?.trim()) return;

		const scope = await showTransient<AllowScope | null>(ctx, {
			title: "Scope",
			context: [entered.trim()],
			sections: [{
				type: "row",
				bindings: [
					{ key: "s", label: "session", value: "session" as AllowScope },
					{ key: "p", label: "project", value: "project" as AllowScope },
					{ key: "g", label: "global", value: "global" as AllowScope },
				],
			}],
			cancelValue: null,
			cancelLabel: "back",
			grace: 0,
		});
		if (!scope) return;

		if (type === "domain") {
			await addAllowedDomain(entered.trim(), scope, ctx);
		} else {
			const level: AccessLevel = type === "dir-full" ? "full" : "read";
			const dir = await normalizeAllowedDir(entered.trim());
			await addAllowedDir(dir, scope, level, ctx);
		}
		updateStatus(ctx);
	}

	async function sandboxClearFlow(ctx: any): Promise<void> {
		const scope = await showTransient<string | null>(ctx, {
			title: "Clear",
			context: ["Remove all sandbox permissions"],
			sections: [{
				type: "row",
				bindings: [
					{ key: "s", label: "session only", value: "session" },
					{ key: "p", label: "project rules", value: "project" },
					{ key: "g", label: "global rules", value: "global" },
					{ key: "a", label: "all", value: "all" },
				],
			}],
			cancelValue: null,
			cancelLabel: "back",
			grace: 0,
		});
		if (!scope) return;

		if (scope === "project" || scope === "all") { projectRules = emptyRules(); await saveRulesForScope("project", ctx); }
		if (scope === "global" || scope === "all") { globalRules = emptyRules(); await saveRulesForScope("global", ctx); }
		if (scope === "session" || scope === "all") {
			resetSessionState();
			persistSessionState();
		}
		sensitiveFilePaths = await refreshSensitiveFilePaths(pi, activeDirs());
		syncRuntimeBaseConfig(ctx.cwd);
		updateStatus(ctx);
	}

	pi.registerCommand("sandbox", {
		description: "Manage sandbox permissions",
		handler: async (args, ctx) => {
			// Debug dump for troubleshooting
			if (args?.trim() === "debug") {
				const formatSection = (label: string, values: string[]) => values.length ? [label + ":", ...values.map((value) => `  - ${value}`)] : [`${label}: (none)`];
				const configuredDomains = configuredAllowedDomains();
				const effectiveDomains = effectiveAllowedDomains();
				const configuredDomainsLabel = configuredDomains === undefined ? "(unrestricted)" : configuredDomains.length ? configuredDomains.join(", ") : "(blocked unless explicitly allowed)";
				const effectiveDomainsLabel = effectiveDomains === undefined ? "(unrestricted)" : effectiveDomains.length ? effectiveDomains.join(", ") : "(blocked)";
				const lines = [
					`Project root: ${projectRoot}`,
					`OS sandbox: ${isOsSandboxActive() ? "enabled" : `off (${osSandboxReason})`}`,
					`Global rules:  ${globalRulesPath}`,
					`Project rules: ${projectRulesPath}`,
					`Global config: ${globalConfigPath}`,
					`Project config: ${projectConfigPath}`,
					"",
					...formatSection("Full access dirs", activeDirs()),
					...formatSection("Read-only dirs", currentReadOnlyDirs()),
					...formatSection("Protected full access", currentProtectedDirs()),
					...formatSection("Protected read-only", currentProtectedReadOnlyDirs()),
					"",
					...formatSection("Session allowed domains", [...session.allowedDomains].sort()),
					...formatSection("Project allowed domains", projectRules.allowedDomains ?? []),
					...formatSection("Global allowed domains", globalRules.allowedDomains ?? []),
					"",
					"Filesystem:",
					`  Effective deny read: ${effectiveDenyRead().join(", ") || "(none)"}`,
					`  Sensitive files: ${sensitiveFilePaths.length}`,
					`  Effective allow write: ${effectiveWriteRoots(cwd).join(", ")}`,
					`  Effective deny write: ${effectiveDenyWrite().join(", ") || "(none)"}`,
					"",
					"Network:",
					`  Configured: ${configuredDomainsLabel}`,
					`  Effective: ${effectiveDomainsLabel}`,
					`  Denied: ${effectiveDeniedDomains().join(", ") || "(none)"}`,
				];
				if (session.highRiskPrefixes.size) {
					lines.push("", `High-risk prefixes (${session.highRiskPrefixes.size}):`);
					for (const prefix of [...session.highRiskPrefixes].sort()) lines.push(`  ${prefix}`);
				}
				ctx.ui.notify(lines.join("\n"), "info");
				return;
			}

			// Interactive management loop
			let action: string | null = "show";
			while (action) {
				if (action === "show") {
					action = await showSandboxManager(ctx);
				} else if (action === "add") {
					await sandboxAddFlow(ctx);
					action = "show";
				} else if (action === "clear") {
					await sandboxClearFlow(ctx);
					action = "show";
				} else {
					action = null;
				}
			}
		},
	});
}
