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
		const parts = [projectRoot];
		if (currentFullAccessDirs().length) parts.push(`+${currentFullAccessDirs().length} dirs`);
		if (currentReadOnlyDirs().length) parts.push(`+${currentReadOnlyDirs().length} read-only`);
		const protectedCount = currentProtectedDirs().length + currentProtectedReadOnlyDirs().length;
		if (protectedCount) parts.push(`+${protectedCount} protected`);
		if (currentRuleDomains().length) parts.push(`+${currentRuleDomains().length} domains`);
		parts.push("sockets unrestricted", isOsSandboxActive() ? "os sandbox" : `os off (${osSandboxReason})`);
		ctx.ui.setStatus("sandbox", ctx.ui.theme.fg("accent", parts.join(" · ")));
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

	pi.registerCommand("sandbox", {
		description: "Show sandbox status. Usage: /sandbox [clear]",
		handler: async (args, ctx) => {
			if (args?.trim() === "clear") {
				const scope = await ctx.ui.select("Clear which approved sandbox access?", ["Project rules only", "Global rules only", "Both", "Cancel"]);
				if (scope === "Project rules only" || scope === "Both") { projectRules = emptyRules(); await saveRulesForScope("project", ctx); }
				if (scope === "Global rules only" || scope === "Both") { globalRules = emptyRules(); await saveRulesForScope("global", ctx); }
				if (scope !== "Cancel") {
					resetSessionState();
					persistSessionState();
					sensitiveFilePaths = await refreshSensitiveFilePaths(pi, activeDirs());
					syncRuntimeBaseConfig(ctx.cwd);
					updateStatus(ctx);
					ctx.ui.notify("Sandbox access cleared.", "info");
				}
				return;
			}
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
				"",
				...formatSection("Read-only dirs", currentReadOnlyDirs()),
				"",
				...formatSection("Session full access", [...session.dirs].sort()),
				"",
				...formatSection("Session read-only", [...session.readDirs].sort()),
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
				...formatSection("Session protected full", [...session.protectedDirs].sort()),
				"",
				...formatSection("Session protected read-only", [...session.protectedReadDirs].sort()),
				"",
				...formatSection("Project protected full", projectRules.protectedDirs ?? []),
				"",
				...formatSection("Project protected read-only", projectRules.protectedReadDirs ?? []),
				"",
				...formatSection("Global protected full", globalRules.protectedDirs ?? []),
				"",
				...formatSection("Global protected read-only", globalRules.protectedReadDirs ?? []),
				"",
				...formatSection("Session allowed domains", [...session.allowedDomains].sort()),
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
				`  Protected sandbox control files: ${protectedControlFiles(protectedPaths).join(", ") || "(none)"}`,
				"",
				"Network:",
				`  Configured allowed domains: ${configuredDomainsLabel}`,
				`  Effective allowed domains: ${effectiveDomainsLabel}`,
				"  Unix sockets: unrestricted",
				`  Denied domains: ${effectiveDeniedDomains().join(", ") || "(none)"}`,
				`  Local binding: ${osSandboxConfig?.network?.allowLocalBinding ? "allowed" : "blocked"}`,
			];
			if (session.highRiskPrefixes.size) {
				lines.push("", `Session high-risk prefixes (${session.highRiskPrefixes.size}):`);
				for (const prefix of [...session.highRiskPrefixes].sort()) lines.push(`  ${prefix}`);
			}
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});
}
