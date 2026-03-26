import type { AccessBoundary } from "./policy";
import { defaultHighRiskPrefix, highRiskSegments, normalizeDomainPattern, normalizePrefix } from "./policy";
import { showTransient, type Binding, type MenuSection } from "./transient-menu";
import type { AccessLevel, AllowScope } from "./state";

type UIContext = { ui: any; hasUI?: boolean };
export type PathResult = "once" | "sr" | "Sf" | "pr" | "Pf" | "gr" | "Gf" | "custom" | "deny";
export type DomainResult = "once" | "session" | "project" | "global" | "custom" | "deny";

const pathScopes: Record<string, { scope: AllowScope; level: AccessLevel }> = {
	sr: { scope: "session", level: "read" }, Sf: { scope: "session", level: "full" },
	pr: { scope: "project", level: "read" }, Pf: { scope: "project", level: "full" },
	gr: { scope: "global", level: "read" }, Gf: { scope: "global", level: "full" },
};
const domainScopes = { session: "session", project: "project", global: "global" } as const;

function pathScopeLevel(result: string): { scope: AllowScope; level: AccessLevel } | undefined {
	return pathScopes[result];
}

function buildPathMenuSections(showReadColumn: boolean, includeOnce: boolean): MenuSection<PathResult>[] {
	const persistSection: MenuSection<PathResult> = showReadColumn
		? {
			type: "matrix",
			columns: ["read", "full"],
			rows: [
				{ label: "session", cells: [{ key: "s", label: "", value: "sr" }, { key: "S", label: "", value: "Sf" }] },
				{ label: "project", cells: [{ key: "p", label: "", value: "pr" }, { key: "P", label: "", value: "Pf" }] },
				{ label: "global", cells: [{ key: "g", label: "", value: "gr" }, { key: "G", label: "", value: "Gf" }] },
			],
		}
		: {
			type: "row",
			bindings: [
				{ key: "S", label: "session", value: "Sf" },
				{ key: "P", label: "project", value: "Pf" },
				{ key: "G", label: "global", value: "Gf" },
			],
		};
	return includeOnce
		? [{ type: "row", bindings: [{ key: "y", label: "once", value: "once" }] }, { type: "spacer" }, persistSection]
		: [persistSection];
}

export async function promptBoundaryAccess(
	ctx: UIContext,
	operation: string,
	path: string,
	boundary: AccessBoundary,
	deps: {
		allowPersistent?: boolean;
		protectedMode?: boolean;
		extraContext?: string[];
		addAllowedDir: (dir: string, scope: AllowScope, level: AccessLevel, ctx?: { ui: any }) => Promise<boolean>;
		addProtectedAllowedDir: (dir: string, scope: AllowScope, level: AccessLevel, ctx?: { ui: any }) => Promise<boolean>;
		normalizeAllowedDir: (input: string) => Promise<string>;
		updateStatus: (ctx: { ui: any }) => void;
	},
): Promise<{ block: boolean; reason?: string } | undefined> {
	if (!ctx.hasUI) return { block: true, reason: `${boundary.kind} access blocked (no UI): ${boundary.dir}` };
	const suggested = boundary.suggestions[0];
	const showRead = operation === "READ" || operation === "BASH";
	const allowPersistent = deps.allowPersistent !== false;
	const persistDir = deps.protectedMode ? deps.addProtectedAllowedDir : deps.addAllowedDir;
	const context = [`${operation}  ${path}`, ...(deps.extraContext ?? []), `→  ${suggested.dir}  (${suggested.label})`];
	if (!allowPersistent) {
		const result = await showTransient(ctx, {
			title: "Sandbox",
			context: [...context, "sensitive — once only"],
			sections: [{ type: "row", bindings: [{ key: "y", label: "allow this command", value: "allow" as const }] }],
			cancelValue: "deny" as const,
		});
		return result === "allow" ? undefined : { block: true, reason: `User denied access to ${boundary.dir}` };
	}
	let grace = 500;
	while (true) {
		const result = await showTransient<PathResult>(ctx, {
			title: "Sandbox",
			context: deps.protectedMode ? [...context, "protected path"] : context,
			sections: buildPathMenuSections(showRead, true),
			footer: [{ key: "e", label: "custom path", value: "custom" }],
			cancelValue: "deny",
			grace,
		});
		grace = 0;
		if (result === "once") return undefined;
		if (result === "deny") return { block: true, reason: `User denied access to ${boundary.dir}` };
		const selection = pathScopeLevel(result);
		if (selection) {
			const saved = await persistDir(suggested.dir, selection.scope, selection.level, ctx);
			if (!saved) return { block: true, reason: "Could not persist sandbox access" };
			deps.updateStatus(ctx);
			return undefined;
		}
		if (result !== "custom") continue;
		const entered = await ctx.ui.input("Path:", suggested.dir);
		if (!entered?.trim()) continue;
		const dir = await deps.normalizeAllowedDir(entered.trim());
		const subResult = await showTransient<PathResult>(ctx, {
			title: "Sandbox",
			context: deps.protectedMode ? [`custom  ${dir}`, "protected path"] : [`custom  ${dir}`],
			sections: buildPathMenuSections(showRead, false),
			cancelLabel: "back",
			cancelValue: "deny",
			grace: 0,
		});
		if (subResult === "deny") continue;
		const subSelection = pathScopeLevel(subResult);
		if (!subSelection) continue;
		const saved = await persistDir(dir, subSelection.scope, subSelection.level, ctx);
		if (!saved) return { block: true, reason: "Could not persist sandbox access" };
		deps.updateStatus(ctx);
		return undefined;
	}
}

export async function promptDomainAccess(
	ctx: UIContext,
	domain: string,
	command: string,
	deps: {
		isDomainDenied: (domain: string) => boolean;
		deniedReason: string;
		addAllowedDomain: (domain: string, scope: AllowScope, ctx?: { ui: any }) => Promise<boolean>;
		updateStatus: (ctx: { ui: any }) => void;
	},
): Promise<{ block: boolean; reason?: string; oneShotPatterns?: string[] } | undefined> {
	if (deps.isDomainDenied(domain)) return { block: true, reason: `Domain ${domain} is denied by sandbox config (${deps.deniedReason})` };
	if (!ctx.hasUI) return { block: true, reason: `Domain blocked (no UI): ${domain}` };
	const bindings: Binding<DomainResult>[] = [
		{ key: "y", label: "once", value: "once" },
		{ key: "s", label: "session", value: "session" },
		{ key: "p", label: "project", value: "project" },
		{ key: "g", label: "global", value: "global" },
	];
	const handle = async (result: DomainResult, target: string) => {
		if (result === "once") return { block: false, oneShotPatterns: [target] };
		const scope = domainScopes[result as keyof typeof domainScopes];
		if (!scope) return { block: true, reason: `User denied domain access to ${domain}` };
		const saved = await deps.addAllowedDomain(target, scope, ctx);
		if (!saved) return { block: true, reason: `Could not persist domain access for ${target}` };
		deps.updateStatus(ctx);
		return { block: false };
	};
	let grace = 500;
	while (true) {
		const result = await showTransient<DomainResult>(ctx, {
			title: "Sandbox",
			context: [`BASH  ${domain}`, `in  ${command}`],
			sections: [{ type: "row", bindings }],
			footer: [{ key: "e", label: "custom pattern", value: "custom" }],
			cancelValue: "deny",
			grace,
		});
		grace = 0;
		if (result !== "custom") return handle(result, domain);
		const entered = await ctx.ui.input("Domain or pattern:", domain);
		const normalized = normalizeDomainPattern(entered?.trim() ?? "");
		if (!normalized) {
			if (!entered?.trim()) continue;
			ctx.ui.notify("Invalid domain or pattern", "warning");
			continue;
		}
		const subResult = await showTransient<DomainResult>(ctx, {
			title: "Sandbox",
			context: [`custom  ${normalized}`],
			sections: [{ type: "row", bindings }],
			cancelLabel: "back",
			cancelValue: "deny",
			grace: 0,
		});
		if (subResult === "deny") continue;
		return handle(subResult, normalized);
	}
}

export async function confirmHighRiskBash(
	command: string,
	ctx: UIContext,
	deps: {
		isApprovedForSession: (segment: string) => boolean;
		approvePrefix: (prefix: string) => void;
		persistSessionState: () => void;
	},
): Promise<{ block: boolean; reason?: string } | undefined> {
	const risks = highRiskSegments(command);
	if (risks.length === 0) return undefined;
	if (!ctx.hasUI) return { block: true, reason: `High-risk bash blocked (no UI): ${command}` };
	for (const { segment, reasons } of risks) {
		if (deps.isApprovedForSession(segment)) continue;
		const suggestedPrefix = defaultHighRiskPrefix(segment);
		const result = await showTransient<"once" | "approve" | "edit" | "deny">(ctx, {
			title: "Sandbox",
			context: [`BASH  ${segment}`, ...reasons.map((reason) => `·  ${reason}`)],
			sections: [
				{ type: "row", bindings: [{ key: "y", label: "allow once", value: "once" }] },
				{ type: "row", bindings: [{ key: "a", label: `approve "${suggestedPrefix}" for session`, value: "approve" }] },
				{ type: "row", bindings: [{ key: "e", label: "edit prefix to approve", value: "edit" }] },
			],
			cancelValue: "deny",
		});
		if (result === "once") continue;
		if (result === "approve") deps.approvePrefix(suggestedPrefix);
		else if (result === "edit") {
			const entered = await ctx.ui.editor("Edit prefix:", suggestedPrefix);
			const prefix = normalizePrefix(entered?.trim() ?? "");
			if (!prefix) return { block: true, reason: "Blocked by user" };
			deps.approvePrefix(prefix);
		} else return { block: true, reason: "Blocked by user" };
		deps.persistSessionState();
	}
	return undefined;
}
