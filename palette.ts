/**
 * Action palette — alt+x or /palette
 *
 * Discovers two dynamic sources:
 * 1. Core interactive actions copied onto a CustomEditor instance
 * 2. Extension / skill / prompt commands from pi.getCommands()
 *
 * This is intentionally closer to Emacs M-x than to slash-command completion.
 */

import { CustomEditor, type AppKeybinding, type ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { getSelectListTheme } from "@mariozechner/pi-coding-agent";
import { SelectList, type SelectItem, matchesKey, Key, fuzzyFilter } from "@mariozechner/pi-tui";
import { withPanelUI, titleRule, bottomRule, hintsLine } from "./sandbox/transient-menu";
import path from "node:path";

type PaletteValue = `action:${string}` | `command:${string}` | `extaction:${string}`;

type ExtensionPaletteAction = {
	id: string;
	label: string;
	description: string;
	shortcut?: string;
	run: (ctx: any) => Promise<void> | void;
};

class ActionMirrorEditor extends CustomEditor {
	constructor(tui: any, theme: any, keybindings: any, onReady: (editor: ActionMirrorEditor) => void) {
		super(tui, theme, keybindings);
		onReady(this);
	}
}

function loadBuiltInSlashCommands(): Array<{ name: string; description?: string }> {
	try {
		const pkgEntry = require.resolve("@mariozechner/pi-coding-agent");
		const pkgRoot = path.dirname(pkgEntry).replace(/\/dist$/, "");
		const mod = require(path.join(pkgRoot, "dist/core/slash-commands.js"));
		return Array.isArray(mod?.BUILTIN_SLASH_COMMANDS) ? mod.BUILTIN_SLASH_COMMANDS : [];
	} catch {
		return [];
	}
}

const BUILTIN_SLASH_COMMANDS = loadBuiltInSlashCommands();

export default function (pi: ExtensionAPI) {
	let currentEditor: ActionMirrorEditor | undefined;

	async function runCommandPreservingDraft(command: string, ctx: any) {
		const draft = ctx.ui?.getEditorText?.() ?? currentEditor?.getText() ?? "";
		if (currentEditor?.onSubmit) {
			await Promise.resolve(currentEditor.onSubmit(command));
			ctx.ui?.setEditorText?.(draft);
			currentEditor?.setText(draft);
			return;
		}
		if (ctx.isIdle?.()) pi.sendUserMessage(command);
		else pi.sendUserMessage(command, { deliverAs: "followUp" });
		ctx.ui?.setEditorText?.(draft);
		currentEditor?.setText(draft);
	}

	const extensionActions: ExtensionPaletteAction[] = [
		{
			id: "reload",
			label: "Reload Runtime",
			description: "Reload extensions, skills, prompts, and themes",
			shortcut: Key.alt("r"),
			run: async (ctx) => {
				if (typeof ctx.reload === "function") {
					await ctx.reload();
					return;
				}
				await runCommandPreservingDraft("/reload", ctx);
			},
		},
		{
			id: "compact",
			label: "Compact Context",
			description: "Trigger context compaction",
			run: async (ctx) => {
				ctx.compact();
			},
		},
		{
			id: "shutdown",
			label: "Quit Pi",
			description: "Gracefully shut down pi",
			run: async (ctx) => {
				ctx.shutdown();
			},
		},
	];

	function titleCaseWords(text: string): string {
		return text
			.split(/\s+/)
			.filter(Boolean)
			.map((word) => word.charAt(0).toUpperCase() + word.slice(1))
			.join(" ");
	}

	function prettifyCommandName(name: string): string {
		const normalized = name
			.replace(/^skill:/, "")
			.replace(/[:_\-]+/g, " ")
			.trim();
		return titleCaseWords(normalized || name);
	}

	function compactParts(parts: Array<string | undefined>): string {
		return parts.filter(Boolean).join(" · ");
	}

	function getActionItems(keybindings: any): SelectItem[] {
		if (!currentEditor) return [];
		return [...currentEditor.actionHandlers.entries()].map(([action]) => {
			const def = keybindings.getDefinition?.(action as AppKeybinding);
			const keys = keybindings.getKeys?.(action as AppKeybinding) ?? [];
			return {
				value: `action:${action}` satisfies PaletteValue,
				label: def?.description ?? titleCaseWords(action.replace(/^app\./, "").replace(/[._]+/g, " ")),
				description: compactParts([
					action,
					keys.length ? keys.join(", ") : undefined,
				]),
			};
		});
	}

	function getDiscoveredCommandItems(): SelectItem[] {
		return pi.getCommands().map((cmd) => ({
			value: `command:/${cmd.name}` satisfies PaletteValue,
			label: prettifyCommandName(cmd.name),
			description: compactParts([
				`/${cmd.name}`,
				cmd.source,
				cmd.description,
			]),
		}));
	}

	function getBuiltInCommandItems(): SelectItem[] {
		return BUILTIN_SLASH_COMMANDS.map((cmd) => ({
			value: `command:/${cmd.name}` satisfies PaletteValue,
			label: prettifyCommandName(cmd.name),
			description: compactParts([
				`/${cmd.name}`,
				"builtin",
				cmd.description,
			]),
		}));
	}

	function getExtensionActionItems(): SelectItem[] {
		return extensionActions.map((action) => ({
			value: `extaction:${action.id}` satisfies PaletteValue,
			label: action.label,
			description: compactParts([
				action.description,
				action.shortcut,
			]),
		}));
	}

	async function showPalette(ctx: any): Promise<PaletteValue | null> {
		return withPanelUI<PaletteValue | null>(ctx, (tui: any, theme: any, keybindings: any, done: (v: PaletteValue | null) => void) => {
			let query = "";
			let selectList: SelectList;
			let items = [...getExtensionActionItems(), ...getActionItems(keybindings), ...getBuiltInCommandItems(), ...getDiscoveredCommandItems()];

			const rebuildList = () => {
				items = [...getExtensionActionItems(), ...getActionItems(keybindings), ...getBuiltInCommandItems(), ...getDiscoveredCommandItems()];
				const filteredItems = query.trim()
					? fuzzyFilter(items, query, (item) => `${item.label} ${item.description ?? ""} ${item.value}`)
					: items;
				selectList = new SelectList(
					filteredItems,
					Math.min(filteredItems.length || 1, 15),
					getSelectListTheme(),
				);
				selectList.onSelect = (item: SelectItem) => done(item.value as PaletteValue);
				selectList.onCancel = () => done(null);
			};
			rebuildList();

			return {
				render(width: number): string[] {
					const border = (s: string) => theme.fg("border", s);
					const title = (s: string) => theme.fg("accent", theme.bold(s));
					const accent = (s: string) => theme.fg("accent", s);
					const dim = (s: string) => theme.fg("dim", s);
					const text = (s: string) => theme.fg("text", s);

					const lines: string[] = [];
					lines.push(titleRule(width, "M-x", border, title));
					lines.push(text(`  search: ${query}`));
					lines.push(...selectList.render(width));
					lines.push("");
					lines.push(
						hintsLine(
							`${dim("type fuzzy filter")}   ${accent("backspace")}  ${dim("delete")}`,
							`${accent("ESC")}  ${dim("close")}`,
							width,
						),
					);
					lines.push(bottomRule(width, border));
					return lines;
				},
				invalidate() {
					selectList.invalidate();
				},
				handleInput(data: string) {
					if (matchesKey(data, Key.backspace)) {
						if (query.length > 0) {
							query = query.slice(0, -1);
							rebuildList();
							tui.requestRender();
						}
						return;
					}
					if (data.length === 1 && data.charCodeAt(0) >= 32) {
						query += data;
						rebuildList();
						tui.requestRender();
						return;
					}
					selectList.handleInput(data);
					tui.requestRender();
				},
			};
		});
	}

	async function executeSelection(selected: PaletteValue, ctx: any) {
		if (selected.startsWith("extaction:")) {
			const id = selected.slice("extaction:".length);
			const action = extensionActions.find((item) => item.id === id);
			if (action) await action.run(ctx);
			return;
		}

		if (selected.startsWith("action:")) {
			const action = selected.slice("action:".length) as AppKeybinding;
			currentEditor?.actionHandlers.get(action)?.();
			return;
		}

		const command = selected.slice("command:".length);
		await runCommandPreservingDraft(command, ctx);
	}

	pi.on("session_start", (_event, ctx) => {
		ctx.ui.setEditorComponent((tui, theme, keybindings) => new ActionMirrorEditor(tui, theme, keybindings, (editor) => {
			currentEditor = editor;
		}));
	});

	pi.registerShortcut(Key.alt("x"), {
		description: "Action palette",
		handler: async (ctx) => {
			const selected = await showPalette(ctx);
			if (selected) await executeSelection(selected, ctx);
		},
	});

	pi.registerShortcut(Key.alt("r"), {
		description: "Reload runtime",
		handler: async (ctx) => {
			await extensionActions.find((action) => action.id === "reload")?.run(ctx);
		},
	});

	pi.registerCommand("palette", {
		description: "Open action palette",
		handler: async (_args, ctx) => {
			const selected = await showPalette(ctx);
			if (selected) await executeSelection(selected, ctx);
		},
	});
}
