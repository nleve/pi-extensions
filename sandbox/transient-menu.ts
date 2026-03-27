/**
 * Transient menu — single-keypress bottom panel for sandbox prompts.
 *
 * Inspired by magit/which-key. Replaces the editor and footer with a clean
 * panel at the bottom of the screen. Conversation stays fully visible above.
 * Responds to single keypresses and includes a configurable grace period to
 * prevent accidental triggers from buffered input.
 */

import { matchesKey, Key, visibleWidth, truncateToWidth } from "@mariozechner/pi-tui";

// ── Types ────────────────────────────────────────────────────────────────────

export interface Binding<T> {
	key: string;
	label: string;
	value: T;
}

export type MenuSection<T> =
	| { type: "row"; bindings: Binding<T>[] }
	| {
			type: "matrix";
			columns: string[];
			rows: { label: string; cells: (Binding<T> | null)[] }[];
	  }
	| { type: "spacer" };

export interface TransientOptions<T> {
	title: string;
	context: string[];
	sections: MenuSection<T>[];
	footer?: Binding<T>[];
	cancelLabel?: string;
	cancelValue: T;
	grace?: number;
}

// ── Key matching ─────────────────────────────────────────────────────────────

function matchBinding<T>(data: string, binding: Binding<T>): boolean {
	if (binding.key === "ESC") return matchesKey(data, Key.escape);
	return data === binding.key;
}

function collectBindings<T>(options: TransientOptions<T>): Binding<T>[] {
	const result: Binding<T>[] = [];
	for (const s of options.sections) {
		if (s.type === "row") result.push(...s.bindings);
		else if (s.type === "matrix")
			for (const r of s.rows) for (const c of r.cells) if (c) result.push(c);
	}
	if (options.footer) result.push(...options.footer);
	return result;
}

// ── Rendering ────────────────────────────────────────────────────────────────

export const LPAD = 2;

interface Styles {
	border: (s: string) => string;
	title: (s: string) => string;
	key: (s: string) => string;
	text: (s: string) => string;
	muted: (s: string) => string;
	dim: (s: string) => string;
	escKey: (s: string) => string;
}

export function titleRule(width: number, title: string, border: (s: string) => string, titleStyle: (s: string) => string): string {
	const t = ` ${title} `;
	const styled = titleStyle(t);
	const pre = "───";
	const rest = Math.max(0, width - 3 - visibleWidth(styled));
	return border(pre) + styled + border("─".repeat(rest));
}

export function bottomRule(width: number, border: (s: string) => string): string {
	return border("─".repeat(width));
}

export function pad(content: string, width: number): string {
	return truncateToWidth(" ".repeat(LPAD) + content, width);
}

function renderRow<T>(bindings: Binding<T>[], s: Styles): string {
	return bindings.map((b) => `${s.key(b.key)}  ${s.text(b.label)}`).join("   ");
}

function renderMatrix<T>(
	columns: string[],
	rows: { label: string; cells: (Binding<T> | null)[] }[],
	s: Styles,
): string[] {
	const labelW = Math.max(...rows.map((r) => r.label.length)) + 2;
	const colW = Math.max(8, ...columns.map((c) => c.length + 3));

	let header = " ".repeat(labelW);
	for (const col of columns) header += s.dim(col.padEnd(colW));

	const lines = [header];
	for (const row of rows) {
		let line = s.muted(row.label.padEnd(labelW));
		for (const cell of row.cells) {
			if (!cell) {
				line += " ".repeat(colW);
			} else {
				const styled = s.key(cell.key);
				line += styled + " ".repeat(Math.max(0, colW - visibleWidth(styled)));
			}
		}
		lines.push(line);
	}
	return lines;
}

export function hintsLine(
	leftHints: string,
	rightHints: string,
	width: number,
): string {
	const leftVW = visibleWidth(leftHints);
	const rightVW = visibleWidth(rightHints);
	const total = LPAD + leftVW + 3 + rightVW;
	if (total <= width) {
		const gap = width - LPAD - leftVW - rightVW;
		return truncateToWidth(" ".repeat(LPAD) + leftHints + " ".repeat(gap) + rightHints, width);
	}
	// Fallback: just right-align the cancel
	return truncateToWidth(" ".repeat(Math.max(0, width - rightVW)) + rightHints, width);
}

// ── Footer hiding ────────────────────────────────────────────────────────────

const emptyFooterFactory = (_tui: any, _theme: any, _footerData: any) => ({
	render: (_width: number): string[] => [],
	invalidate: () => {},
});

/**
 * Run a custom UI component as a bottom panel, hiding the footer while active.
 */
export async function withPanelUI<T>(
	ctx: { ui: any; hasUI?: boolean },
	factory: (tui: any, theme: any, kb: any, done: (v: T) => void) => any,
): Promise<T> {
	if (typeof ctx.ui.setFooter === "function") ctx.ui.setFooter(emptyFooterFactory);
	try {
		return await ctx.ui.custom<T>(factory);
	} finally {
		if (typeof ctx.ui.setFooter === "function") ctx.ui.setFooter(undefined);
	}
}

// ── Public API ───────────────────────────────────────────────────────────────

export async function showTransient<T>(
	ctx: { ui: any; hasUI?: boolean },
	options: TransientOptions<T>,
): Promise<T> {
	if (!ctx.hasUI) return options.cancelValue;

	return withPanelUI<T>(ctx, (tui: any, theme: any, _kb: any, done: (v: T) => void) => {
		const graceDuration = options.grace ?? 500;
		const graceUntil = Date.now() + graceDuration;
		let graceActive = graceDuration > 0;
		let cachedWidth: number | undefined;
		let cachedLines: string[] | undefined;

		const timer =
			graceDuration > 0
				? setTimeout(() => {
						graceActive = false;
						cachedWidth = undefined;
						cachedLines = undefined;
						tui.requestRender();
					}, graceDuration)
				: undefined;

		const bindings = collectBindings(options);

		return {
			handleInput(data: string) {
				if (matchesKey(data, Key.escape)) {
					if (timer) clearTimeout(timer);
					done(options.cancelValue);
					return;
				}
				if (Date.now() < graceUntil) return;
				for (const b of bindings) {
					if (matchBinding(data, b)) {
						if (timer) clearTimeout(timer);
						done(b.value);
						return;
					}
				}
			},

			render(width: number): string[] {
				if (cachedLines && cachedWidth === width) return cachedLines;

				const s: Styles = {
					border: (t) => theme.fg("border", t),
					title: (t) => theme.fg("accent", theme.bold(t)),
					key: (k) => (graceActive ? theme.fg("dim", k) : theme.fg("accent", k)),
					text: (t) => theme.fg("text", t),
					muted: (t) => theme.fg("muted", t),
					dim: (t) => theme.fg("dim", t),
					escKey: (t) => theme.fg("accent", t),
				};

				const lines: string[] = [];

				// Title rule
				lines.push(titleRule(width, options.title, s.border, s.title));

				// Context
				for (const c of options.context) lines.push(pad(s.muted(c), width));
				lines.push("");

				// Sections
				for (const section of options.sections) {
					if (section.type === "spacer") {
						lines.push("");
					} else if (section.type === "row") {
						lines.push(pad(renderRow(section.bindings, s), width));
					} else if (section.type === "matrix") {
						for (const ml of renderMatrix(section.columns, section.rows, s))
							lines.push(pad(ml, width));
					}
				}

				// Hints
				lines.push("");
				const cancelStr = `${s.escKey("ESC")}  ${s.muted(options.cancelLabel ?? "deny")}`;
				const leftStr = options.footer?.length ? renderRow(options.footer, s) : "";
				lines.push(hintsLine(leftStr, cancelStr, width));

				// Bottom rule
				lines.push(bottomRule(width, s.border));

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
