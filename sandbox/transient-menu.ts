/**
 * Transient menu — single-keypress overlay menus for sandbox prompts.
 *
 * Inspired by magit/which-key. Renders a bordered overlay with keybinding
 * groups, responds to single keypresses, and includes a configurable grace
 * period to prevent accidental triggers from buffered input.
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

const LPAD = 2;

interface Styles {
	border: (s: string) => string;
	title: (s: string) => string;
	key: (s: string) => string;
	text: (s: string) => string;
	muted: (s: string) => string;
	dim: (s: string) => string;
	escKey: (s: string) => string;
}

function borderLine(l: string, r: string, w: number, fn: Styles["border"], label?: { text: string; style: (s: string) => string }): string {
	if (!label) return fn(l + "─".repeat(w - 2) + r);
	const t = ` ${label.text} `;
	const fill = Math.max(0, w - 3 - t.length);
	return fn(l + "─") + label.style(t) + fn("─".repeat(fill) + r);
}

function contentLine(inner: string, w: number, border: Styles["border"]): string {
	const maxW = w - 2 - LPAD;
	const truncated = truncateToWidth(inner, maxW);
	const vw = visibleWidth(truncated);
	const pad = Math.max(0, maxW - vw);
	return border("│") + " ".repeat(LPAD) + truncated + " ".repeat(pad) + border("│");
}

function blankLine(w: number, border: Styles["border"]): string {
	return border("│") + " ".repeat(w - 2) + border("│");
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

// ── Public API ───────────────────────────────────────────────────────────────

export function showTransient<T>(
	ctx: { ui: any; hasUI?: boolean },
	options: TransientOptions<T>,
): Promise<T> {
	if (!ctx.hasUI) return Promise.resolve(options.cancelValue);

	return ctx.ui.custom<T>(
		(tui: any, theme: any, _kb: any, done: (v: T) => void) => {
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
					// ESC always works, even during grace
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
						escKey: (t) => theme.fg("accent", t), // ESC always bright
					};

					const lines: string[] = [];
					lines.push(borderLine("╭", "╮", width, s.border, { text: options.title, style: s.title }));
					for (const c of options.context) lines.push(contentLine(s.muted(c), width, s.border));
					lines.push(borderLine("├", "┤", width, s.border));

					for (const section of options.sections) {
						if (section.type === "spacer") {
							lines.push(blankLine(width, s.border));
						} else if (section.type === "row") {
							lines.push(contentLine(renderRow(section.bindings, s), width, s.border));
						} else if (section.type === "matrix") {
							for (const ml of renderMatrix(section.columns, section.rows, s))
								lines.push(contentLine(ml, width, s.border));
						}
					}

					// Footer: optional left bindings + right-aligned cancel
					lines.push(blankLine(width, s.border));
					const maxW = width - 2 - LPAD;
					const cancelStr = `${s.escKey("ESC")}  ${s.muted(options.cancelLabel ?? "deny")}`;
					const cancelVW = visibleWidth(cancelStr);

					if (options.footer?.length) {
						const leftStr = renderRow(options.footer, s);
						const leftVW = visibleWidth(leftStr);
						if (leftVW + 3 + cancelVW <= maxW) {
							const gap = maxW - leftVW - cancelVW;
							lines.push(contentLine(leftStr + " ".repeat(gap) + cancelStr, width, s.border));
						} else {
							lines.push(contentLine(leftStr, width, s.border));
							lines.push(contentLine(" ".repeat(Math.max(0, maxW - cancelVW)) + cancelStr, width, s.border));
						}
					} else {
						lines.push(contentLine(" ".repeat(Math.max(0, maxW - cancelVW)) + cancelStr, width, s.border));
					}

					lines.push(borderLine("╰", "╯", width, s.border));

					cachedWidth = width;
					cachedLines = lines;
					return lines;
				},

				invalidate() {
					cachedWidth = undefined;
					cachedLines = undefined;
				},
			};
		},
		{
			overlay: true,
			overlayOptions: {
				anchor: "bottom-center" as any,
				width: "60%",
				minWidth: 50,
			},
		},
	);
}
