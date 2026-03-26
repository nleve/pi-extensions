/**
 * Agents extension -- switchable agent modes with different tool sets and prompts.
 *
 * Built-in agents:
 *   Build - all tools, default mode for writing code
 *   Plan  - read + bash, investigation and planning, no file edits
 *   Web   - bash only (agent-browser, curl, wget), network still limited by
 *           the sandbox's allowed domains
 *
 * Switch agents:
 *   Alt+A        - cycle through agents
 *   /agent       - show current agent or switch by name
 *
 * Constraints are published on the shared extension event bus for the sandbox
 * extension to enforce.
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

const SANDBOX_AGENT_CONSTRAINTS_EVENT = "sandbox:agent-constraints";

// ── Types ────────────────────────────────────────────────────────────────────

interface AgentConstraints {
	bash?: {
		/** If set, only commands starting with one of these prefixes are allowed. */
		allowPrefixes?: string[];
	};
}

interface Agent {
	name: string;
	label: string;
	tools: string[] | null; // null = all tools
	constraints?: AgentConstraints;
	prompt: string;
}

// ── Agent definitions ────────────────────────────────────────────────────────

const AGENTS: Agent[] = [
	{
		name: "build",
		label: "BUILD",
		tools: null,
		prompt: "",
	},
	{
                name: "review",
		label: "REVIEW",
		tools: ["read", "bash"],
		prompt: [
                        "You are reviewing code. Be critical, but not nitpicky. Look for opportunities for simplification and distillation. Look for interfaces that could be cleaner, and abstractions that are not necessary. Consider critical paths, and whether they could be more resilient and/or simpler. Look for correctness. Consider how understandable the code is. Think through whether abstractions are worth their weight. In general, perform a thoughtful code review.",
                        "Write review comments that are 1-3 sentences each. Be direct. State what should change and why, without hedging. When there's an underlying principle (consistency, simplicity, user impact, etc), lead with it briefly, then give the specific feedback. Name concrete alternative approaches when you have one, but don't write the implementation. When pointing out dead code or unnecessary abstractions, say so plainly. Ground feedback in user-facing impact where relevant (\"this adds latency\", \"the user won't see the failure\"). Use \"we\" framing. No praise sandwiches, no emojis, no filler."
		].join("\n"),
	},
	{
		name: "plan",
		label: "PLAN",
		tools: ["read", "bash"],
		prompt: [
			"You are in PLAN mode. Your job is to investigate, analyze, and produce a plan.",
			"You can read files and run commands but you CANNOT create or edit files.",
			"Focus on understanding the codebase, identifying issues, and outlining a clear plan of action.",
			"When you have a plan, present it clearly in your response. Keep it concise but complete.",
		].join("\n"),
	},
	{
		name: "web",
		label: "WEB",
		tools: ["bash"],
		constraints: {
			bash: {
				allowPrefixes: ["agent-browser", "curl", "wget"],
			},
		},
		prompt: [
			"You are in WEB mode. You are a general-purpose assistant with restricted web-browsing capability.",
			"Use the agent-browser CLI to browse the web:",
			"  agent-browser open <url>",
			"  agent-browser snapshot -i",
			"  agent-browser click @e1",
			"  agent-browser fill @e1 \"text\"",
			"  agent-browser close",
			"You can also use curl and wget for direct HTTP requests.",
			"Network access is still limited by the sandbox's allowed domains.",
			"If a site is blocked, explain that the sandbox configuration needs to allow it.",
			"Focus on helping the user with questions, research, and information from allowed web sources.",
		].join("\n"),
	},
];

// ── Extension ────────────────────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
	let allToolNames: string[] = [];
	let currentIndex = 0;
	let lastMessageAgentIndex = 0;

	function current(): Agent {
		return AGENTS[currentIndex];
	}

	function publish(agent: Agent) {
		pi.events.emit(SANDBOX_AGENT_CONSTRAINTS_EVENT, {
			agentName: agent.name,
			constraints: agent.constraints,
		});
	}

	function applyAgent(ctx: { ui: any }) {
		const agent = current();
		const tools = agent.tools ?? allToolNames;
		pi.setActiveTools(tools);
		publish(agent);
		ctx.ui.setStatus("agent", agent.label);
	}

	function switchTo(index: number, ctx: { ui: any }): { from: Agent; to: Agent } {
		const from = current();
		currentIndex = index;
		const to = current();
		applyAgent(ctx);
		return { from, to };
	}

	pi.on("session_start", async (_event, ctx) => {
		allToolNames = pi.getAllTools().map((t) => t.name);
		applyAgent(ctx);
	});

	pi.on("before_agent_start", async (event, _ctx) => {
		const agent = current();
		const switched = currentIndex !== lastMessageAgentIndex;
		const prev = AGENTS[lastMessageAgentIndex];
		lastMessageAgentIndex = currentIndex;

		const result: any = {};
		if (agent.prompt) result.systemPrompt = event.systemPrompt + "\n\n" + agent.prompt;
		if (switched) {
			result.message = {
				customType: "agent-switch",
				content: `Switched from ${prev.label} to ${agent.label}`,
				display: true,
			};
		}
		return Object.keys(result).length > 0 ? result : undefined;
	});

	pi.registerShortcut("alt+a", {
		description: "Cycle agent mode",
		handler: async (ctx) => {
			const nextIndex = (currentIndex + 1) % AGENTS.length;
			switchTo(nextIndex, ctx);
			ctx.ui.notify(`Agent: ${current().label}`, "info");
		},
	});

	pi.registerCommand("agent", {
		description: "Show or switch agent. Usage: /agent [build|plan|web]",
		handler: async (args, ctx) => {
			const name = args?.trim().toLowerCase();

			if (!name) {
				const agent = current();
				const tools = agent.tools ? agent.tools.join(", ") : "all";
				const lines = [`Current agent: ${agent.label}`, `Tools: ${tools}`];
				if (agent.constraints?.bash?.allowPrefixes) {
					lines.push(`Bash restricted to: ${agent.constraints.bash.allowPrefixes.join(", ")}`);
				}
				if (agent.name === "web") lines.push("Network remains limited by sandbox allowed domains.");
				lines.push("", `Available: ${AGENTS.map((a) => a.name).join(", ")}`);
				lines.push("Shortcut: Alt+A to cycle");
				ctx.ui.notify(lines.join("\n"), "info");
				return;
			}

			const index = AGENTS.findIndex((a) => a.name === name);
			if (index === -1) {
				ctx.ui.notify(`Unknown agent: ${name}\nAvailable: ${AGENTS.map((a) => a.name).join(", ")}`, "error");
				return;
			}
			if (index === currentIndex) {
				ctx.ui.notify(`Already in ${current().label} mode`, "info");
				return;
			}

			switchTo(index, ctx);
			ctx.ui.notify(`Agent: ${current().label}`, "info");
		},
	});
}
