/**
 * Where omp and upstream pi differ, kept in one place.
 *
 * omp is a pi-compatible fork: same package manifest, same tool and command
 * API, so one extension serves both hosts. The differences are small and are
 * feature-detected here instead of being spread through the code:
 *   - `api.pi` exists only on omp.
 *   - pi says why a session ended on `session_start` / `session_shutdown`;
 *     omp says it on `session_switch`, and its start and shutdown events carry
 *     no reason.
 *   - `ctx.agent` names the agent a binding serves (omp only).
 *   - omp tiers tools for its approval modes; pi has no such field.
 */
import type { ExtensionAPI, ExtensionContext, ToolDefinition } from "@earendil-works/pi-coding-agent";

export function isOmpHost(pi: ExtensionAPI): boolean {
	return "pi" in pi;
}

/**
 * omp asks for approval by tier and defaults to "exec" when none is given, so
 * a read-only tool would be prompted like a shell command. pi ignores the field.
 */
export function withTier<T extends ToolDefinition<any, any>>(tool: T, approval: "read" | "write" | "exec"): T {
	return { ...tool, approval } as T;
}

/** Why the bound session stopped being the one that unlocked. */
export type LeaveReason = "new" | "fork" | "resume" | "quit" | "reload";
type LeaveHandler = (reason: LeaveReason, ctx: ExtensionContext | undefined) => void | Promise<void>;

/**
 * Call `handler` when the session served by this binding is left: `/new`,
 * `/fork`, `/resume`, reload, or shutdown. Startup is not a leave.
 */
export function onSessionLeave(pi: ExtensionAPI, omp: boolean, handler: LeaveHandler): void {
	if (omp) {
		// omp's `session_switch` and its reason-less `session_shutdown`. The start
		// event has no reason, so it must never be read as one.
		const on = (event: string, h: (event: { reason?: string }, ctx: ExtensionContext) => unknown) =>
			(pi as unknown as { on(name: string, handler: typeof h): void }).on(event, h);
		on("session_switch", (event, ctx) => handler((event.reason ?? "quit") as LeaveReason, ctx));
		on("session_shutdown", (_event, ctx) => handler("quit", ctx));
		return;
	}
	pi.on("session_start", async (event, ctx) => {
		if (event.reason === "startup" || event.reason === "reload") return;
		await handler(event.reason, ctx);
	});
	pi.on("session_shutdown", async (event, ctx) => {
		await handler(event.reason, ctx);
	});
}

/** The subagent this context serves, or undefined for a top-level session. */
export function subagentId(ctx: unknown): string | undefined {
	const agent = (ctx as { agent?: { kind?: string; id?: string } } | undefined)?.agent;
	return agent?.kind === "sub" && agent.id ? agent.id : undefined;
}

/**
 * Short, stable label for the audit log: the first bytes of the session id,
 * plus the agent id for a subagent.
 */
export function sessionLabel(ctx: unknown): string {
	let id = "";
	try {
		const manager = (ctx as { sessionManager?: { getSessionId?: () => string } } | undefined)?.sessionManager;
		id = manager?.getSessionId?.() ?? "";
	} catch {
		/* a context without a session manager */
	}
	const base = id.replace(/-/g, "").slice(0, 8) || "main";
	const sub = subagentId(ctx);
	return sub ? `${base}/${sub.replace(/[^\w.-]/g, "").slice(0, 24) || "sub"}` : base;
}
