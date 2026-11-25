/**
 * Desktop dialogs for the local vault.
 *
 * A display (X11 or Wayland) opens a zenity window. Cancel (exit 1) or
 * timeout (exit 5) does not fall through to the terminal. Zenity missing or
 * unable to open a display falls back to the host TUI. Upstream pi shows that
 * fallback in the clear; OMP masks it when `secret` is set.
 */
import { spawn } from "node:child_process";

const DIALOG_MS = 10 * 60_000;

export interface PromptHost {
	hasUI: boolean;
	ui: {
		input(title: string, placeholder?: string, opts?: { timeout?: number; secret?: boolean }): Promise<string | undefined>;
		confirm(title: string, message: string, opts?: { timeout?: number }): Promise<boolean>;
	};
}

export function hasDisplay(): boolean {
	return !!(process.env.DISPLAY || process.env.WAYLAND_DISPLAY);
}

interface ZenityResult {
	/** False when zenity could not be started. */
	spawned: boolean;
	code: number;
	stdout: string;
}

function zenity(args: string[], signal?: AbortSignal): Promise<ZenityResult> {
	if (signal?.aborted) return Promise.resolve({ spawned: false, code: 1, stdout: "" });
	const { promise, resolve } = Promise.withResolvers<ZenityResult>();
	const child = spawn("zenity", args, { stdio: ["ignore", "pipe", "pipe"] });
	let out = "";
	let settled = false;
	const finish = (result: ZenityResult) => {
		if (settled) return;
		settled = true;
		clearTimeout(timer);
		signal?.removeEventListener("abort", onAbort);
		resolve(result);
	};
	const onAbort = () => {
		child.kill("SIGKILL");
		finish({ spawned: true, code: 1, stdout: "" });
	};
	const timer = setTimeout(() => {
		child.kill("SIGKILL");
		finish({ spawned: true, code: 5, stdout: "" });
	}, DIALOG_MS);
	signal?.addEventListener("abort", onAbort, { once: true });
	child.stdout?.on("data", (chunk: Buffer | string) => {
		if (out.length < 256_000) out += chunk;
	});
	child.on("error", (err: NodeJS.ErrnoException) => {
		// ENOENT or a failed spawn: caller may use the TUI. Never include stdout.
		finish({ spawned: false, code: err.code === "ENOENT" ? 127 : -1, stdout: "" });
	});
	child.on("close", (code) => finish({ spawned: true, code: code ?? -1, stdout: out }));
	return promise;
}

function cancelled(result: ZenityResult): boolean {
	return result.spawned && (result.code === 1 || result.code === 5);
}

/** Secret entry. Empty and cancel are both "no value". */
export async function promptSecret(
	ctx: PromptHost | undefined,
	title: string,
	label: string,
	signal?: AbortSignal,
): Promise<string | undefined> {
	if (signal?.aborted) return undefined;
	if (hasDisplay()) {
		const result = await zenity(
			["--password", `--title=${title} — ${label}`, "--width=420", `--timeout=${DIALOG_MS / 1000}`],
			signal,
		);
		if (cancelled(result)) return undefined;
		if (result.spawned && result.code === 0) {
			const value = result.stdout.replace(/[\r\n]+$/, "");
			return value.length > 0 ? value : undefined;
		}
	}
	if (ctx?.hasUI) {
		const value = await ctx.ui.input(title, label, { timeout: DIALOG_MS, secret: true });
		if (signal?.aborted) return undefined;
		return value && value.length > 0 ? value : undefined;
	}
	return undefined;
}

/** Plain text entry. Cancel is undefined; confirming an empty field is "". */
export async function promptText(
	ctx: PromptHost | undefined,
	title: string,
	label: string,
	signal?: AbortSignal,
): Promise<string | undefined> {
	if (signal?.aborted) return undefined;
	if (hasDisplay()) {
		const result = await zenity(
			["--entry", `--title=${title}`, `--text=${label}`, "--width=480", "--no-markup", `--timeout=${DIALOG_MS / 1000}`],
			signal,
		);
		if (cancelled(result)) return undefined;
		if (result.spawned && result.code === 0) return result.stdout.replace(/[\r\n]+$/, "");
	}
	if (ctx?.hasUI) {
		const value = await ctx.ui.input(title, label, { timeout: DIALOG_MS });
		if (signal?.aborted) return undefined;
		return value;
	}
	return undefined;
}

/**
 * Yes/no window. Deny and timeout are false and do not fall through.
 * A missing display stack falls back to the host confirm dialog.
 */
export async function confirmWindow(
	ctx: PromptHost | undefined,
	title: string,
	message: string,
	signal?: AbortSignal,
): Promise<boolean> {
	if (signal?.aborted) return false;
	if (hasDisplay()) {
		const result = await zenity(
			[
				"--question",
				`--title=${title}`,
				"--text",
				message,
				"--no-markup",
				"--width=520",
				"--default-cancel",
				"--ok-label=允许",
				"--cancel-label=拒绝",
				`--timeout=${DIALOG_MS / 1000}`,
			],
			signal,
		);
		if (cancelled(result)) return false;
		if (result.spawned && result.code === 0) return true;
		// Any other exit means the window never opened. A user deny is exit 1.
	}
	if (ctx?.hasUI) {
		const ok = await ctx.ui.confirm(title, message, { timeout: DIALOG_MS });
		if (signal?.aborted) return false;
		return ok === true;
	}
	return false;
}
