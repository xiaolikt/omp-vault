/**
 * Desktop dialogs, shared by the local vault and the Bitwarden tools.
 *
 * A display (X11 or Wayland) opens a zenity window. Cancel (exit 1) and our
 * own timeout (exit 5) end the prompt there: they never fall through to a
 * second, terminal prompt. When no window could open at all (zenity missing,
 * an option it rejects, a display it cannot reach) the host dialog is used
 * instead. Upstream pi shows typed text in the clear; OMP masks it.
 */
import { spawn } from "node:child_process";

const DIALOG_MS = 10 * 60_000;
const STDERR_CAP = 16_000;

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
	stderr: string;
}

function zenity(args: string[], signal?: AbortSignal): Promise<ZenityResult> {
	const closed: ZenityResult = { spawned: false, code: 1, stdout: "", stderr: "" };
	if (signal?.aborted) return Promise.resolve(closed);
	const { promise, resolve } = Promise.withResolvers<ZenityResult>();
	const child = spawn("zenity", args, { stdio: ["ignore", "pipe", "pipe"] });
	let out = "";
	let err = "";
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
		finish({ spawned: true, code: 1, stdout: "", stderr: "" });
	};
	const timer = setTimeout(() => {
		child.kill("SIGKILL");
		finish({ spawned: true, code: 5, stdout: "", stderr: "" });
	}, DIALOG_MS);
	signal?.addEventListener("abort", onAbort, { once: true });
	// Both pipes must be drained, or a chatty GTK fills one and blocks the dialog.
	child.stdout?.on("data", (chunk: Buffer | string) => {
		if (out.length < 256_000) out += chunk;
	});
	child.stderr?.on("data", (chunk: Buffer | string) => {
		if (err.length < STDERR_CAP) err += chunk;
	});
	child.on("error", (e: NodeJS.ErrnoException) => {
		// ENOENT or a failed spawn: the caller may use the host dialog.
		finish({ spawned: false, code: e.code === "ENOENT" ? 127 : -1, stdout: "", stderr: "" });
	});
	child.on("close", (code) => finish({ spawned: true, code: code ?? -1, stdout: out, stderr: err }));
	return promise;
}

/**
 * True when no dialog ran. Exit 1 is ambiguous on some zenity builds (cancel
 * and a failed start both use it), so stderr decides: GTK's own diagnostics
 * carry a `(zenity:PID): Gtk-WARNING` prefix; any other line, or a display
 * failure, means the window never opened.
 */
function failedToOpen(result: ZenityResult): boolean {
	if (!result.spawned) return true;
	if (result.code === 0 || result.code === 5) return false;
	if (/cannot open display|unable to (?:open|init)|failed to (?:open|init)/i.test(result.stderr)) return true;
	const gtkDiagnostic = /^\**\s*\(\w+:\d+\):\s+[\w-]+-(?:WARNING|CRITICAL|MESSAGE|DEBUG)\b/;
	return result.stderr.split(/\r?\n/).some((line) => line.trim() !== "" && !gtkDiagnostic.test(line));
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
		if (!failedToOpen(result)) {
			const value = result.stdout.replace(/[\r\n]+$/, "");
			return result.code === 0 && value ? value : undefined;
		}
		if (signal?.aborted) return undefined;
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
		if (!failedToOpen(result)) return result.code === 0 ? result.stdout.replace(/[\r\n]+$/, "") : undefined;
		if (signal?.aborted) return undefined;
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
 * When no window could open, the host confirm dialog is asked instead.
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
		if (!failedToOpen(result)) return result.code === 0;
		if (signal?.aborted) return false;
	}
	if (ctx?.hasUI) {
		const ok = await ctx.ui.confirm(title, message, { timeout: DIALOG_MS });
		if (signal?.aborted) return false;
		return ok === true;
	}
	return false;
}
