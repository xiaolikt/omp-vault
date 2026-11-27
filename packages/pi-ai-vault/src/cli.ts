/**
 * Thin client for the `ai-vault` binary.
 *
 * The extension holds no key and does no cryptography: it asks the CLI to
 * unlock (one desktop password window), keeps the session token, and passes
 * that token back for every later call. Passwords are typed into the CLI's own
 * windows; a headless machine answers exit code 3 ("needs-ui") and the host
 * dialog takes over here.
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const EXIT = {
	error: 1,
	usage: 2,
	needsUi: 3,
	denied: 4,
	auth: 5,
} as const;

/** Which dialog the CLI would have opened, when it cannot open one. */
export type UiStep = "password" | "text" | "confirm";

export interface CliRun {
	code: number;
	stdout: string;
	stderr: string;
}

/** Non-zero exit from the CLI, with the meaning of the code preserved. */
export class CliError extends Error {
	constructor(
		readonly code: number,
		readonly needsUi: UiStep | undefined,
		message: string,
		readonly stderr: string,
	) {
		super(message);
		this.name = "CliError";
	}

	get denied(): boolean {
		return this.code === EXIT.denied;
	}

	get auth(): boolean {
		return this.code === EXIT.auth;
	}
}

/**
 * `AI_VAULT_BIN`, then the copy this package depends on (npm puts the shim in
 * a node_modules/.bin next to or above the plugin), then PATH, then the usual
 * install spots.
 */
export function resolveBinary(): string | undefined {
	const explicit = process.env.AI_VAULT_BIN;
	if (explicit) return existsSync(explicit) ? explicit : undefined;

	// pip/npm layouts hoist differently: walk up from packages/pi-ai-vault/src.
	let dir = dirname(fileURLToPath(import.meta.url));
	for (let depth = 0; depth < 5; depth++) {
		const bundled = join(dir, "node_modules", ".bin", "ai-vault");
		if (existsSync(bundled)) return bundled;
		const parent = dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}

	for (const entry of (process.env.PATH ?? "").split(delimiter)) {
		if (!entry) continue;
		const candidate = join(entry, "ai-vault");
		if (existsSync(candidate)) return candidate;
	}
	for (const candidate of [join(homedir(), ".local", "bin", "ai-vault"), join(homedir(), ".cargo", "bin", "ai-vault")]) {
		if (existsSync(candidate)) return candidate;
	}
	return undefined;
}

const NEEDS_UI = /^needs-ui:\s*(\w+)/m;

function message(stderr: string, fallback: string): string {
	const lines = stderr
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter((line) => line.length > 0 && !line.startsWith("needs-ui:") && !line.startsWith("no desktop window"));
	return lines[0]?.replace(/^ai-vault:\s*/, "") ?? fallback;
}

export class VaultCli {
	readonly bin = resolveBinary();

	get available(): boolean {
		return this.bin !== undefined;
	}

	/** The store directory the CLI will use, for messages only. */
	get dir(): string {
		return process.env.AI_VAULT_DIR ?? join(homedir(), ".ai-vault");
	}

	async run(args: string[], opts: { stdin?: string; signal?: AbortSignal } = {}): Promise<CliRun> {
		const bin = this.bin;
		if (!bin) {
			throw new CliError(EXIT.error, undefined, "ai-vault CLI not found", "");
		}
		if (opts.signal?.aborted) {
			throw new CliError(EXIT.denied, undefined, "aborted", "");
		}
		const run = await new Promise<CliRun>((resolve, reject) => {
			const child = spawn(bin, args, { stdio: ["pipe", "pipe", "pipe"] });
			let stdout = "";
			let stderr = "";
			const onAbort = () => child.kill("SIGKILL");
			opts.signal?.addEventListener("abort", onAbort, { once: true });
			child.stdout?.on("data", (chunk: Buffer | string) => {
				if (stdout.length < 32 * 1024 * 1024) stdout += chunk;
			});
			child.stderr?.on("data", (chunk: Buffer | string) => {
				if (stderr.length < 256_000) stderr += chunk;
			});
			child.on("error", (error) => {
				opts.signal?.removeEventListener("abort", onAbort);
				reject(new CliError(EXIT.error, undefined, `cannot run ${bin}: ${error.message}`, ""));
			});
			child.on("close", (code) => {
				opts.signal?.removeEventListener("abort", onAbort);
				resolve({ code: code ?? -1, stdout, stderr });
			});
			// A dialog may keep stdin open for minutes; closing it early would
			// make a password read fail, so only write when there is input.
			if (opts.stdin !== undefined) child.stdin?.end(opts.stdin);
			else child.stdin?.end();
		});
		if (run.code !== 0) {
			const step = NEEDS_UI.exec(run.stderr)?.[1] as UiStep | undefined;
			throw new CliError(run.code, step, message(run.stderr, `ai-vault exited with ${run.code}`), run.stderr);
		}
		return run;
	}

	/** One CLI call whose output is a JSON object. */
	async json<T>(args: string[], opts: { stdin?: string; signal?: AbortSignal } = {}): Promise<T> {
		const run = await this.run([...args, "--json"], opts);
		try {
			return JSON.parse(run.stdout) as T;
		} catch {
			throw new CliError(EXIT.error, undefined, `ai-vault returned non-JSON output: ${run.stdout.slice(0, 200)}`, run.stderr);
		}
	}

	/** Start a call, turning a "needs-ui password" into the host secret dialog. */
	async withPassword(
		args: string[],
		ask: () => Promise<string | undefined>,
		opts: { stdin?: string; signal?: AbortSignal } = {},
	): Promise<CliRun> {
		try {
			return await this.run(args, opts);
		} catch (error) {
			if (!(error instanceof CliError) || !error.needsUi) throw error;
			const password = await ask();
			if (!password) throw new CliError(EXIT.denied, undefined, "cancelled: no password entered", "");
			return this.run([...args, "--password-stdin"], { stdin: `${password}\n`, signal: opts.signal });
		}
	}
}
