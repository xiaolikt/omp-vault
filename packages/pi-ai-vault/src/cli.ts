/**
 * Thin client for the `ai-vault` binary.
 *
 * The extension holds no key and does no cryptography: it asks the CLI to
 * unlock (one desktop password window), keeps the session token, and passes
 * that token back for every later call. Passwords are typed into the CLI's own
 * windows; a headless machine answers exit code 3 ("needs-ui") and the host
 * dialog takes over here.
 */
import { createHmac, randomBytes } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { delimiter, dirname, extname, join } from "node:path";
import { lang } from "./i18n.js";
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
	/** For `needsUi === "password"`: the hidden field the CLI wants next. */
	readonly field: string | undefined;

	constructor(
		readonly code: number,
		readonly needsUi: UiStep | undefined,
		message: string,
		readonly stderr: string,
		field?: string,
	) {
		super(message);
		this.name = "CliError";
		this.field = field;
	}

	get denied(): boolean {
		return this.code === EXIT.denied;
	}

	get auth(): boolean {
		return this.code === EXIT.auth;
	}
}

/** How to start the CLI: a program, plus what has to precede our arguments. */
export interface CliLaunch {
	program: string;
	pre: string[];
}

const WIN32 = process.platform === "win32";
/** The file npm links for the bin: an `.exe` where there is one, else its `.cmd` wrapper. */
const BIN_NAMES = WIN32 ? ["ai-vault.exe", "ai-vault.cmd"] : ["ai-vault"];

/**
 * What an npm `.cmd` wrapper starts, so that that can be started instead.
 *
 * npm links a package's bin as a sh script, a `.cmd` and a `.ps1` beside the
 * real thing. Node refuses to run any of them without a shell on Windows
 * (`spawn EINVAL`), and a shell would hand every argument to cmd.exe's parser.
 * A `.cmd` is a fixed format, though; it ends with
 *
 *   "%_prog%"  "%dp0%\node_modules\pkg\bin\tool.js" %*
 *
 * so it is read, and what it names is started directly: a script with this
 * very Node, anything else as the program it is.
 */
export function npmShimLaunch(shim: string): CliLaunch | undefined {
	let text: string;
	try {
		text = readFileSync(shim, "utf8");
	} catch {
		return undefined;
	}
	const target = /"%dp0%([^"\r\n]+)"\s*%\*/.exec(text)?.[1];
	if (!target) return undefined;
	const wrapped = join(dirname(shim), target);
	if (!existsSync(wrapped)) return undefined;
	return /\.[cm]?js$/i.test(wrapped) ? { program: process.execPath, pre: [wrapped] } : { program: wrapped, pre: [] };
}

/** A file that was found, as something `spawn` can start. */
function launchOf(candidate: string): CliLaunch | undefined {
	if (!existsSync(candidate)) return undefined;
	if (!WIN32) return { program: candidate, pre: [] };
	const ext = extname(candidate).toLowerCase();
	if (ext === ".exe" || ext === ".com") return { program: candidate, pre: [] };
	if (ext === ".cmd" || ext === ".bat") return npmShimLaunch(candidate);
	return undefined; // the sh script and the .ps1 need a shell as well
}

/**
 * The prebuilt binary that came with this package: `@xiaolikt/ai-vault`
 * depends on `@xiaolikt/ai-vault-<os>-<arch>`, resolved by Node from here, so
 * a hoisted and a nested node_modules layout both work.
 */
function platformBinary(): CliLaunch | undefined {
	const id = `@xiaolikt/ai-vault-${process.platform}-${process.arch}/package.json`;
	try {
		const manifest = createRequire(import.meta.url).resolve(id);
		const binary = join(dirname(manifest), "bin", WIN32 ? "ai-vault.exe" : "ai-vault");
		return existsSync(binary) ? { program: binary, pre: [] } : undefined;
	} catch {
		return undefined; // no prebuilt binary for this platform
	}
}

/**
 * `AI_VAULT_BIN`, then the prebuilt binary that came with this package, then
 * the wrappers npm links in a node_modules/.bin next to or above the plugin,
 * then PATH, then the usual install spots.
 *
 * On Windows the program is always a real executable: a wrapper is unwrapped
 * to what it starts, never handed to `spawn` as it is.
 */
export function resolveLaunch(): CliLaunch | undefined {
	const explicit = process.env.AI_VAULT_BIN;
	if (explicit) return launchOf(explicit);

	const bundled = platformBinary();
	if (bundled) return bundled;

	// npm layouts hoist differently: walk up from packages/pi-ai-vault/src.
	let dir = dirname(fileURLToPath(import.meta.url));
	for (let depth = 0; depth < 5; depth++) {
		for (const name of BIN_NAMES) {
			const found = launchOf(join(dir, "node_modules", ".bin", name));
			if (found) return found;
		}
		const parent = dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}

	for (const entry of (process.env.PATH ?? "").split(delimiter)) {
		if (!entry) continue;
		for (const name of BIN_NAMES) {
			const found = launchOf(join(entry, name));
			if (found) return found;
		}
	}
	for (const base of [join(homedir(), ".local", "bin"), join(homedir(), ".cargo", "bin"), join(homedir(), ".ai-vault", "bin")]) {
		for (const name of BIN_NAMES) {
			const found = launchOf(join(base, name));
			if (found) return found;
		}
	}
	return undefined;
}

/** The program `resolveLaunch()` would start, for messages and the like. */
export function resolveBinary(): string | undefined {
	return resolveLaunch()?.program;
}

/**
 * Start one CLI call. A program Node will not start is reported through
 * `CliError` like every other failure, not thrown from inside the promise.
 */
function startCli(launch: CliLaunch, args: string[], env: NodeJS.ProcessEnv): ChildProcessWithoutNullStreams {
	try {
		// windowsHide: the CLI is a console program, and gets no window of its
		// own when the host has none. The dialogs it opens are windows it opens
		// on purpose, and show regardless.
		return spawn(launch.program, [...launch.pre, ...args], { stdio: ["pipe", "pipe", "pipe"], env, windowsHide: true });
	} catch (error) {
		throw new CliError(EXIT.error, undefined, `cannot run ${launch.program}: ${error instanceof Error ? error.message : String(error)}`, "");
	}
}

const NEEDS_UI = /^needs-ui:\s*(\w+)(?:\s+field=(\S+))?/m;

function message(stderr: string, fallback: string): string {
	const lines = stderr
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter((line) => line.length > 0 && !line.startsWith("needs-ui:") && !line.startsWith("no desktop window"));
	return lines[0]?.replace(/^ai-vault:\s*/, "") ?? fallback;
}

/**
 * The secret this process keeps for the sessions it unlocked. It never reaches
 * disk: the CLI writes it into the HMAC on each session file, and uses it to
 * check the approvals we relay. A model-driven `bash` that finds a session
 * token can therefore `list`, but can neither forge a read approval nor edit
 * the token's grants.
 */
export class HostSecret {
	#value: string | undefined;

	get present(): boolean {
		return this.#value !== undefined;
	}

	/** Use the one the CLI echoed back at unlock time (it is ours already). */
	adopt(secret: string | undefined): void {
		if (secret && secret.length >= 32) this.#value = secret;
	}

	/** 32 fresh bytes, hex — minted once per process, before the first unlock. */
	rotate(): string {
		this.#value = randomBytes(32).toString("hex");
		return this.#value;
	}

	/** The secret, minting it on first use. */
	get value(): string {
		return (this.#value ??= randomBytes(32).toString("hex"));
	}

	/** Environment for a CLI child: marks us as the host and passes the secret. */
	env(): Record<string, string> {
		return { AI_VAULT_HOST: "1", AI_VAULT_HOST_SECRET: this.value, AI_VAULT_LANG: lang() };
	}

	/** HMAC over "allow:<token>:<entry>:<y|n>", what `get --answer-stdin` expects. */
	approve(token: string, entry: string, answer: boolean): string | undefined {
		if (!this.#value) return undefined;
		return createHmac("sha256", this.#value)
			.update(`allow:${token}:${entry.toLowerCase()}:${answer ? "y" : "n"}`)
			.digest("hex");
	}
}

export class VaultCli {
	private readonly launch = resolveLaunch();
	/** The program that gets started: `AI_VAULT_BIN` when that was set. */
	readonly bin = this.launch?.program;
	/** Set by the extension at startup; the same secret for every binding. */
	host = new HostSecret();

	get available(): boolean {
		return this.bin !== undefined;
	}

	/** The store directory the CLI will use, for messages only. */
	get dir(): string {
		return process.env.AI_VAULT_DIR ?? join(homedir(), ".ai-vault");
	}

	async run(args: string[], opts: { stdin?: string; signal?: AbortSignal } = {}): Promise<CliRun> {
		const launch = this.launch;
		if (!launch) {
			throw new CliError(EXIT.error, undefined, "ai-vault CLI not found", "");
		}
		if (opts.signal?.aborted) {
			throw new CliError(EXIT.denied, undefined, "aborted", "");
		}
		const run = await new Promise<CliRun>((resolve, reject) => {
			// A program Node will not start fails here like any other CLI failure,
			// not as a bare exception from inside the promise.
			const child = startCli(launch, args, { ...process.env, ...this.host.env() });
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
				reject(new CliError(EXIT.error, undefined, `cannot run ${launch.program}: ${error.message}`, ""));
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
			const match = NEEDS_UI.exec(run.stderr);
			const step = match?.[1] as UiStep | undefined;
			throw new CliError(run.code, step, message(run.stderr, `ai-vault exited with ${run.code}`), run.stderr, match?.[2]);
		}
		return run;
	}

	/**
	 * `init` or `unlock`: returns the parsed result with the token, and keeps
	 * the host secret the CLI minted (or used ours) for later signing.
	 */
	async open<T extends { hostSecret?: string }>(subcommand: "init" | "unlock", args: string[], opts: { stdin?: string; signal?: AbortSignal } = {}): Promise<T> {
		const result = await this.json<T>([subcommand, ...args], opts);
		this.host.adopt(result.hostSecret);
		return result;
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
