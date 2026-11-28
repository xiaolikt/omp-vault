/**
 * Bitwarden half of ai-vault — deliver vault secrets to processes, not to the LLM.
 *
 * Security model
 * ==============
 * - Master password: asked in a desktop window, or the host's input dialog
 *   when no window can open (prompt.ts). Lives in memory only for the duration
 *   of one `bw unlock` call, passed via env var (never argv). The session key
 *   (BW_SESSION) stays in this process's memory: never on disk, never in the
 *   bash environment, never in logs or results.
 * - One unlock per session or subagent: omp rebinds the extension for each, and
 *   every binding owns its session key. A subagent or a second session cannot
 *   use an unlock that is not its own.
 * - bw_inject (pi only): fetches a secret and injects it as an env var into
 *   this binding's bash tool (createBashTool's spawnHook). The model never
 *   sees the value. A tool_result scrubber replaces every active secret
 *   (raw/base64/base64url/URL/hex, plus details/structuredContent) in ALL tool
 *   results before they reach the model (catches `echo $VAR`).
 * - bw_run: runs one command with the secret in its environment. This is the
 *   OMP path (OMP discards spawnHook env), and also works on pi. Output is
 *   scrubbed; nothing is persisted after the command exits.
 * - Every confirmation names the entry that was really matched, not the
 *   model's reference. Only the listing's metadata is used to build it; the
 *   entry's fields are fetched by id after the user has agreed.
 * - bw_clipboard: copies a secret to the system clipboard, auto-cleared after
 *   the configured delay and on lock/exit (only if it still holds our value).
 *   The copied value also joins the scrub list, so reading it back with
 *   pbpaste/xclip/wl-paste in a later tool result does not leak it.
 * - bw_reveal (off by default, per-call confirmation): returns a secret in
 *   plain text. The value then transits the LLM provider and the session file —
 *   that is inherent, hence every reveal needs explicit approval.
 * - Auto-lock: configurable idle timeout (config.json, default: session-lifetime,
 *   i.e. unlock once per session); always on /bw lock and when the session is
 *   left (/new, /fork, exit; a /resume keeps it when keepOnResume is set).
 *   `bw lock` is global, so it runs only when the last binding releases its
 *   key; one session's lock cannot invalidate another session's unlock.
 * - Audit log: ~/.bw/pi-extension/audit.log (timestamps, session/subagent
 *   labels, item names, env var names, allow/deny — never secret values;
 *   rotated at 1 MiB).
 * - Config: ~/.bw/pi-extension/config.json (autoLockMinutes, keepOnResume,
 *   clipboardClearSeconds, allowReveal, maxInjectedEnv).
 *
 * Requires: bitwarden CLI (`bw`), logged in (`bw login`).
 * Browser filling works via agent-browser: agent-browser fill @ref "$VAR"
 *   (the value never enters the conversation).
 */

import { spawn, spawnSync } from "node:child_process";
import { constants as fsConstants, accessSync, readFileSync, promises as fs } from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import type { ExtensionAPI, ExtensionContext, ToolDefinition, ToolResultEventResult } from "@earendil-works/pi-coding-agent";
import { createBashTool } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { bitwardenItems, filterItems } from "./import-map.js";
import type { Draft } from "./types.js";
import { onSessionLeave, sessionLabel, withTier } from "./host.js";
import { confirmWindow, hasDisplay, promptSecret } from "./prompt.js";
import { getSettingsSafe, settingsCli } from "./settings.js";
import { tr } from "./i18n.js";
import { scrubDeep, scrubText } from "./scrub.js";

// ---------------------------------------------------------------------------
// Configuration (defaults overridable via ~/.bw/pi-extension/config.json)
// ---------------------------------------------------------------------------
const STATE_DIR = process.env.OMP_VAULT_BW_DIR ?? path.join(homedir(), ".bw", "pi-extension");
const CONFIG_PATH = path.join(STATE_DIR, "config.json");

const DEFAULTS = {
	/** Idle minutes before the vault session and injected secrets drop.
	 *  0 = unlock lasts for the whole pi session (lock only on /bw lock or exit). */
	autoLockMinutes: 0,
	/** Keep the unlock state when switching sessions with /resume in the same pi process. */
	keepOnResume: true,
	/** Clipboard auto-clear delay. */
	clipboardClearSeconds: 30,
	/** Allow bw_reveal (plain-text secret to the model, per-call confirmation). */
	allowReveal: false,
	/** Upper bound on concurrently injected env vars. */
	maxInjectedEnv: 12,
};

function loadConfig(): typeof DEFAULTS {
	type Config = typeof DEFAULTS;
	const fail = (key: keyof Config, expected: string, fallback: unknown) =>
		process.stderr.write(
			`pi-bitwarden: invalid ${key} in ${CONFIG_PATH} (expected ${expected}); using ${String(fallback)}\n`,
		);
	const int = (
		raw: Record<string, unknown>,
		key: keyof Config,
		min: number,
		max: number,
		invalidFallback: number = DEFAULTS[key] as number,
	): number => {
		const value = raw[key];
		if (value === undefined) return DEFAULTS[key] as number;
		if (typeof value === "number" && Number.isInteger(value) && value >= min && value <= max) return value;
		fail(key, `integer ${min}..${max}`, invalidFallback);
		return invalidFallback;
	};
	const bool = (raw: Record<string, unknown>, key: keyof Config, invalidValue: boolean): boolean => {
		const fallback = DEFAULTS[key] as boolean;
		const value = raw[key];
		if (value === undefined) return fallback;
		if (typeof value === "boolean") return value;
		// Explicit but wrong type: fail closed for security switches.
		fail(key, "true or false", invalidValue);
		return invalidValue;
	};

	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(CONFIG_PATH, "utf-8"));
	} catch {
		return { ...DEFAULTS };
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { ...DEFAULTS };
	const raw = parsed as Record<string, unknown>;
	return {
		autoLockMinutes: int(raw, "autoLockMinutes", 0, 10_080, 15),
		keepOnResume: bool(raw, "keepOnResume", false),
		clipboardClearSeconds: int(raw, "clipboardClearSeconds", 0, 3600),
		allowReveal: bool(raw, "allowReveal", false),
		maxInjectedEnv: int(raw, "maxInjectedEnv", 1, 64),
	};
}

const CONFIG = loadConfig();
/** 0 = no idle lock (session-lifetime unlock). */
const autoLockMs = CONFIG.autoLockMinutes > 0 ? CONFIG.autoLockMinutes * 60_000 : 0;
const CLIPBOARD_CLEAR_TEXT =
	CONFIG.clipboardClearSeconds > 0
		? `auto-cleared after ${CONFIG.clipboardClearSeconds}s`
		: "auto-clear disabled (lock/exit still clear)";
const BW_TIMEOUT_MS = 120_000;

/** Env names the model may never claim (shell/loader injection vectors + Bitwarden internals). */
const ENV_BLOCKLIST =
	/^(PATH|HOME|SHELL|USER|LOGNAME|PWD|OLDPWD|IFS|PS1|PS2|PROMPT_COMMAND|BASH_ENV|BASH_FUNC_.+|BASH_LOADABLES_PATH|ENV|SHELLOPTS|BASHOPTS|LD_.+|DYLD_.+|PYTHONPATH|PYTHONSTARTUP|PERL5OPT|RUBYOPT|NODE_OPTIONS|NODE_PATH|GIT_CONFIG|GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_SSH|GIT_SSH_COMMAND|GIT_ASKPASS|GIT_EDITOR|GIT_PAGER|GIT_EXTERNAL_DIFF|SSH_AUTH_SOCK|SSH_ASKPASS|SUDO_ASKPASS|LESSOPEN|LESSCLOSE|PAGER|MANPAGER|EDITOR|VISUAL|BROWSER|SSL_CERT_FILE|REQUESTS_CA_BUNDLE|CURL_HOME|CURL_CA_BUNDLE|http_proxy|https_proxy|all_proxy|no_proxy|PI_.+|BW_.+)$/i;

const FIELD_RE = /^(password|totp|code|notes|field:[\w.\- ]{1,64})$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const BW_LOGIN_HINT =
	"Bitwarden CLI is not logged in. Run `bw login` in a terminal first " +
	"(and `bw config --server <url>` if self-hosted), then retry. " +
	"You can check with /bw status.";

// ---------------------------------------------------------------------------
// State (memory only)
// ---------------------------------------------------------------------------
type BwItem = {
	id?: string;
	name?: string;
	type?: number;
	notes?: string;
	login?: { username?: string; password?: string; totp?: string; uris?: { uri?: string }[] };
	card?: { cardholderName?: string; brand?: string; number?: string; code?: string };
	identity?: { title?: string; firstName?: string; lastName?: string; email?: string; phone?: string };
	sshKey?: { publicKey?: string; keyFingerprint?: string };
	fields?: { name?: string; value?: string; type?: number }[];
};
/** Only metadata is cached; secrets stay in the vault process until needed. */
type LiteItem = { id: string; name: string; username: string; uri: string; type: string };
type InjectedSecret = { value: string; item: string; field: string; at: number };

/**
 * One session or subagent. omp rebinds the extension factory for each, so the
 * session key, the injected variables, and the item cache belong to the binding
 * that unlocked them and are never shared with another.
 */
export interface BwState {
	key?: string;
	verifiedAt: number;
	lastActivity: number;
	inFlight?: Promise<string>;
	/** Bumped by lock(): an unlock that started earlier is discarded. */
	epoch: number;
	/** Metadata only; an entry's fields are fetched by id, for an approved request. */
	cache?: { at: number; items: LiteItem[] };
	/** Audit label of the session or subagent this binding serves (set when it unlocks). */
	sessionLabel?: string;
	/** pi only: ENV -> injected secret, read by this binding's bash tool. */
	injected: Map<string, InjectedSecret>;
	lockTimer?: NodeJS.Timeout;
}

export function newBwState(): BwState {
	return { verifiedAt: 0, lastActivity: Date.now(), epoch: 0, injected: new Map() };
}

/**
 * Values the output scrubber must keep hiding, even after /bw clear or lock:
 * a command may already have copied $VAR to a file, and a later `cat` would
 * otherwise leak it. Keyed by ENV + value so replacements keep both.
 *
 * The list is bounded so a session that asks for many different values (every
 * TOTP code is a new one) cannot grow it without end. It is kept large enough
 * that an ordinary session never evicts a value that may still be on disk;
 * past the bound, the least recently used value loses its protection.
 */
const scrubValues = new Map<string, { env: string; value: string }>();
const MAX_SCRUB_VALUES = 512;

/**
 * Bindings in this process that still hold a Bitwarden session key.
 *
 * `bw lock` destroys every active session key, not just ours, so it must run
 * only when the last binding lets go. A /new, /fork, idle lock or subagent
 * shutdown in one session must not invalidate another session's unlock.
 */
let liveSessionKeys = 0;

function acquireSessionKey(): void {
	liveSessionKeys++;
}

/** Returns true when this was the last key, i.e. a global `bw lock` is now safe. */
function releaseSessionKey(): boolean {
	if (liveSessionKeys > 0) liveSessionKeys--;
	return liveSessionKeys === 0;
}

function rememberScrubValue(env: string, value: string): void {
	const key = `${env}\u0000${value}`;
	// Re-insert so a value that is still in use moves to the back: the oldest
	// entry to drop is the one that has gone unused the longest.
	scrubValues.delete(key);
	scrubValues.set(key, { env, value });
	while (scrubValues.size > MAX_SCRUB_VALUES) {
		const oldest = scrubValues.keys().next();
		if (oldest.done) break;
		scrubValues.delete(oldest.value);
	}
}

process.once("exit", () => {
	clearClipboardSync();
});

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
function safeStatus(ctx: ExtensionContext | undefined, text: string | undefined): void {
	try {
		ctx?.ui.setStatus("bitwarden", text);
	} catch {
		/* runner may be inactive */
	}
}

function tail(s: string, n = 200): string {
	const t = s.trim();
	if (!t) return "";
	return t.length > n ? t.slice(-n) : t;
}

/** Most output kept per stream; a runaway command must not exhaust memory. */
const OUTPUT_CAP = 8 * 1024 * 1024;

interface ExecOptions {
	env?: Record<string, string>;
	timeout?: number;
	input?: string;
	signal?: AbortSignal;
	cwd?: string;
	/** Run in its own process group, so a timeout also kills what it spawned. */
	group?: boolean;
}

interface ExecResult {
	stdout: string;
	stderr: string;
	code: number;
	/** True when output past OUTPUT_CAP was dropped. */
	truncated: boolean;
}

/**
 * Environment for a child process: the host's environment without any BW_*
 * variables. The session key is passed explicitly per call (BW_SESSION for
 * `bw`, BW_MASTER_PASSWORD for one unlock), so a key exported in the user's
 * shell can never leak into bash or a bw_run command.
 */
function childEnv(extra?: Record<string, string>): NodeJS.ProcessEnv {
	const env: NodeJS.ProcessEnv = {};
	for (const [key, value] of Object.entries(process.env)) {
		if (!key.startsWith("BW_")) env[key] = value;
	}
	if (extra) Object.assign(env, extra);
	return env;
}

function exec(cmd: string, args: string[], opts: ExecOptions = {}): Promise<ExecResult> {
	if (opts.signal?.aborted) return Promise.reject(new Error(`${cmd} cancelled`));
	const { promise, resolve, reject } = Promise.withResolvers<ExecResult>();
	const child = spawn(cmd, args, {
		env: childEnv(opts.env),
		cwd: opts.cwd,
		stdio: ["pipe", "pipe", "pipe"],
		detached: opts.group === true,
	});
	let out = "";
	let err = "";
	let truncated = false;
	let settled = false;
	const kill = () => {
		if (opts.group && child.pid) {
			try {
				process.kill(-child.pid, "SIGKILL");
			} catch {
				/* the group is already gone */
			}
		}
		child.kill("SIGKILL");
	};
	const cleanup = () => {
		clearTimeout(timer);
		opts.signal?.removeEventListener("abort", onAbort);
	};
	const finish = (fn: () => void) => {
		if (settled) return;
		settled = true;
		cleanup();
		fn();
	};
	const onAbort = () =>
		finish(() => {
			kill();
			reject(new Error(`${cmd} cancelled`));
		});
	const timer = setTimeout(
		() =>
			finish(() => {
				kill();
				reject(new Error(`${cmd} timed out after ${opts.timeout ?? BW_TIMEOUT_MS}ms`));
			}),
		opts.timeout ?? BW_TIMEOUT_MS,
	);
	opts.signal?.addEventListener("abort", onAbort, { once: true });
	if (opts.signal?.aborted) onAbort();
	child.stdout?.on("data", (chunk: Buffer | string) => {
		if (out.length < OUTPUT_CAP) out += chunk;
		else truncated = true;
	});
	child.stderr?.on("data", (chunk: Buffer | string) => {
		if (err.length < OUTPUT_CAP) err += chunk;
		else truncated = true;
	});
	child.on("error", (e) => finish(() => reject(e)));
	child.on("close", (code) => finish(() => resolve({ stdout: out, stderr: err, code: code ?? -1, truncated })));
	child.stdin?.on("error", () => {}); // EPIPE when the child dies before reading input
	if (opts.input !== undefined) child.stdin?.write(opts.input);
	child.stdin?.end();
	return promise;
}

const AUDIT_MAX_BYTES = 1024 * 1024;
let auditModeFixed = false;

/** One audit line per event. `session` is the binding's label, so a subagent's `bw_run` can be told from its parent's. */
export async function auditEvent(event: string, detail: string, session?: string): Promise<void> {
	try {
		await fs.mkdir(STATE_DIR, { recursive: true, mode: 0o700 });
		const log = path.join(STATE_DIR, "audit.log");
		if (!auditModeFixed) {
			auditModeFixed = true;
			await fs.chmod(STATE_DIR, 0o700).catch(() => {});
			await fs.chmod(log, 0o600).catch(() => {});
		}
		try {
			const stat = await fs.stat(log);
			if (stat.size > AUDIT_MAX_BYTES) await fs.rename(log, `${log}.1`);
		} catch {
			/* first entry */
		}
		// Item names are model/vault supplied: keep one entry per line.
		const safeDetail = detail.replace(/[\r\n]+/g, " ").slice(0, 500);
		const safeSession = session?.replace(/[^\w./-]/g, "").slice(0, 48);
		const line = `${new Date().toISOString()} ${event}${safeSession ? ` session=${safeSession}` : ""} ${safeDetail}\n`;
		await fs.appendFile(log, line, { mode: 0o600 });
	} catch {
		/* best-effort */
	}
}

// ---------------------------------------------------------------------------
// Bitwarden CLI plumbing (secrets only ever travel via env vars / pipes)
// ---------------------------------------------------------------------------
let bwBin: string | undefined;

async function resolveBw(): Promise<string> {
	if (bwBin) return bwBin;
	try {
		await exec("bw", ["--version"], { timeout: 20_000 });
		bwBin = "bw";
		return bwBin;
	} catch {
		/* fall through to nvm scan */
	}
	try {
		const nvmDir = path.join(homedir(), ".nvm", "versions", "node");
		const versions = (await fs.readdir(nvmDir).catch(() => [] as string[]))
			.filter((v) => /^\d+\.\d+\.\d+$/.test(v))
			.sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
			.reverse();
		for (const v of versions) {
			const p = path.join(nvmDir, v, "bin", "bw");
			if (await fs.access(p).then(() => true, () => false)) {
				bwBin = p;
				return bwBin;
			}
		}
	} catch {
		/* ignore */
	}
	throw new Error("Bitwarden CLI (`bw`) not found in PATH or ~/.nvm. Install it, `bw login`, and retry.");
}

async function runBw(
	args: string[],
	opts: { session?: string; extraEnv?: Record<string, string>; signal?: AbortSignal } = {},
): Promise<string> {
	const bin = await resolveBw();
	const env: Record<string, string> = { ...opts.extraEnv };
	if (opts.session) env.BW_SESSION = opts.session;
	const r = await exec(bin, [...args, "--nointeraction"], { env, signal: opts.signal });
	if (r.code !== 0) {
		const hint = tail(r.stderr) || `exit ${r.code}`;
		// Never include stdout in errors — some commands print secrets on success-ish paths.
		throw new Error(`bw ${args.slice(0, 2).join(" ")} failed: ${hint}`);
	}
	return r.stdout;
}

async function runBwJson(args: string[], session?: string, signal?: AbortSignal): Promise<any> {
	return JSON.parse(await runBw(args, { session, signal }));
}

let statusCache: { at: number; json: any } | undefined;

async function bwStatus(session?: string, signal?: AbortSignal): Promise<any> {
	// With a session, this verifies that key. Without one it asks whether the CLI
	// itself is locked; a stale BW_SESSION in the host env would make it exit
	// non-zero, so the probe never inherits the env (see childEnv).
	if (session) {
		const r = await runBw(["status"], { session, signal });
		return JSON.parse(r);
	}
	if (statusCache && Date.now() - statusCache.at < 3000) return statusCache.json;
	const json = await runBwJson(["status"], undefined, signal);
	statusCache = { at: Date.now(), json };
	return json;
}

/** The Bitwarden master password, in a window or the host's input dialog. */
async function askMasterPassword(ctx: ExtensionContext | undefined, signal?: AbortSignal): Promise<string> {
	const pw = await promptSecret(ctx, tr("Bitwarden · master password", "Bitwarden · 主密码"), tr("unlock the Bitwarden vault", "解锁 Bitwarden 保险库"), signal);
	if (pw) return pw;
	if (signal?.aborted) throw new Error("Cancelled.");
	if (!hasDisplay() && !ctx?.hasUI) {
		throw new Error(
			"No way to prompt for the master password (no desktop, no interactive UI). Run /bw unlock in an interactive session.",
		);
	}
	throw new Error("Master password prompt cancelled.");
}

async function confirmAction(
	ctx: ExtensionContext | undefined,
	title: string,
	message: string,
	signal?: AbortSignal,
): Promise<boolean> {
	const ok = await confirmWindow(ctx, title, message, signal);
	if (signal?.aborted) throw new Error("Cancelled.");
	return ok;
}

function touchActivity(st: BwState): void {
	st.lastActivity = Date.now();
}

function startAutoLock(st: BwState, ctx: ExtensionContext | undefined): void {
	st.lastActivity = Date.now();
	if (st.lockTimer || !autoLockMs) return;
	const tick = () => {
		if (st.key && autoLockMs && Date.now() - st.lastActivity > autoLockMs) {
			void lock(st, "auto-idle");
		}
	};
	// A timer made through omp's context is cleared for us on session_shutdown.
	const host = ctx as { setInterval?: (callback: () => void, ms?: number) => NodeJS.Timeout } | undefined;
	st.lockTimer = host?.setInterval ? host.setInterval(tick, 30_000) : setInterval(tick, 30_000);
	st.lockTimer.unref?.();
}

/** Drop this binding's session key and injected variables, and the clipboard. */
async function lock(st: BwState, reason: string): Promise<void> {
	const hadSession = !!st.key;
	// A key kept for `bitwarden.unlock = never | time` must go with an explicit
	// lock, or the next call would silently unlock again.
	void settingsCli().run(["bw-session", "clear"]).catch(() => undefined);
	st.epoch++;
	st.key = undefined;
	st.verifiedAt = 0;
	st.cache = undefined;
	st.injected.clear();
	// An unlock that was waiting for its password window must not be reused;
	// its epoch check already discards the result, and the next call asks again.
	st.inFlight = undefined;
	// From here on the clipboard is not ours to keep: a copy still in flight
	// must clear again when it lands (see copyToClipboard).
	clipboardDrops++;
	await clearClipboardIfOwner();
	if (st.lockTimer) {
		clearInterval(st.lockTimer);
		st.lockTimer = undefined;
	}
	if (hadSession) {
		await auditEvent("lock", `reason=${reason}`, st.sessionLabel);
		if (!releaseSessionKey()) return; // another binding still uses its own key
		try {
			const bin = await resolveBw();
			await exec(bin, ["lock", "--nointeraction"], { timeout: 15_000 });
		} catch {
			/* best-effort; dropping our session key is what matters */
		}
	}
}

async function ensureUnlocked(st: BwState, ctx: ExtensionContext | undefined, signal?: AbortSignal): Promise<string> {
	touchActivity(st);
	// Every audit line of this binding names the session or subagent that asked.
	st.sessionLabel = sessionLabel(ctx);
	if (signal?.aborted) throw new Error("Cancelled.");
	if (st.key && Date.now() - st.verifiedAt < 30_000) return st.key;
	if (st.key) {
		try {
			const status = await bwStatus(st.key, signal);
			if (status?.status === "unlocked") {
				st.verifiedAt = Date.now();
				return st.key;
			}
		} catch {
			if (signal?.aborted) throw new Error("Cancelled.");
			/* stale session key */
		}
		st.key = undefined;
		st.verifiedAt = 0;
		releaseSessionKey();
	}
	if (st.inFlight) return st.inFlight;

	const epoch = st.epoch;
	const pending = (async () => {
		const policy = (await getSettingsSafe(signal)).bitwarden;
		// `never` / `time`: the CLI keeps the session key (0600, in the store
		// directory), so Bitwarden costs no window at all.
		if (policy.unlock !== "session") {
			try {
				const saved = await settingsCli().json<{ key: string }>(["bw-session", "get"], { signal });
				if (saved?.key) {
					const verify = await bwStatus(saved.key, signal);
					if (verify?.status === "unlocked") {
						st.key = saved.key;
						st.verifiedAt = Date.now();
						acquireSessionKey();
						startAutoLock(st, ctx);
						return saved.key;
					}
				}
			} catch {
				/* absent or expired: fall through to the password */
			}
		}

		const status = await bwStatus(undefined, signal); // no session env
		if (status?.status === "unauthenticated") throw new Error(BW_LOGIN_HINT);

		const pw = await askMasterPassword(ctx, signal);
		const bin = await resolveBw();
		const r = await exec(bin, ["unlock", "--passwordenv", "BW_MASTER_PASSWORD", "--raw"], {
			env: { BW_MASTER_PASSWORD: pw },
			timeout: 60_000,
			signal,
		});
		if (r.code !== 0) {
			await auditEvent("unlock", "deny=bad-password", st.sessionLabel);
			throw new Error(`Unlock failed (wrong master password or CLI error). ${tail(r.stderr, 120)}`);
		}
		const key = r.stdout.replace(/[\r\n]+$/, "");
		if (!key) throw new Error("Unlock failed: empty session key.");
		const verify = await bwStatus(key, signal);
		if (verify?.status !== "unlocked") throw new Error("Unlock failed: session key not accepted.");
		// /bw lock or a session switch ran while the password window was open.
		if (epoch !== st.epoch || signal?.aborted) throw new Error("Cancelled.");
		st.key = key;
		st.verifiedAt = Date.now();
		acquireSessionKey();
		startAutoLock(st, ctx);
		if (policy.unlock !== "session") {
			// Keep the key where the CLI can hand it back; the file's expiry comes
			// from the bitwarden.hours policy.
			await settingsCli().run(["bw-session", "put"], { stdin: key }).catch(() => undefined);
		}
		await auditEvent("unlock", "ok", st.sessionLabel);
		// Refresh in the background: a full sync can take seconds on large vaults.
		const lastSync = Date.parse(status?.lastSync ?? "");
		if (!Number.isFinite(lastSync) || Date.now() - lastSync > 15 * 60_000) {
			void runBw(["sync"], { session: key }).catch(() => {
				/* offline ok — cached vault */
			});
		}
		return key;
	})();
	st.inFlight = pending;
	// Only clear the slot if it still belongs to this attempt: a lock followed
	// by a new unlock must not have its promise erased by the old one.
	void pending.then(
		() => {
			if (st.inFlight === pending) st.inFlight = undefined;
		},
		() => {
			if (st.inFlight === pending) st.inFlight = undefined;
		},
	);
	return pending;
}

const BW_TYPE_NAMES: Record<number, string> = { 1: "login", 2: "note", 3: "card", 4: "identity", 5: "sshKey", 6: "bankAccount", 7: "driversLicense", 8: "passport" };

function toLite(raw: BwItem): LiteItem {
	const type = BW_TYPE_NAMES[raw.type ?? 1] ?? `type-${raw.type}`;
	// The identifying, non-secret line of each type: username for a login,
	// cardholder for a card, a person's name for an identity, and so on.
	const who =
		raw.login?.username ??
		raw.card?.cardholderName ??
		(raw.identity ? [raw.identity.title, raw.identity.firstName, raw.identity.lastName].filter(Boolean).join(" ") : "") ??
		"";
	return {
		id: raw.id ?? "",
		name: raw.name ?? "",
		username: who,
		uri: raw.login?.uris?.[0]?.uri ?? "",
		type,
	};
}

async function listItems(
	st: BwState,
	session: string,
	signal?: AbortSignal,
	opts: { fresh?: boolean } = {},
): Promise<LiteItem[]> {
	if (!opts.fresh && st.cache && Date.now() - st.cache.at < 5 * 60_000) return st.cache.items;
	const raw = (await runBwJson(["list", "items"], session, signal)) as BwItem[];
	const items = raw.map(toLite);
	st.cache = { at: Date.now(), items };
	return items;
}

/** The whole entry, secret fields included. Called only for an entry the user already approved, by id. */
async function getItemById(session: string, id: string, signal?: AbortSignal): Promise<BwItem> {
	try {
		return (await runBwJson(["get", "item", id], session, signal)) as BwItem;
	} catch (e) {
		// Only a missing item is reported as such; a CLI or network error keeps its own message.
		if (e instanceof Error && /not found/i.test(e.message)) throw new Error(`No Bitwarden item with id ${id}.`);
		throw e;
	}
}

function itemScore(item: LiteItem, query: string): number {
	const haystack = `${item.name} ${item.username} ${item.uri}`.toLowerCase();
	let score = 0;
	for (const token of query.split(/\s+/).filter(Boolean)) {
		if (haystack.includes(token)) score += 10;
		else if (token.length > 3 && haystack.includes(token.slice(0, Math.max(3, token.length - 2)))) score += 3;
	}
	return score;
}

/**
 * Resolve the model's reference to the entry it really names, as metadata.
 * Asking the user only needs the name and username; the entry's fields are
 * fetched by id in secretOf(), after the user has agreed.
 */
async function resolveItem(st: BwState, session: string, ref: string, signal?: AbortSignal): Promise<LiteItem> {
	if (UUID_RE.test(ref)) {
		let items = await listItems(st, session, signal);
		// An item created after the cache was filled is missing from it: look once more.
		if (!items.some((i) => i.id === ref)) items = await listItems(st, session, signal, { fresh: true });
		const byId = items.find((i) => i.id === ref);
		if (byId) return byId;
		throw new Error(`No Bitwarden item with id ${ref}. Use bw_list to browse item ids.`);
	}

	const items = await listItems(st, session, signal);
	const query = ref.trim().toLowerCase();
	if (!query) throw new Error("Item reference is empty; pass an item name or id.");
	const exact = items.filter((i) => i.name.toLowerCase() === query);
	const partial = items.filter((i) =>
		`${i.name}\n${i.username}\n${i.uri}`.toLowerCase().includes(query),
	);
	const hits = exact.length > 0 ? exact : partial;
	const only = hits[0];
	if (hits.length === 1 && only) return only;

	const list = (items: LiteItem[]) =>
		items
			.slice(0, 10)
			.map((i) => `- ${i.name || "?"} | user: ${i.username || "-"} | ${i.uri || "-"} | id: ${i.id}`)
			.join("\n");
	if (hits.length > 1) throw new Error(`Multiple Bitwarden items match "${ref}". Specify by id:\n${list(hits)}`);

	const closest = items
		.map((item) => ({ item, score: itemScore(item, query) }))
		.filter((entry) => entry.score > 0)
		.sort((a, b) => b.score - a.score)
		.slice(0, 10)
		.map((entry) => entry.item);
	throw new Error(
		closest.length > 0
			? `No Bitwarden item matches "${ref}". Closest items:\n${list(closest)}`
			: `No Bitwarden item matches "${ref}". Use bw_list to browse item names.`,
	);
}

function extractSecret(item: BwItem, field: string): string {
	let v: string | undefined;
	if (field === "password") v = item.login?.password;
	else if (field === "totp") v = item.login?.totp; // TOTP seed, not the rotating code
	else if (field === "notes") v = item.notes;
	else if (field.startsWith("field:")) {
		const name = field.slice(6);
		v = item.fields?.find((f) => f.name === name)?.value;
	}
	if (typeof v !== "string" || v.length === 0) {
		throw new Error(`Field "${field}" is empty or missing on item "${item.name ?? "?"}".`);
	}
	return v;
}

/**
 * Unlock, resolve the model's reference to the entry it really names, and ask
 * the user about that entry. The window shows the resolved name and username,
 * so a fuzzy or mistyped reference cannot be approved as some other entry.
 * Only metadata is resolved here; the entry's fields are fetched after the
 * user agrees, by the id that was shown.
 */
async function approveItem(
	st: BwState,
	ctx: ExtensionContext | undefined,
	event: string,
	title: string,
	itemRef: string,
	field: string,
	detail: string,
	signal?: AbortSignal,
): Promise<{ session: string; item: LiteItem } | undefined> {
	const session = await ensureUnlocked(st, ctx, signal);
	const item = await resolveItem(st, session, itemRef, signal);
	const name = item.name || "?";
	const user = item.username ? ` (user: ${item.username})` : "";
	const ok = await confirmAction(ctx, title, `Item:   ${name}${user}\nField:  ${field}\n${detail}\n\nAllow?`, signal);
	if (!ok) {
		await auditEvent(event, `deny item="${name}" field=${field}`, st.sessionLabel);
		return undefined;
	}
	return { session, item };
}

/** Read one field of an entry the user has just approved: the entry is fetched now, by the id that was shown. */
async function secretOf(
	session: string,
	item: LiteItem,
	field: string,
	signal?: AbortSignal,
): Promise<{ value: string; itemId: string; itemName: string }> {
	const itemName = item.name || "?";
	if (!item.id) {
		throw new Error(`Bitwarden item "${itemName}" has no id, so ${field === "code" ? "no TOTP code can be generated" : "its fields cannot be read"}.`);
	}
	if (field === "code") {
		const code = (await runBw(["get", "totp", item.id], { session, signal })).trim();
		if (!code) throw new Error(`No TOTP code available for item "${itemName}".`);
		return { value: code, itemId: item.id, itemName };
	}
	const full = await getItemById(session, item.id, signal);
	return { value: extractSecret(full, field), itemId: item.id, itemName };
}

export type BitwardenMeta = { id: string; name: string; username: string; uri: string };

/** Metadata only. Unlocks Bitwarden (master-password window) on first use. */
export async function queryBitwarden(
	st: BwState,
	ctx: ExtensionContext | undefined,
	search: string | undefined,
	signal?: AbortSignal,
): Promise<BitwardenMeta[]> {
	const session = await ensureUnlocked(st, ctx, signal);
	let items = await listItems(st, session, signal);
	const query = (search ?? "").trim().toLowerCase();
	if (query) {
		items = items.filter((item) => `${item.name}\n${item.username}\n${item.uri}`.toLowerCase().includes(query));
	}
	return items.map((item) => ({ id: item.id, name: item.name, username: item.username, uri: item.uri }));
}

/**
 * Every item that matches `search`, ready to store in the local vault: all
 * types, field for field. Call only after the user has agreed to the import —
 * this reads secrets.
 */
export async function pullBitwardenItems(
	st: BwState,
	ctx: ExtensionContext | undefined,
	search: string | undefined,
	signal?: AbortSignal,
): Promise<Draft[]> {
	const session = await ensureUnlocked(st, ctx, signal);
	const raw: unknown = await runBwJson(["list", "items"], session, signal);
	return filterItems(bitwardenItems(raw), search);
}

export type BitwardenHit = { draft: Draft; label: string };

/**
 * Look one item up, of any type, and return it as a draft with its secrets,
 * with no window of its own: the caller shows the user what was found and asks
 * whether to read it. `undefined` means "no such item"; an ambiguous reference
 * throws with the candidates so the model can pick one.
 */
export async function lookupBitwardenItem(
	st: BwState,
	ctx: ExtensionContext | undefined,
	ref: string,
	signal?: AbortSignal,
): Promise<BitwardenHit | undefined> {
	const session = await ensureUnlocked(st, ctx, signal);
	let item: LiteItem;
	try {
		item = await resolveItem(st, session, ref, signal);
	} catch (e) {
		if (e instanceof Error && /^No Bitwarden item matches/.test(e.message)) return undefined;
		throw e;
	}
	if (!item.id) throw new Error(`Bitwarden item "${item.name}" has no id, so it cannot be read.`);
	const full = (await runBwJson(["get", "item", item.id], session, signal)) as unknown;
	const [draft] = bitwardenItems([full]);
	if (!draft) return undefined;
	const who = item.username ? `  ${item.username}` : "";
	return { draft, label: `${draft.name}${who}  (${item.type})` };
}

function normalizeEnvName(raw: string): string {
	const name = raw.trim().toUpperCase();
	if (!/^[A-Z_][A-Z0-9_]*$/.test(name)) {
		throw new Error(`Invalid env var name "${raw}". Use letters, digits, underscores; must not start with a digit.`);
	}
	if (ENV_BLOCKLIST.test(name)) {
		throw new Error(`Env var name "${name}" is blocked (shell/loader/Bitwarden internals). Pick a specific name like MYAPP_TOKEN.`);
	}
	return name;
}

function injectedListText(st: BwState): string {
	if (st.injected.size === 0) return "(none)";
	return [...st.injected.entries()].map(([env, r]) => `$${env} ← "${r.item}" (${r.field})`).join(", ");
}

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------
type ClipboardBackend = {
	copy: [string, string[]];
	clear: [string, string[]];
	read: [string, string[]];
};

/** Whether an executable is on PATH, so a Wayland session can fall back to X11. */
function commandExists(command: string): boolean {
	for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
		if (!dir) continue;
		try {
			accessSync(path.join(dir, command), fsConstants.X_OK);
			return true;
		} catch {
			/* not in this directory */
		}
	}
	return false;
}

function clipboardBackend(): ClipboardBackend | undefined {
	if (process.platform === "darwin") {
		return { copy: ["pbcopy", []], clear: ["pbcopy", []], read: ["pbpaste", []] };
	}
	if (process.env.WAYLAND_DISPLAY && commandExists("wl-copy") && commandExists("wl-paste")) {
		return {
			copy: ["wl-copy", []],
			clear: ["wl-copy", ["-c"]],
			read: ["wl-paste", ["--no-newline"]],
		};
	}
	if (process.env.DISPLAY && commandExists("xclip")) {
		return {
			copy: ["xclip", ["-selection", "clipboard"]],
			clear: ["xclip", ["-selection", "clipboard", "/dev/null"]],
			read: ["xclip", ["-selection", "clipboard", "-o"]],
		};
	}
	return undefined;
}

let clipboardValue: string | undefined;
/** Set while a copy is in flight, so exit cleanup can still clear it. */
let clipboardPending: string | undefined;
let clipboardTimer: NodeJS.Timeout | undefined;
/**
 * Bumped whenever the clipboard is dropped for good (a lock or an exit), not by
 * the auto-clear timer. A copy that was in flight across a drop puts its value
 * back afterwards, so it compares this and clears again instead of only
 * arming its own timer.
 */
let clipboardDrops = 0;

function clipboardMatches(current: string, value: string): boolean {
	return current === value || current.replace(/[\r\n]+$/, "") === value.replace(/[\r\n]+$/, "");
}

async function copyToClipboard(value: string): Promise<void> {
	const backend = clipboardBackend();
	if (!backend) throw new Error("No clipboard available (need Wayland, X11, or macOS).");
	const drops = clipboardDrops;
	const [cmd, args] = backend.copy;
	const { promise, resolve, reject } = Promise.withResolvers<void>();
	// wl-copy/xclip stay alive to own the selection; a quick clean exit also means success.
	const child = spawn(cmd, args, { stdio: ["pipe", "ignore", "pipe"], detached: true, env: childEnv() });
	let settled = false;
	let stderr = "";
	const finish = (err?: Error) => {
		if (settled) return;
		settled = true;
		if (err) reject(err);
		else {
			child.unref();
			resolve();
		}
	};
	child.stderr?.on("data", (d) => (stderr += d));
	child.on("error", finish);
	child.on("exit", (code) => {
		if (code === 0) finish();
		else finish(new Error(`${cmd} exited with ${code}${stderr ? `: ${tail(stderr, 120)}` : ""}`));
	});
	child.stdin?.on("error", (e) => finish(e instanceof Error ? e : new Error(String(e))));
	child.stdin?.write(value, (err) => {
		if (err) {
			finish(err);
			return;
		}
		child.stdin?.end();
		setTimeout(() => finish(), 500);
	});
	clipboardPending = value;
	try {
		await promise;
	} catch (e) {
		if (clipboardPending === value) clipboardPending = undefined;
		throw e;
	}
	if (clipboardPending === value) clipboardPending = undefined;
	clearTimeout(clipboardTimer);
	clipboardValue = value;
	clipboardTimer = undefined;
	// A lock or an exit ran while this copy was in flight: the value is back in
	// the clipboard, so it goes again, now and once more in case the copy
	// command has not taken the selection yet.
	if (drops !== clipboardDrops) {
		await clearClipboardIfOwner();
		clipboardValue = value;
		clipboardTimer = setTimeout(() => void clearClipboardIfOwner(), 1000);
		clipboardTimer.unref?.();
		throw new Error("Bitwarden was locked while copying; the clipboard is being cleared.");
	}
	if (CONFIG.clipboardClearSeconds > 0) {
		clipboardTimer = setTimeout(() => void clearClipboardIfOwner(), CONFIG.clipboardClearSeconds * 1000);
		clipboardTimer.unref?.();
	}
}

/** Clear only if the clipboard still holds our value (never wipe a newer user copy). */
async function clearClipboardIfOwner(): Promise<boolean> {
	const value = clipboardValue ?? clipboardPending;
	const backend = clipboardBackend();
	clipboardValue = undefined;
	clipboardPending = undefined;
	if (clipboardTimer) {
		clearTimeout(clipboardTimer);
		clipboardTimer = undefined;
	}
	if (!value || !backend) return false;
	try {
		const r = await exec(backend.read[0], backend.read[1], { timeout: 3000 });
		if (r.code === 0 && r.stdout.length > 0 && !clipboardMatches(r.stdout, value)) return false;
	} catch {
		/* unreadable clipboard: clear anyway (fail-safe) */
	}
	try {
		await exec(backend.clear[0], backend.clear[1], { timeout: 5000, input: "" });
	} catch {
		/* best-effort */
	}
	return true;
}

/** Exit-path cleanup: timers never run after the process exits. */
function clearClipboardSync(): void {
	clipboardDrops++;
	const value = clipboardValue ?? clipboardPending;
	const backend = clipboardBackend();
	clipboardValue = undefined;
	clipboardPending = undefined;
	if (!value || !backend) return;
	try {
		const r = spawnSync(backend.read[0], backend.read[1], { encoding: "utf8", timeout: 1000, env: childEnv() });
		if (r.status === 0 && typeof r.stdout === "string" && r.stdout.length > 0 && !clipboardMatches(r.stdout, value)) return;
	} catch {
		/* clear anyway */
	}
	try {
		spawnSync(backend.clear[0], backend.clear[1], { input: "", timeout: 2000, env: childEnv() });
	} catch {
		/* best-effort */
	}
}

/** The exact file shape pi's bash tool writes for truncated output. */
const ARTIFACT_RE = /^pi-bash-[0-9a-f]{16}\.log$/;

/** A path is only an output artifact if it is one of bash's files in the OS temp dir. */
function artifactPath(details: unknown): string | undefined {
	if (!details || typeof details !== "object" || !("fullOutputPath" in details)) return undefined;
	const file = (details as { fullOutputPath?: unknown }).fullOutputPath;
	if (typeof file !== "string" || !file) return undefined;
	const resolved = path.resolve(file);
	if (path.dirname(resolved) !== path.resolve(tmpdir())) return undefined;
	if (!ARTIFACT_RE.test(path.basename(resolved))) return undefined;
	return resolved;
}

/**
 * Bash truncation can leave the full output in a file; scrub that copy too.
 * Only bash's own temp artifact is touched: a tool cannot use `fullOutputPath`
 * to make the extension delete or rewrite an arbitrary file.
 */
async function scrubArtifact(toolName: string, details: unknown): Promise<void> {
	if (toolName !== "bash") return;
	const file = artifactPath(details);
	if (!file) return;
	let handle: Awaited<ReturnType<typeof fs.open>> | undefined;
	try {
		// O_NOFOLLOW: never read or rewrite through a symlink placed in the temp dir.
		handle = await fs.open(file, fsConstants.O_RDWR | fsConstants.O_NOFOLLOW);
		const stat = await handle.stat();
		if (!stat.isFile()) return;
		if (stat.size > OUTPUT_CAP) {
			await fs.rm(file, { force: true });
			return;
		}
		const raw = await handle.readFile({ encoding: "utf-8" });
		const { text, changed } = scrubText(raw, scrubValues.values());
		if (changed) {
			await handle.truncate(0);
			await handle.write(text, 0, "utf-8");
		}
	} catch {
		/* artifact already gone, unreadable, or not a regular file */
	} finally {
		if (handle) await handle.close().catch(() => {});
	}
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------
const itemField = {
	item: Type.String({ description: "Item name or id (see bw_list)" }),
	field: Type.Optional(
		Type.String({
			description:
				"password | totp (seed) | code (rotating TOTP code) | notes | field:<customFieldName> (default: password)",
		}),
	),
};
const bwListParams = Type.Object({
	search: Type.Optional(Type.String({ description: "Substring filter on name, username, or URI" })),
	offset: Type.Optional(Type.Number({ description: "Rows to skip (default 0)" })),
	limit: Type.Optional(Type.Number({ description: "Rows to return (default 60, max 200)" })),
});
const bwInjectParams = Type.Object({
	...itemField,
	env: Type.String({ description: "Env var name for bash commands, e.g. MYAPP_TOKEN" }),
});
const bwRunParams = Type.Object({
	...itemField,
	env: Type.Optional(Type.String({ description: "Env var name available to the command (default VAULT_SECRET)" })),
	command: Type.String({ description: "Shell command; use $VAULT_SECRET for the value" }),
	cwd: Type.Optional(Type.String({ description: "Working directory (default: current session cwd)" })),
	timeout: Type.Optional(Type.Number({ description: "Seconds (default 120, max 600)" })),
});
const bwSecretParams = Type.Object(itemField);
const bwRevealParams = Type.Object({
	...itemField,
	reason: Type.String({ description: "Why the plain-text value is needed (shown to the user)" }),
});

/**
 * Register the Bitwarden tools for one binding. `st` is that binding's own
 * state (see BwState), so nothing here can reach another session's unlock.
 */
export function registerBitwarden(pi: ExtensionAPI, st: BwState, ompHost: boolean): void {
	// pi honors createBashTool's spawnHook. OMP already has its own bash tool and
	// discards that env, so registering another bash would only shadow it.
	if (!ompHost) {
		const bashTool = createBashTool(process.cwd(), {
			spawnHook: ({ command, cwd, env }) => {
				// A BW_SESSION exported in the user's shell must not reach bash.
				for (const name of Object.keys(env)) if (name.startsWith("BW_")) delete env[name];
				// Same for Ente's unattended vault key / export password: the model's
				// shell must not be able to open Ente Auth with what the user exported.
				for (const name of ["ENTE_CLI_VAULT_KEY", "ENTE_CLI_PASSWORD"]) delete env[name];
				for (const [name, rec] of st.injected) env[name] = rec.value;
				return { command, cwd, env };
			},
		});
		pi.registerTool({ ...bashTool } as any);
	}

	// Bash activity counts toward the idle auto-lock.
	pi.on("tool_call", async (event) => {
		if (event.toolName === "bash") touchActivity(st);
		return undefined;
	});

	// --- bw_list: vault map without secrets ---
	const delivery = ompHost ? "bw_run" : "bw_inject";
	const bwList: ToolDefinition<typeof bwListParams> = {
		name: "bw_list",
		label: "Bitwarden list",
		description:
			"List Bitwarden vault items: name, username, URI, id. NEVER returns passwords, TOTP, notes or field values. " +
			"Search matches item name, username, or URI. Paginated with offset/limit. " +
			`First use in a session prompts for the Bitwarden master password (unlock). Use it to find item names/ids before ${delivery} or vault_import. ` +
			"This reads Bitwarden live; vault_list is the separate local ai-vault store.",
		promptSnippet: "List Bitwarden items (no secrets)",
		promptGuidelines: [
			`Use bw_list to find Bitwarden item names/ids, then ${delivery} to pass a credential to a command.`,
		],
		parameters: bwListParams,
		async execute(_id, params, signal, _onUpdate, ctx) {
			const session = await ensureUnlocked(st, ctx, signal);
			const offsetInput = params.offset;
			const limitInput = params.limit;
			const offset =
				typeof offsetInput === "number" && Number.isFinite(offsetInput)
					? Math.max(0, Math.trunc(offsetInput))
					: 0;
			const limit =
				typeof limitInput === "number" && Number.isFinite(limitInput)
					? Math.min(200, Math.max(1, Math.trunc(limitInput)))
					: 60;
			let items = [...(await listItems(st, session, signal))].sort((a, b) => a.name.localeCompare(b.name));
			const query = (params.search ?? "").trim().toLowerCase();
			if (query) {
				items = items.filter((i) => `${i.name}\n${i.username}\n${i.uri}`.toLowerCase().includes(query));
			}
			const page = items.slice(offset, offset + limit);
			const lines = page.map(
				(i) => `${i.name || "?"} | user: ${i.username || "-"} | uri: ${i.uri || "-"} | id: ${i.id}`,
			);
			const range = page.length > 0 ? `${offset + 1}-${offset + page.length} of ` : "0 of ";
			const more =
				offset + page.length < items.length
					? `\n... ${items.length - offset - page.length} more (use offset=${offset + page.length})`
					: "";
			const text =
				`${range}${items.length} item(s)${query ? ` matching "${params.search}"` : ""}:\n` +
				lines.join("\n") +
				more;
			return { content: [{ type: "text", text }], details: { count: items.length, offset, limit } };
		},
	};
	pi.registerTool(withTier(bwList, "read"));

	// --- bw_inject: secret -> bash env, model never sees the value ---
	// OMP drops the bash spawnHook env, so there the tool is not offered at all.
	if (!ompHost) {
		const bwInject: ToolDefinition<typeof bwInjectParams> = {
			name: "bw_inject",
			label: "Bitwarden inject",
			description:
				"Fetch a Bitwarden secret and inject it as an environment variable into bash tool commands. " +
				"The VALUE IS NEVER SHOWN to you nor stored in the conversation; reference it as $VAR in later bash commands. " +
				"Requires user confirmation per injection. Use when a command needs a credential (API token, docker login, git push, ...). " +
				"Browser filling: agent-browser fill @ref \"$VAR\" types it into a form without the value entering the conversation. " +
				"Prefer this over bw_reveal. field: 'password' (default) | 'totp' (seed) | 'code' (rotating TOTP code) | 'notes' | 'field:<customFieldName>'.",
			promptSnippet: "Pass a Bitwarden secret to bash via env var (value hidden from model)",
			promptGuidelines: [
				"Use bw_inject when a bash command needs a Bitwarden credential; never ask the user to paste secrets into chat.",
				"To fill a browser login with agent-browser: bw_inject the secret, then run agent-browser fill @ref \"$VAR\" — the value stays out of the conversation.",
				"For repeated browser logins, import once with: printenv $VAR | agent-browser auth save <name> --username <user> --password-stdin — afterwards agent-browser auth login <name> needs no secret.",
			],
			parameters: bwInjectParams,
			async execute(_id, params, signal, _onUpdate, ctx) {
				const field = (params.field ?? "password").trim();
				if (!FIELD_RE.test(field)) {
					throw new Error(`Invalid field "${field}". Use password | totp | code | notes | field:<name>.`);
				}
				const envName = normalizeEnvName(params.env);
				if (!st.injected.has(envName) && st.injected.size >= CONFIG.maxInjectedEnv) {
					throw new Error(`Too many injected vars (max ${CONFIG.maxInjectedEnv}). Run /bw clear to drop some.`);
				}

				const replaced = st.injected.get(envName);
				const approved = await approveItem(
					st,
					ctx,
					"inject",
					"Bitwarden: inject secret into AI bash environment",
					params.item,
					field,
					`Env:     $${envName}` +
						(replaced ? `\nReplaces: "${replaced.item}" (${replaced.field})` : "") +
						`\n\nCommands run by the AI in this session will see $${envName}.` +
						`\nThe value itself is never shown to the AI nor stored in the chat.` +
						`\nDropped on ` +
						(autoLockMs ? `idle lock (${Math.round(autoLockMs / 60000)} min) or /bw lock` : `/bw lock or session end`) +
						`.`,
					signal,
				);
				if (!approved) throw new Error("User declined the injection.");

				const { value, itemId, itemName } = await secretOf(approved.session, approved.item, field, signal);
				st.injected.set(envName, { value, item: itemName, field, at: Date.now() });
				rememberScrubValue(envName, value);
				await auditEvent("inject", `allow env=${envName} item="${itemName}" (${itemId}) field=${field}`, st.sessionLabel);
				safeStatus(ctx, `🔓 bw: ${st.injected.size} env var(s)`);
				const weak =
					value.length < 6
						? " WARNING: this value is shorter than 6 characters, so tool output cannot be reliably scrubbed."
						: "";

				return {
					content: [
						{
							type: "text",
							text:
								`Injected $${envName} (item "${itemName}", field ${field}) into the bash environment. ` +
								`Use $${envName} in bash commands. Do NOT try to print, echo, or exfiltrate it — output is scrubbed.${weak} ` +
								`Active injected vars: ${injectedListText(st)}`,
						},
					],
					details: { env: envName, item: itemName, field },
				};
			},
		};
		pi.registerTool(bwInject);
	}

	// --- bw_run: one command with the secret in its env (works on OMP) ---
	const bwRun: ToolDefinition<typeof bwRunParams> = {
		name: "bw_run",
		label: "Bitwarden run",
		description:
			"Run a shell command with a Bitwarden secret in its environment as $VAULT_SECRET (or a chosen env name). " +
			"The value never enters the conversation; stdout/stderr are scrubbed. Requires confirmation per call. " +
			"Use this on OMP (where bw_inject is unavailable) or when the secret should live for exactly one command. " +
			"field: 'password' (default) | 'totp' (seed) | 'code' (rotating TOTP) | 'notes' | 'field:<customFieldName>'.",
		promptSnippet: "Run one command with a Bitwarden secret in its env (value hidden)",
		promptGuidelines: [
			"Use bw_run for a command that needs a Bitwarden credential; reference it as $VAULT_SECRET.",
			"Never print or echo the value; prefer piping it into the consumer (e.g. --password-stdin).",
		],
		parameters: bwRunParams,
		async execute(_id, params, signal, _onUpdate, ctx) {
			const field = (params.field ?? "password").trim();
			if (!FIELD_RE.test(field)) {
				throw new Error(`Invalid field "${field}". Use password | totp | code | notes | field:<name>.`);
			}
			if (!params.command.trim()) throw new Error("Command is empty.");
			const envName = normalizeEnvName(params.env ?? "VAULT_SECRET");
			const timeoutInput = params.timeout;
			const seconds =
				typeof timeoutInput === "number" && Number.isFinite(timeoutInput)
					? Math.min(600, Math.max(1, Math.trunc(timeoutInput)))
					: 120;
			const cwd = params.cwd?.trim() || ctx.cwd || process.cwd();
			const approved = await approveItem(
				st,
				ctx,
				"run",
				"Bitwarden: run command with secret",
				params.item,
				field,
				`Env:     $${envName}\nCwd:     ${cwd}\nCommand:\n${params.command}\n\n` +
					`The command runs once with $${envName} set. The value never enters the chat; output is scrubbed.`,
				signal,
			);
			if (!approved) throw new Error("User declined the command.");
			const { value, itemName } = await secretOf(approved.session, approved.item, field, signal);
			rememberScrubValue(envName, value);
			const r = await exec("bash", ["-c", params.command], {
				env: { [envName]: value },
				cwd,
				timeout: seconds * 1000,
				signal,
				group: true,
			});
			await auditEvent("run", `allow env=${envName} item="${itemName}" field=${field} exit=${r.code}`, st.sessionLabel);
			const raw = [r.stdout, r.stderr].filter((s) => s.length > 0).join("\n");
			const scrubbed = scrubText(raw, scrubValues.values()).text;
			const output =
				scrubbed.length > 32_000
					? `... (truncated to the last 32000 chars)\n${scrubbed.slice(-32_000)}`
					: scrubbed;
			const dropped = r.truncated ? "(command output past 8 MiB was dropped)\n" : "";
			return {
				content: [
					{
						type: "text",
						text:
							`Ran with $${envName} (item "${itemName}", field ${field}); exit ${r.code}.\n${dropped}` +
							(output ? `--- output ---\n${output}` : "(no output)"),
					},
				],
				details: { item: itemName, field, env: envName, exit: r.code, truncated: r.truncated },
			};
		},
	};
	pi.registerTool(withTier(bwRun, "exec"));

	// --- bw_clipboard: secret -> clipboard, auto-cleared ---
	const bwClipboard: ToolDefinition<typeof bwSecretParams> = {
		name: "bw_clipboard",
		label: "Bitwarden clipboard",
		description:
			"Copy a Bitwarden secret to the system clipboard; " +
			CLIPBOARD_CLEAR_TEXT +
			". The value never enters the conversation. Requires user confirmation. " +
			"field: 'password' (default) | 'totp' (seed) | 'code' (rotating TOTP code) | 'notes' | 'field:<customFieldName>'.",
		promptSnippet: "Copy a Bitwarden secret to clipboard (auto-clear)",
		parameters: bwSecretParams,
		async execute(_id, params, signal, _onUpdate, ctx) {
			const field = (params.field ?? "password").trim();
			if (!FIELD_RE.test(field)) throw new Error(`Invalid field "${field}".`);
			const approved = await approveItem(
				st,
				ctx,
				"clipboard",
				"Bitwarden: copy secret to clipboard",
				params.item,
				field,
				`The value is copied to the system clipboard; ${CLIPBOARD_CLEAR_TEXT}. It never enters the chat.`,
				signal,
			);
			if (!approved) throw new Error("User declined.");
			const { value, itemName } = await secretOf(approved.session, approved.item, field, signal);
			// The value is now in a place bash can read back (pbpaste/xclip -o),
			// so tool output carrying it must be scrubbed like an injected var.
			rememberScrubValue("CLIPBOARD", value);
			await copyToClipboard(value);
			await auditEvent("clipboard", `allow item="${itemName}" field=${field}`, st.sessionLabel);
			const clears =
				CONFIG.clipboardClearSeconds > 0 ? `Clears in ${CONFIG.clipboardClearSeconds}s.` : "Auto-clear disabled.";
			return {
				content: [{ type: "text", text: `Copied "${itemName}" (${field}) to clipboard. ${clears}` }],
				details: { item: itemName, field },
			};
		},
	};
	pi.registerTool(withTier(bwClipboard, "write"));

	// --- bw_reveal: plain text to the model, per-call confirmation ---
	const bwReveal: ToolDefinition<typeof bwRevealParams> = {
		name: "bw_reveal",
		label: "Bitwarden reveal (danger)",
		description:
			"Return a Bitwarden secret in PLAIN TEXT. DANGEROUS: the value will be sent to the LLM provider and stored in the session file. " +
			"Requires explicit user confirmation every single call, and is disabled unless allowReveal is set in the config. " +
			"Only use when bw_inject / bw_clipboard genuinely cannot do the job. " +
			"field: 'password' (default) | 'totp' (seed) | 'code' (rotating TOTP code) | 'notes' | 'field:<customFieldName>'.",
		promptSnippet: "Reveal a Bitwarden secret in plain text (per-call approval)",
		promptGuidelines: [
			"Use bw_reveal only as a last resort; prefer bw_inject (bash env) or bw_clipboard which keep the value out of the conversation.",
		],
		parameters: bwRevealParams,
		async execute(_id, params, signal, _onUpdate, ctx) {
			if (!CONFIG.allowReveal) {
				throw new Error("bw_reveal is disabled in this installation (set allowReveal in ~/.bw/pi-extension/config.json to enable it).");
			}
			const field = (params.field ?? "password").trim();
			if (!FIELD_RE.test(field)) throw new Error(`Invalid field "${field}".`);
			const provider = ctx?.model?.provider ?? "the LLM provider";
			const approved = await approveItem(
				st,
				ctx,
				"reveal",
				"⚠️ Bitwarden: reveal secret IN PLAIN TEXT",
				params.item,
				field,
				`Reason: ${params.reason}\n\n` +
					`The value will be shown to the AI, sent to ${provider}, and stored in the session file.`,
				signal,
			);
			if (!approved) throw new Error("User declined the reveal.");
			const { value, itemName } = await secretOf(approved.session, approved.item, field, signal);
			await auditEvent("reveal", `allow item="${itemName}" field=${field}`, st.sessionLabel);
			return {
				content: [{ type: "text", text: `${itemName} (${field}):\n<secret>${value}</secret>` }],
				details: { item: itemName, field },
			};
		},
	};
	pi.registerTool(bwReveal);

	// --- Scrubber: active secrets never reach the model via tool results ---
	pi.on("tool_result", async (event) => {
		// bw_reveal and vault_get are intentional, user-approved plain-text
		// reveals; scrubbing them would corrupt the value the user asked for.
		if (event.toolName === "bw_reveal" || event.toolName === "vault_get") return undefined;
		if (scrubValues.size === 0) return undefined;
		let changed = false;
		const content = event.content.map((block: any) => {
			if (block?.type !== "text" || typeof block.text !== "string") return block;
			const result = scrubText(block.text, scrubValues.values());
			if (result.changed) changed = true;
			return result.changed ? { ...block, text: result.text } : block;
		});
		// Host tool details can carry expanded command/env data; scrub them too.
		const details = scrubDeep(event.details, scrubValues.values());
		const structured = scrubDeep(event.structuredContent, scrubValues.values());
		if (details.changed || structured.changed) changed = true;
		await scrubArtifact(event.toolName, event.details);
		if (!changed) return undefined;
		const result: ToolResultEventResult = { content };
		if (details.changed) result.details = details.value;
		// The scrubbed tree is still JSON-shaped (strings, arrays, plain objects).
		if (structured.changed) result.structuredContent = structured.value as ToolResultEventResult["structuredContent"];
		return result;
	});

	// --- /bw command ---
	pi.registerCommand("bw", {
		description: "Bitwarden: status | unlock | lock | clear [ENV]",
		handler: async (args: string, ctx) => {
			const parts = (args ?? "status").trim().split(/\s+/);
			const sub = (parts[0] || "status").toLowerCase();
			if (sub === "lock") {
				await lock(st, "user");
				safeStatus(ctx, undefined);
				ctx.ui.notify("Bitwarden: locked (session key + injected env dropped)", "info");
				return;
			}
			if (sub === "clear") {
				const target = parts[1];
				if (target) {
					let envName: string;
					try {
						envName = normalizeEnvName(target);
					} catch (e) {
						ctx.ui.notify(e instanceof Error ? e.message : String(e), "error");
						return;
					}
					const removed = st.injected.delete(envName);
					safeStatus(ctx, st.key ? `🔓 bw: ${st.injected.size} env var(s)` : undefined);
					ctx.ui.notify(
						removed ? `Bitwarden: dropped $${envName}` : `Bitwarden: $${envName} was not injected`,
						removed ? "info" : "warning",
					);
					return;
				}
				st.injected.clear();
				safeStatus(ctx, st.key ? `🔓 bw: 0 env var(s)` : undefined);
				ctx.ui.notify("Bitwarden: injected env vars cleared", "info");
				return;
			}
			if (sub === "unlock") {
				try {
					await ensureUnlocked(st, ctx);
					safeStatus(ctx, `🔓 bw: ${st.injected.size} env var(s)`);
					ctx.ui.notify("Bitwarden: unlocked", "info");
				} catch (e: unknown) {
					ctx.ui.notify(`Bitwarden unlock failed: ${e instanceof Error ? e.message : String(e)}`, "error");
				}
				return;
			}
			// status
			let cli = "unknown";
			try {
				const cliState = await bwStatus();
				cli = cliState?.status ?? "unknown";
			} catch (e: unknown) {
				cli = `error: ${tail(e instanceof Error ? e.message : String(e), 80)}`;
			}
			const ttl = st.key && autoLockMs ? Math.max(0, Math.round((autoLockMs - (Date.now() - st.lastActivity)) / 60000)) : 0;
			ctx.ui.notify(
				`bw CLI: ${cli}\n` +
					`extension: ${st.key ? (autoLockMs ? `unlocked (auto-lock in ${ttl} min)` : "unlocked (session-lifetime)") : "locked"}\n` +
					`injected env: ${injectedListText(st)}\n` +
					`bw_reveal: ${CONFIG.allowReveal ? "enabled" : "disabled"}`,
				"info",
			);
		},
	});

	// --- Lifecycle ---
	// /new and /fork must not carry this unlock into the next transcript; a
	// /resume keeps it when keepOnResume is set. Which event reports that is
	// the host's business (see host.ts).
	onSessionLeave(pi, ompHost, async (reason, ctx) => {
		if (reason === "resume" && CONFIG.keepOnResume) return;
		await lock(st, `session-${reason}`);
		safeStatus(ctx, undefined);
	});
}
