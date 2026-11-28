// Shared setup for the ai-vault tests: a throwaway HOME and vault, a mock
// `bw` CLI, and a mock `zenity` that answers from queue files.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const MOCKS = join(dirname(fileURLToPath(import.meta.url)), "mocks", "bin");
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The Rust binary the extension calls: $AI_VAULT_BIN, else a local build. */
export function cliBinary() {
	const explicit = process.env.AI_VAULT_BIN;
	if (explicit) return explicit;
	const file = process.platform === "win32" ? "ai-vault.exe" : "ai-vault";
	for (const profile of ["release", "debug"]) {
		const candidate = join(ROOT, "target", profile, file);
		if (existsSync(candidate)) return candidate;
	}
	const built = spawnSync("cargo", ["build", "--release"], { cwd: ROOT, stdio: "inherit" });
	if (built.status !== 0) throw new Error("cannot build the ai-vault CLI; run `cargo build --release`");
	return join(ROOT, "target", "release", file);
}

/**
 * Point the process at the mocks and at a private HOME, so nothing touches the
 * user's real vault, Bitwarden config, or audit log. Call before importing
 * anything under src/: module state is created at import time.
 */
export function useMocks() {
	const dir = mkdtempSync(join(tmpdir(), "ai-vault-test-"));
	mkdirSync(join(dir, "home"), { recursive: true });
	process.env.HOME = join(dir, "home");
	process.env.DISPLAY = ":99";
	delete process.env.WAYLAND_DISPLAY;
	process.env.PATH = `${MOCKS}${delimiter}${process.env.PATH}`;
	process.env.OMP_VAULT_BW_MOCK_DIR = dir;
	process.env.OMP_VAULT_MOCK = dir;
	// The ente mock keeps its own state directory, like the bw one.
	process.env.ENTE_MOCK_DIR = dir;
	process.env.AI_VAULT_DIR = join(dir, "vault");
	process.env.AI_VAULT_BIN = cliBinary();
	// The extension resolves the CLI from PATH; the tests pass one explicitly.
	// Put the same build first so both halves run the same version.
	process.env.PATH = `${dirname(process.env.AI_VAULT_BIN)}${delimiter}${process.env.PATH}`;
	return dir;
}

/** Remove the throwaway directory when the process exits. Call after importing src/. */
export function cleanUpOnExit(dir) {
	// Registered after the extension's own exit handler, so that handler still
	// finds its mock clipboard and the directory goes last.
	process.on("exit", () => rmSync(dir, { recursive: true, force: true }));
}

/**
 * Answers the mock dialogs give, in the order they are asked. Each call
 * replaces its queue, so a prompt that never opened cannot leak into a later one.
 */
export const answers = {
	/** Master-password dialogs, local or Bitwarden. */
	master: (dir, ...lines) => writeFileSync(join(dir, "passwords"), lines.map((l) => `${l}\n`).join("")),
	/** The dialog that types a new entry's password. */
	entryPassword: (dir, password) => writeFileSync(join(dir, "entry-passwords"), `${password}\n`),
	entries: (dir, ...lines) => writeFileSync(join(dir, "entries"), lines.map((l) => `${l}\n`).join("")),
	/** --question answers, one per window ("y"/"n"). */
	questions: (dir, ...lines) => writeFileSync(join(dir, "questions"), lines.map((l) => `${l}\n`).join("")),
	deny: (dir, on = true) =>
		on ? writeFileSync(join(dir, "deny"), "") : rmSync(join(dir, "deny"), { force: true }),
};

/** Every dialog the code opened, one line per call. */
export const dialogTrace = (dir) =>
	existsSync(join(dir, "zenity.log")) ? readFileSync(join(dir, "zenity.log"), "utf8") : "";
export const passwordPrompts = (dir) => dialogTrace(dir).split("\n").filter((l) => l.startsWith("--password")).length;

let seq = 0;
const uuid = () => `${(0x10000000 + ++seq).toString(16)}-1111-4111-8111-111111111111`;

/** A host context. `input` and `confirm` replace the host dialog (used when no window can open). */
export function makeCtx({ sessionId, agent, hasUI = true, input, confirm } = {}) {
	const notes = [];
	const sid = sessionId ?? uuid();
	const ctx = {
		hasUI,
		cwd: process.env.OMP_VAULT_BW_MOCK_DIR,
		mode: "tui",
		sessionManager: { getSessionId: () => sid },
		agent,
		model: { provider: "test-provider" },
		ui: {
			notify: (message, type = "info") => notes.push({ type, message }),
			setStatus() {},
			input: (title, placeholder) => (input ? input(title, placeholder) : Promise.resolve(undefined)),
			confirm: (title, message) => (confirm ? confirm(title, message) : Promise.resolve(false)),
		},
	};
	return {
		ctx,
		notes,
		sid,
		last: () => notes.at(-1),
	};
}

const SUBAGENT = { kind: "sub", id: "0-Explore", name: "explore", depth: 0, parentId: "Main" };
export const subCtx = (options) => makeCtx({ agent: SUBAGENT, ...options });

/** Run the extension factory against a recording API. `omp: false` is upstream pi. */
export function bind(ompVault, omp = true) {
	const tools = new Map();
	const commands = new Map();
	const handlers = new Map();
	const api = {
		registerTool: (tool) => tools.set(tool.name, tool),
		registerCommand: (name, def) => commands.set(name, def),
		on: (event, handler) => {
			if (!handlers.has(event)) handlers.set(event, []);
			handlers.get(event).push(handler);
			return () => {};
		},
	};
	if (omp) api.pi = {};
	ompVault(api);
	return {
		tools,
		commands,
		has: (event) => handlers.has(event),
		fire: (event, payload = {}, ctx = makeCtx().ctx) =>
			Promise.all((handlers.get(event) ?? []).map((handler) => handler(payload, ctx))),
		tool: (name, params, ctx = makeCtx().ctx) => tools.get(name).execute("call", params, undefined, undefined, ctx),
		cmd: (args, ctx = makeCtx().ctx) => commands.get("vault").handler(args, ctx),
	};
}

export const textOf = (result) => result.content.find((block) => block.type === "text")?.text ?? "";

/** A fresh human session token for the throwaway store, or undefined. */
export function unlockToken() {
	const run = spawnSync(process.env.AI_VAULT_BIN, ["unlock", "--password-stdin", "--json"], {
		input: "correct horse battery\n",
		env: process.env,
		encoding: "utf8",
	});
	return run.status === 0 ? JSON.parse(run.stdout).token : undefined;
}

/**
 * Change an ai-vault setting the way a host does: with a session token, and
 * with the master password on stdin for the changes that lower protection
 * (confirm off, unlock never, import always …). Returns the CLI result.
 */
export function setSetting(key, value, { password } = {}) {
	// The extension caches settings for 30s; a change made here must be seen.
	process.emit("ai-vault:settings-changed");
	const bin = process.env.AI_VAULT_BIN;
	const run = spawnSync(bin, ["unlock", "--password-stdin", "--json"], {
		input: `${password ?? "correct horse battery"}\n`,
		env: process.env,
		encoding: "utf8",
	});
	// In `never` mode the unlock refreshes the machine-wide session and the
	// caller is expected to use no token at all (that is what `auto: true`
	// means); a per-session token is not minted there.
	const unlocked = run.status === 0 ? JSON.parse(run.stdout) : undefined;
	const token = unlocked && !unlocked.auto ? unlocked.token : undefined;
	return spawnSync(bin, ["settings", key, value, "--password-stdin", ...(token ? ["--token", token] : [])], {
		input: `${password ?? "correct horse battery"}\n`,
		env: process.env,
		encoding: "utf8",
	});
}
