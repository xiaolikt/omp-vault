import { tr } from "./i18n.js";
/**
 * Ente CLI client.
 *
 * `ente` (Ente's "client for terminals and agents") is logged in once —
 * `ente account login --app auth` — and then keeps its session on disk
 * (`$XDG_DATA_HOME/ente-cli`) with the database key in the OS keychain, or in
 * `ENTE_CLI_VAULT_KEY` for unattended use. So no password per call here: we
 * only run the CLI and parse its JSON.
 *
 * What this module adds on top of the bare CLI is the extension's rules:
 * metadata listing returns no secrets, reading one current code always passes
 * through a confirm window that names the entry, and every read is audited.
 *
 * JSON contract (ente.com/help/cli/auth):
 *   `auth code list --json` -> [{ id, name, issuer, accountName, type }]
 *   `auth code view <q> --json` -> the same object plus { otp, validUntil }
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";
import type { ExtensionAPI, ExtensionContext, ToolDefinition } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import { auditEvent } from "./bitwarden.js";
import { confirmWindow, forDialog } from "./prompt.js";
import { withTier } from "./host.js";
import { getSettingsSafe, settingsCli } from "./settings.js";

export interface EnteCodeMeta {
	id: string;
	name: string;
	issuer: string;
	accountName: string;
	type: string;
}

export interface EnteCode extends EnteCodeMeta {
	otp: string;
	validUntil: string;
}

export class EnteError extends Error {
	constructor(message: string, readonly code: number) {
		super(message);
		this.name = "EnteError";
	}
}

const ENTE_MISSING =
	tr("ente CLI not found (that is ente.com's `ente`, 0.4+). After installing it, run `ente account login --app auth` once; ENTE_BIN can point at the binary.", "ente CLI 没找到（要的是 ente.com 的 `ente`，0.4+）。装好后先 `ente account login --app auth` 登录一次；也可以用 ENTE_BIN 指到二进制。");

/** `ENTE_BIN`, then PATH, then the usual install spots. */
export function resolveEnte(): string | undefined {
	const explicit = process.env.ENTE_BIN;
	if (explicit) return existsSync(explicit) ? explicit : undefined;
	for (const dir of (process.env.PATH ?? "").split(delimiter)) {
		if (!dir) continue;
		// Windows: the program is ente.exe; the bare name matches no file there.
		for (const name of process.platform === "win32" ? ["ente.exe", "ente"] : ["ente"]) {
			const candidate = join(dir, name);
			if (existsSync(candidate)) return candidate;
		}
	}
	for (const candidate of [
		join(homedir(), ".local", "opt", "ente-cli", "bin", "ente"),
		join(homedir(), ".local", "bin", "ente"),
		join(homedir(), ".cargo", "bin", "ente"),
	]) {
		if (existsSync(candidate)) return candidate;
	}
	return undefined;
}

interface Run {
	code: number;
	stdout: string;
	stderr: string;
}

/**
 * The environment for one `ente` run.
 *
 * `ente.unlock = never | time`: the key is kept sealed by ai-vault (the same
 * wrapping as the Bitwarden session), so Ente needs neither the OS keychain
 * nor a login window. `session` (default) leaves the keychain in charge and
 * passes nothing.
 */
async function enteEnv(signal?: AbortSignal): Promise<Record<string, string | undefined>> {
	const env: Record<string, string | undefined> = { ...process.env };
	// Never let a key the user exported in their shell decide this.
	delete env.ENTE_CLI_VAULT_KEY;
	const settings = await getSettingsSafe(signal);
	if (settings.ente.unlock === "session") return env;
	try {
		const sealed = await settingsCli().json<{ key: string }>(["ente-session", "get"], { signal });
		if (sealed?.key) env.ENTE_CLI_VAULT_KEY = sealed.key;
	} catch {
		// No key saved yet, or it expired: ente will fall back to the keychain,
		// which is exactly what a `session` policy would have done.
	}
	return env;
}

async function runEnte(args: string[], signal?: AbortSignal): Promise<Run> {
	const bin = resolveEnte();
	if (!bin) throw new EnteError(ENTE_MISSING, 127);
	if (signal?.aborted) throw new EnteError("Cancelled.", 4);
	const env = await enteEnv(signal);
	return new Promise<Run>((resolve, reject) => {
		const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"], env });
		let stdout = "";
		let stderr = "";
		const onAbort = () => child.kill("SIGKILL");
		signal?.addEventListener("abort", onAbort, { once: true });
		child.stdout?.on("data", (chunk: Buffer | string) => {
			if (stdout.length < 8 * 1024 * 1024) stdout += chunk;
		});
		child.stderr?.on("data", (chunk: Buffer | string) => {
			if (stderr.length < 64_000) stderr += chunk;
		});
		child.on("error", (error) => {
			signal?.removeEventListener("abort", onAbort);
			reject(new EnteError(`cannot run ente: ${error.message}`, 127));
		});
		child.on("close", (code) => {
			signal?.removeEventListener("abort", onAbort);
			resolve({ code: code ?? -1, stdout, stderr });
		});
	});
}

async function enteJson<T>(args: string[], signal?: AbortSignal): Promise<T> {
	// --no-input: a prompt becomes an error instead of a hang behind our back.
	const run = await runEnte(["--json", "--no-input", ...args], signal);
	if (run.code !== 0) {
		const message = run.stderr
			.split(/\r?\n/)
			.map((line) => line.trim())
			.filter(Boolean)
			.slice(-3)
			.join(" ");
		throw new EnteError(message || `ente exited with ${run.code}`, run.code);
	}
	try {
		return JSON.parse(run.stdout) as T;
	} catch {
		throw new EnteError(`ente returned non-JSON output: ${run.stdout.slice(0, 200)}`, 1);
	}
}

const asString = (value: unknown): string => (typeof value === "string" ? value : "");
const normalize = (raw: unknown): EnteCodeMeta => {
	const r = (raw ?? {}) as Record<string, unknown>;
	return {
		id: asString(r.id),
		name: forDialog(asString(r.name), 80),
		issuer: forDialog(asString(r.issuer), 60),
		accountName: forDialog(asString(r.accountName), 60),
		type: asString(r.type) || "totp",
	};
};

/** Metadata only: names, issuers, account names. No codes, no secrets. */
export async function listCodes(signal?: AbortSignal): Promise<EnteCodeMeta[]> {
	const list = async (extra: string[] = []): Promise<EnteCodeMeta[]> => {
		const raw = await enteJson<unknown[]>(["auth", "code", "list", ...extra], signal);
		return Array.isArray(raw) ? raw.map(normalize) : [];
	};
	try {
		return await list();
	} catch (error) {
		// A first run may have nothing synced yet; --offline reads what is cached.
		// A not-logged-in CLI fails both ways, and the error is what the user needs.
		if (!(error instanceof EnteError)) throw error;
		return list(["--offline"]);
	}
}

/** One current code. The caller must have shown the user which entry this is. */
export async function viewCode(ref: string, signal?: AbortSignal): Promise<EnteCode> {
	const raw = await enteJson<Record<string, unknown>>(["auth", "code", "view", ref], signal);
	const meta = normalize(raw);
	const otp = asString(raw.otp);
	if (!otp) throw new EnteError(`ente returned no code for "${ref}"`, 1);
	return { ...meta, otp, validUntil: asString(raw.validUntil) };
}

/** The entry a reference really names, so the window shows what will be read. */
export function resolveRef(items: EnteCodeMeta[], ref: string): EnteCodeMeta | undefined {
	const query = ref.trim().toLowerCase();
	if (!query) return undefined;
	const haystack = (item: EnteCodeMeta): string =>
		`${item.name}\n${item.issuer}\n${item.accountName}`.toLowerCase();
	const exact = items.filter((item) => item.name.toLowerCase() === query);
	if (exact.length === 1) return exact[0];
	const hits = items.filter((item) => haystack(item).includes(query));
	return hits.length === 1 ? hits[0] : exact[0] ?? (hits.length > 1 ? undefined : undefined);
}

type ToolOutcome = {
	content: { type: "text"; text: string }[];
	details: { ok?: boolean; denied?: boolean; item?: string; count?: number };
	isError?: boolean;
};

const fail = (text: string, denied = false): ToolOutcome => ({
	content: [{ type: "text" as const, text }],
	details: { ok: false, ...(denied ? { denied: true } : {}) },
	isError: true,
});

const describe = (error: unknown): string => (error instanceof Error ? error.message : String(error));

export function registerEnte(pi: ExtensionAPI): void {
	const listParams = Type.Object({});
	const listTool: ToolDefinition<typeof listParams, { ok?: boolean; count?: number }> = {
		name: "ente_list",
		label: "Ente: list Auth codes",
		description:
			"List the entries saved in Ente Auth through the `ente` CLI: name, issuer, account name, type (totp/hotp/steam). " +
			"NEVER returns codes or secrets. Use ente_code to read one; the user must approve a window first. " +
			"Sessions come from `ente account login --app auth` (and optionally ENTE_CLI_VAULT_KEY), not from the master password of ai-vault.",
		promptSnippet: "List Ente Auth entries (metadata only).",
		parameters: listParams,
		async execute(_id, _params, signal, _onUpdate, ctx) {
			try {
				const items = await listCodes(signal);
				await auditEvent(`ente.list`, `count=${items.length}`, sessionLabelOf(ctx));
				return {
					content: [{ type: "text" as const, text: JSON.stringify(items, null, 1) }],
					details: { count: items.length },
				};
			} catch (error) {
				return fail(describe(error));
			}
		},
	};

	const codeParams = Type.Object({
		name: Type.String({ description: "Entry name, or part of its name/issuer/account" }),
	});
	const codeTool: ToolDefinition<typeof codeParams, { ok?: boolean; denied?: boolean; item?: string }> = {
		name: "ente_code",
		label: "Ente: show a current code",
		description:
			"Return the current TOTP/Steam code for one Ente Auth entry. The user approves a window that names the entry; the code is short-lived. " +
			"If the user denies, do not retry. Codes go into the conversation — prefer passing them on in the same turn.",
		promptSnippet: "Read one current Ente Auth code after the user approves a window.",
		parameters: codeParams,
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const items = await listCodes(signal);
				if (items.length === 0) return fail("Ente Auth has no saved codes on this device — run `ente account login --app auth` first.");
				const item = resolveRef(items, params.name);
				if (!item) {
					const names = items.slice(0, 15).map((i) => `${i.name}${i.issuer ? ` (${i.issuer})` : ""}`);
					return fail(`no single Ente entry matches "${params.name}". candidates: ${names.join(", ") || "(none)"}`);
				}
				const ok = await confirmWindow(
					ctx as unknown as Parameters<typeof confirmWindow>[0],
					tr("pi-ai-vault · Ente Auth code", "pi-ai-vault · Ente Auth 验证码"),
					tr(`Entry: ${item.name}\n签发方: ${item.issuer || "-"}\n账号: ${item.accountName || "-"}\n\nRead the current code? (It enters the conversation.)`, `条目: ${item.name}\n签发方: ${item.issuer || "-"}\n账号: ${item.accountName || "-"}\n\n读取当前验证码？（会进入对话）`),
					signal,
				);
				if (!ok) {
					await auditEvent("ente.code", `deny item="${item.name}"`, sessionLabelOf(ctx));
					return fail(`user denied reading the code for "${item.name}" — do not retry`, true);
				}
				const code = await viewCode(item.name, signal);
				await auditEvent("ente.code", `allow item="${item.name}"`, sessionLabelOf(ctx));
				return {
					content: [
						{
							type: "text" as const,
							text: JSON.stringify(
								{ name: code.name, issuer: code.issuer, accountName: code.accountName, code: code.otp, validUntil: code.validUntil, via: "ente" },
								null,
								1,
							),
						},
					],
					details: { ok: true, item: code.name },
				};
			} catch (error) {
				if (signal?.aborted) return fail("cancelled", true);
				return fail(describe(error));
			}
		},
	};

	pi.registerTool(withTier(listTool, "read"));
	pi.registerTool(withTier(codeTool, "write"));
}

/** Same shape as the Bitwarden audit lines: the session or subagent that asked. */
function sessionLabelOf(ctx: ExtensionContext | undefined): string {
	const agent = (ctx as { agent?: { kind?: string; id?: string } } | undefined)?.agent;
	if (agent?.kind === "sub" && agent.id) return agent.id.replace(/[^\w.-]/g, "").slice(0, 24);
	let id = "";
	try {
		id = (ctx as { sessionManager?: { getSessionId?: () => string } } | undefined)?.sessionManager?.getSessionId?.() ?? "";
	} catch {
		/* a context without a session manager */
	}
	return id.replace(/-/g, "").slice(0, 8) || "main";
}
