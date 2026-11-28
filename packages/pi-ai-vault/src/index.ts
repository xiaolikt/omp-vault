import { tr } from "./i18n.js";
/**
 * ai-vault — the pi/omp extension.
 *
 * The store itself lives in the `ai-vault` Rust binary, in one machine-wide
 * directory (~/.ai-vault), so pi, omp, and anything else on this computer
 * share the same imported passwords. This file only registers tools and a
 * command, keeps one session token per binding, and opens host dialogs when
 * the CLI has no desktop window of its own.
 *
 * Bitwarden stays here: `bw_*` tools query the live vault through the `bw`
 * CLI, and `vault_import` copies login items into the local store via
 * `ai-vault save`.
 */
import type { ExtensionAPI, ExtensionCommandContext, ExtensionToolContext, ToolDefinition } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import {
	lookupBitwardenItem,
	newBwState,
	pullBitwardenItems,
	queryBitwarden,
	registerBitwarden,
	type BitwardenMeta,
	type BwState,
} from "./bitwarden.js";
import { CliError } from "./cli.js";
import { ITEM_TYPES, isSecretField, parseItemType } from "./import-map.js";
import type { Draft, ItemType } from "./types.js";
import { registerEnte } from "./ente.js";
import { isOmpHost, onSessionLeave, sessionLabel, subagentId, withTier } from "./host.js";
import { confirmWindow, forDialog, promptSecret, promptText, type PromptHost } from "./prompt.js";
import { forgetSettings, getSettingsSafe, setSettingsToken, settingsCli, settingsToken, type Settings } from "./settings.js";

type Ctx = ExtensionToolContext | ExtensionCommandContext;

const GRANT_MS_DEFAULT = 5 * 60_000;

type UnlockModeName = "never" | "time" | "session";

interface StatusResult {
	ok: boolean;
	unlocked: boolean;
	items: number;
	requester: string;
	idleMs: number;
	expiresAt: number | null;
	mode: UnlockModeName;
	hours: number;
	auto: boolean;
	grants: Record<string, { expiresAt: number; leftMs: number }>;
}

interface UnlockResult {
	ok: boolean;
	token: string;
	expiresAt: number | null;
	items: number;
	mode?: UnlockModeName;
	auto?: boolean;
	/** Minted by the CLI for a host; kept in memory only, signs approvals. */
	hostSecret?: string;
}

interface ListResult {
	ok: boolean;
	count: number;
	items: { name: string; username?: string | null; uris: string[]; updatedAt: string }[];
}

interface RemovingResult {
	ok: boolean;
	removed: boolean;
}

interface SaveResult {
	ok: boolean;
	count: number;
	names: string[];
}

interface AuditResult {
	ok: boolean;
	entries: { ts: string; session: string; event: string; item?: string; reason?: string }[];
}

/**
 * One binding (a session, or a subagent) and the CLI session token it holds.
 * The token is not the key: the key never leaves the ai-vault process tree.
 */
interface Scope {
	token?: string;
	/** Bumped when access is dropped; an unlock prompt opened before is discarded. */
	epoch: number;
	/** Cached entry count for the status line. */
	items: number;
	/** The machine-wide unlock policy, as the CLI last reported it. */
	mode?: UnlockModeName;
	/** True when reads use the machine-wide session instead of a token. */
	auto?: boolean;
	unlocking?: Promise<boolean>;
}

const cli = settingsCli();

const CLI_MISSING =
	tr("ai-vault CLI not found. Install it once for a machine-wide store: cargo install --path <repo>/crates/ai-vault (or point AI_VAULT_BIN at a compiled binary)", "ai-vault CLI 没找到。装一次就有全机共享的库：cargo install --path <repo>/crates/ai-vault（或用 AI_VAULT_BIN 指向编译好的二进制）");
const NOT_INITIALIZED = tr("the local store is not initialised — run /vault init", "本地库还没初始化 — 运行 /vault init");
const LOCKED = "local vault is locked (no master password entered, or the window was cancelled)";

const dialogs = (ctx: Ctx): PromptHost => ctx as unknown as PromptHost;
const note = (ctx: Ctx, text: string, level: "info" | "warning" | "error" = "info"): void => ctx.ui.notify(text, level);

const describe = (error: unknown): string => (error instanceof Error ? error.message : String(error));

/** What a tool call hands back; every error path uses the same shape. */
interface ToolOutcome {
	content: { type: "text"; text: string }[];
	details: { ok?: boolean; denied?: boolean; item?: string; via?: string; count?: number };
	isError?: boolean;
}

type Failure = ToolOutcome;

const fail = (text: string, denied = false): Failure => ({
	content: [{ type: "text" as const, text }],
	details: { ok: false, ...(denied ? { denied: true } : {}) },
	isError: true,
});

/** Turn a CLI error into a tool result, dropping a token the CLI rejected. */
function failure(scope: Scope, error: unknown): Failure {
	if (error instanceof CliError && error.auth) {
		scope.token = undefined;
		return fail(LOCKED);
	}
	if (error instanceof CliError && error.denied) return fail(error.message, true);
	return fail(describe(error));
}

const setStatus = (ctx: Ctx, scope: Scope, suffix = ""): void => {
	const base = scope.token ? `vault:open(${scope.items})` : "vault:locked";
	ctx.ui.setStatus("ai-vault", `${base}${suffix}`);
};

/** End this binding's CLI session. The CLI deletes the token file. */
async function lockNow(scope: Scope): Promise<void> {
	const token = scope.token;
	scope.token = undefined;
	scope.epoch++;
	scope.items = 0;
	setSettingsToken(undefined);
	forgetSettings();
	if (!token || !cli.available) return;
	try {
		await cli.run(["lock", "--token", token]);
	} catch {
		/* the token dies on its own idle timeout */
	}
}

/** Args for a CLI call: this binding's token, or the machine-wide session. */
const tokenArgs = (scope: Scope): string[] => (scope.token ? ["--token", scope.token] : []);

/** Make this binding's unlock happen; never throws. */
async function ensureUnlocked(scope: Scope, ctx: Ctx, signal?: AbortSignal): Promise<boolean> {
	if (!cli.available) {
		note(ctx, CLI_MISSING, "error");
		return false;
	}
	if (scope.unlocking) return scope.unlocking;
	const epoch = scope.epoch;
	scope.unlocking = (async (): Promise<boolean> => {
		if (scope.token) {
			try {
				const status = await cli.json<StatusResult>(["status", "--token", scope.token], { signal });
				scope.items = status.items;
				scope.mode = status.mode;
				scope.auto = false;
				setSettingsToken(scope.token);
				return true;
			} catch (error) {
				if (!(error instanceof CliError) || !error.auth) {
					note(ctx, `ai-vault: ${describe(error)}`, "error");
					return false;
				}
				scope.token = undefined;
				if (/not initialized/i.test(error.message)) {
					note(ctx, NOT_INITIALIZED, "warning");
					return false;
				}
			}
		}
		// `never` mode keeps a machine-wide session: no token, no window. Ask the
		// CLI before opening anything, so that mode really is password-free.
		try {
			const status = await cli.json<StatusResult>(["status"], { signal });
			scope.items = status.items;
			scope.mode = status.mode;
			scope.auto = status.auto;
			setSettingsToken(undefined);
			return true;
		} catch (error) {
			if (error instanceof CliError && /not initialized/i.test(error.message)) {
				note(ctx, NOT_INITIALIZED, "warning");
				return false;
			}
			if (!(error instanceof CliError) || !error.auth) {
				note(ctx, `ai-vault: ${describe(error)}`, "error");
				return false;
			}
		}
		const attempt = async (password?: string): Promise<UnlockResult> => {
			const args = ["--requester", sessionLabel(ctx)];
			if (password !== undefined) args.push("--password-stdin");
			return cli.open<UnlockResult>("unlock", args, {
				stdin: password === undefined ? undefined : `${password}\n`,
				signal,
			});
		};
		try {
			let result: UnlockResult;
			try {
				result = await attempt();
			} catch (error) {
				if (!(error instanceof CliError) || !error.needsUi) throw error;
				const password = await promptSecret(dialogs(ctx), tr("ai-vault · unlock", "ai-vault · 解锁"), tr("local store master password", "本地库主密码"), signal);
				if (!password) {
					if (!signal?.aborted) note(ctx, tr("no master password entered (the window was cancelled, or there is no desktop/UI)", "没有输入主密码（窗口已取消，或没有桌面/界面）"), "warning");
					return false;
				}
				result = await attempt(password);
			}
			// /vault lock or a session switch ran while the window was open.
			if (epoch !== scope.epoch || signal?.aborted) {
				await cli.run(["lock", "--token", result.token]).catch(() => undefined);
				return false;
			}
			scope.mode = result.mode;
			scope.auto = result.mode === "never";
			// In `never` mode the CLI wrote the machine-wide session; keeping a
			// per-binding token would bring back a confirm window on every read.
			scope.token = result.mode === "never" ? undefined : result.token;
			scope.items = result.items;
			setSettingsToken(scope.token);
			return true;
		} catch (error) {
			if (error instanceof CliError && error.auth) {
				note(ctx, tr("ai-vault: wrong master password", "ai-vault: 主密码错误"), "error");
				return false;
			}
			if (error instanceof CliError && /not initialized/i.test(error.message)) {
				note(ctx, NOT_INITIALIZED, "warning");
				return false;
			}
			note(ctx, `ai-vault: ${describe(error)}`, "error");
			return false;
		}
	})().finally(() => {
		scope.unlocking = undefined;
	});
	return scope.unlocking;
}

// ---------------------------------------------------------------- local vault

const vaultListParams = Type.Object({});
function vaultListTool(scope: Scope): ToolDefinition<typeof vaultListParams, { ok?: boolean; count?: number }> {
	const tool: ToolDefinition<typeof vaultListParams, { ok?: boolean; count?: number }> = {
		name: "vault_list",
		label: "Vault: list local entries",
		description:
			"List entries in the machine-wide ai-vault store (metadata only: name, username, uris). " +
			"This is NOT Bitwarden — use bw_list to query Bitwarden live, and vault_import to copy Bitwarden logins into this store. " +
			"Use vault_get to read a secret; that opens a confirm window and the grant expires.",
		promptSnippet: "List local vault metadata; secrets need vault_get plus a user grant.",
		parameters: vaultListParams,
		async execute(_id, _params, signal, _onUpdate, ctx) {
			if (!(await ensureUnlocked(scope, ctx, signal))) return fail(LOCKED);
			try {
				const result = await cli.json<ListResult>(["list", "--token", scope.token!], { signal });
				scope.items = result.count;
				setStatus(ctx, scope);
				return {
					content: [{ type: "text" as const, text: JSON.stringify(result.items, null, 1) }],
					details: { count: result.count },
				};
			} catch (error) {
				return failure(scope, error);
			}
		},
	};
	return withTier(tool, "read");
}

const vaultGetParams = Type.Object({
	name: Type.String({ description: "Entry name, e.g. 'cloudcone-panel'" }),
	reason: Type.Optional(Type.String({ description: "Why this secret is needed (shown to the user in the confirm window)" })),
});
type VaultGetDetails = { ok?: boolean; denied?: boolean; item?: string; via?: string };

/**
 * The local vault is the first stop; Bitwarden is the fallback. A hit there is
 * offered to the user twice: read it this once, then optionally import it so
 * later reads never touch Bitwarden.
 */
async function bitwardenFallback(
	scope: Scope,
	ctx: Ctx,
	bw: BwState,
	name: string,
	reason: string | undefined,
	localMiss: string,
	signal?: AbortSignal,
): Promise<ToolOutcome> {
	const missing = localMiss;
	let hit;
	try {
		hit = await lookupBitwardenItem(bw, ctx, name, signal);
	} catch (error) {
		return fail(`${missing} — the Bitwarden lookup failed: ${describe(error)}`);
	}
	if (!hit) return fail(`${missing} — not in Bitwarden either${reason ? ` (reason: ${reason})` : ""}`);
	const draft = hit.draft;
	const secret = draft.type === "login" ? draft.password : (draft.data?.[ITEM_TYPES[draft.type].primary ?? ""] ?? "");

	const asValue = (via: string): ToolOutcome => ({
		content: [
			{
				type: "text" as const,
				text: JSON.stringify({ ...draft, password: secret ?? draft.password, via }, null, 1),
			},
		],
		details: { item: draft.name, via },
	});

	const importIt = async (): Promise<ToolOutcome> => {
		try {
			const saved = await cli.json<SaveResult>(["save", "--yes", ...tokenArgs(scope)], {
				stdin: JSON.stringify([draft]),
				signal,
			});
			scope.items += saved.count;
			setStatus(ctx, scope);
		} catch (error) {
			return fail(`found "${draft.name}" in Bitwarden but could not import it: ${describe(error)}`);
		}
		return asValue("imported-from-bitwarden");
	};

	const policy = (await getSettingsSafe(signal)).bitwarden.import;
	if (policy === "always") {
		// bitwarden.import = always: the user opted into pulling hits in silently.
		return importIt();
	}

	const allow = await confirmWindow(
		dialogs(ctx),
		tr("pi-ai-vault · found in Bitwarden", "pi-ai-vault · Bitwarden 里找到"),
		tr(
			`Not in the local store as "${forDialog(name)}", but Bitwarden has:\n${forDialog(hit.label)}\n\nRead it this once?`,
			`本地库没有「${forDialog(name)}」，Bitwarden 里有：\n${forDialog(hit.label)}\n\n读取这一次吗？`,
		),
		signal,
	);
	if (!allow) return fail(`user denied reading "${draft.name}" from Bitwarden — do not retry`, true);
	if (policy === "never") return asValue("bitwarden-once");

	const confirmed = await confirmWindow(
		dialogs(ctx),
		tr("pi-ai-vault · import into ai-vault", "pi-ai-vault · 导入到 ai-vault"),
		tr(
			`Write "${forDialog(draft.name)}" into ai-vault?\n\nAllow → read from the local store from now on (no password under the current unlock policy)\nDeny → use it once only; nothing is written to the local store`,
			`把「${forDialog(draft.name)}」写进 ai-vault 吗？\n\n允许 → 以后直接读本地库（按当前解锁模式，可能免密）\n拒绝 → 只用这一次，不写入本地库`,
		),
		signal,
	);
	return confirmed ? importIt() : asValue("bitwarden-once");
}

function vaultGetTool(scope: Scope, bw: BwState): ToolDefinition<typeof vaultGetParams, VaultGetDetails> {
	const viaOf = (stdout: string): string => {
		try {
			return (JSON.parse(stdout) as { via?: string }).via ?? "grant";
		} catch {
			return "grant";
		}
	};
	const tool: ToolDefinition<typeof vaultGetParams, VaultGetDetails> = {
		name: "vault_get",
		label: "Vault: read a secret (local first, Bitwarden second)",
		description:
			"Read one secret. The machine-wide ai-vault store is asked first; that is the vault the agent may use freely, and in `never` unlock mode it answers without any window. " +
			"If the entry is not local, Bitwarden is searched: the user is shown the hit, then asked whether to read it once or import it into ai-vault. " +
			"If the user denies, do not retry. Use bw_run when the value must never enter the chat.",
		promptSnippet: "Read a secret: local vault first, then Bitwarden (with an import offer).",
		parameters: vaultGetParams,
		async execute(_id, params, signal, _onUpdate, ctx) {
			if (!(await ensureUnlocked(scope, ctx, signal))) return fail(LOCKED);
			const base = ["get", params.name, ...(params.reason ? ["--reason", params.reason] : []), ...tokenArgs(scope)];
			try {
				try {
					const run = await cli.run([...base, "--json"], { signal });
					setStatus(ctx, scope, "·ok");
					return {
						content: [{ type: "text" as const, text: run.stdout.trim() }],
						details: { item: params.name, via: viaOf(run.stdout) },
					};
				} catch (error) {
					if (error instanceof CliError && error.needsUi === "confirm") {
						const sub = subagentId(ctx);
						const allowed = await confirmWindow(
							dialogs(ctx),
							tr("ai-vault · read local password", "ai-vault · 读取本地密码"),
							tr(`Entry: ${forDialog(params.name)}\nRequester: ${sub ? `subagent ${forDialog(sub, 32)}` : "main session"}\nReason: ${forDialog(params.reason ?? "(none given)", 120)}\n\n`, `条目: ${forDialog(params.name)}\n请求方: ${sub ? `子代理 ${forDialog(sub, 32)}` : "主会话"}\n原因: ${forDialog(params.reason ?? "(未说明)", 120)}\n\n`) +
								tr("Allowing lets the same requester read it again for 5 minutes. The password enters the conversation.", "允许后 5 分钟内同一请求方可再次读取。密码会进入对话。"),
							signal,
						);
						// Relaying is our privilege as the host: sign the answer under the
						// host secret so the CLI can tell us from the model's own bash.
						const token = scope.token ?? "";
						const approval = cli.host.approve(token, params.name, allowed);
						if (!approval) {
							return fail("cannot relay an approval: no host secret for this session — run /vault unlock again");
						}
						const run = await cli.run([...base, "--json", "--answer-stdin", "--approval", approval], {
							stdin: allowed ? "y\n" : "n\n",
							signal,
						});
						setStatus(ctx, scope, "·granted");
						return {
							content: [{ type: "text" as const, text: run.stdout.trim() }],
							details: { item: params.name, via: viaOf(run.stdout) },
						};
					}
					if (error instanceof CliError && /^no such entry/.test(error.message)) {
						return await bitwardenFallback(scope, ctx, bw, params.name, params.reason, error.message, signal);
					}
					throw error;
				}
			} catch (error) {
				if (error instanceof CliError && error.denied) setStatus(ctx, scope, "·denied");
				return failure(scope, error);
			}
		},
	};
	return tool;
}

const vaultAddParams = Type.Object({
	name: Type.String({ description: "Entry name to create or update, e.g. 'github'" }),
	type: Type.Optional(
		Type.String({
			description:
				"Item type, as in Bitwarden: login (default), note, card, identity, sshkey, bankaccount, driverslicense, passport. " +
				"A note's content goes in `notes`.",
		}),
	),
	username: Type.Optional(Type.String({ description: "Login: account username. Omit to let the user type it in a dialog." })),
	uri: Type.Optional(Type.String({ description: "Login: site or host URI" })),
	notes: Type.Optional(Type.String({ description: "Notes shared by every type. For a `note` entry this is its content." })),
	fields: Type.Optional(
		Type.Record(
			Type.String(),
			Type.Optional(Type.String()),
			{
				description:
					"The type's own fields by Bitwarden's names (card: cardholderName, brand, number, expMonth, expYear, code; " +
					"sshkey: publicKey, privateKey, keyFingerprint; identity: firstName, lastName, email, …). " +
					"Give a non-secret field as text; give a secret field (password, code, number, privateKey, pin, ssn…) " +
					"as null/undefined so the user types it in a dialog. NEVER put a secret value here.",
			},
		),
	),
});
function vaultAddTool(scope: Scope): ToolDefinition<typeof vaultAddParams, { ok?: boolean; item?: string }> {
	const tool: ToolDefinition<typeof vaultAddParams, { ok?: boolean; item?: string }> = {
		name: "vault_add",
		label: "Vault: store a secret via dialog",
		description:
			"Create or update an entry of any Bitwarden type in the machine-wide ai-vault store (login, note, card, identity, sshkey, " +
			"bankaccount, driverslicense, passport). You supply the name, the type and its non-secret fields. " +
			"Secret fields (password, card number and code, private key, PIN, SSN…) are typed by the user in a desktop window: " +
			"leave them empty, they are NEVER accepted from you and NEVER returned. Do not ask the user to paste a secret into the chat.",
		promptSnippet: "Save a local vault entry; the user types the password in a window.",
		parameters: vaultAddParams,
		async execute(_id, params, signal, _onUpdate, ctx) {
			const kind = parseItemType(params.type);
			if (!kind) {
				return fail(`unknown type "${params.type}" — login, note, card, identity, sshkey, bankaccount, driverslicense, passport`);
			}
			// A secret field the model filled in is refused rather than stored:
			// only the user types secrets, in a dialog.
			const fields: Record<string, string | undefined> = {};
			for (const [field, value] of Object.entries(params.fields ?? {})) {
				if (value !== undefined && value !== "" && isSecretField(kind, field)) {
					return fail(`"${field}" is a secret field: leave it empty so the user types it in a dialog`);
				}
				fields[field] = value === "" ? undefined : value;
			}
			const result = await saveLocalEntry(scope, ctx, {
				name: params.name,
				type: kind,
				username: params.username,
				uri: params.uri,
				notes: params.notes,
				fields,
				signal,
			});
			const ok = result.startsWith("saved ");
			return {
				content: [{ type: "text" as const, text: result }],
				details: ok ? { item: params.name } : { ok: false },
				isError: ok ? undefined : true,
			};
		},
	};
	return withTier(tool, "write");
}

const vaultImportParams = Type.Object({
	search: Type.Optional(
		Type.String({ description: "Only import items whose name, username, or URI contains this text. Omit for every login that has a password." }),
	),
});
function vaultImportTool(scope: Scope, bw: BwState): ToolDefinition<typeof vaultImportParams, { ok?: boolean; count?: number }> {
	const tool: ToolDefinition<typeof vaultImportParams, { ok?: boolean; count?: number }> = {
		name: "vault_import",
		label: "Vault: import from Bitwarden",
		description:
			"Copy Bitwarden login items into the machine-wide encrypted ai-vault store. " +
			"Asks the user to approve in a window, then stores passwords locally. Does not return secret values. " +
			"Use bw_list to query Bitwarden without copying it. Same-name local entries are updated.",
		promptSnippet: "Import Bitwarden logins into the local vault after the user confirms.",
		parameters: vaultImportParams,
		async execute(_id, params, signal, _onUpdate, ctx) {
			const result = await importBitwarden(scope, ctx, bw, params.search, signal);
			return {
				content: [{ type: "text" as const, text: result.text }],
				details: { ok: result.ok, count: result.count },
				isError: result.ok ? undefined : true,
			};
		},
	};
	return withTier(tool, "write");
}

interface SaveRequest {
	name?: string;
	type?: ItemType;
	username?: string;
	uri?: string;
	notes?: string;
	/** The type's own fields, NAME=VALUE; a value of `undefined` means "typed in a dialog". */
	fields?: Record<string, string | undefined>;
	signal?: AbortSignal;
}

/** Save one entry, following the CLI's dialog windows through the host UI. */
async function saveLocalEntry(scope: Scope, ctx: Ctx, req: SaveRequest): Promise<string> {
	if (!(await ensureUnlocked(scope, ctx, req.signal))) return LOCKED;
	let name = req.name?.trim() ?? "";
	if (!name) {
		const entered = await promptText(dialogs(ctx), tr("ai-vault · new entry", "ai-vault · 新条目"), tr("name", "名称"), req.signal);
		name = entered?.trim() ?? "";
	}
	if (!name) return "cancelled: no entry name";

	const kind = req.type ?? "login";
	const args = ["add", "--name", name, "--type", kind, "--token", scope.token!];
	if (req.username !== undefined) args.push("--username", req.username);
	if (req.uri?.trim()) args.push("--uri", req.uri.trim());
	if (req.notes?.trim()) args.push("--notes", req.notes.trim());
	const secrets = new Map<string, string>();
	const shown: string[] = [];
	for (const [field, value] of Object.entries(req.fields ?? {})) {
		if (value === undefined) shown.push(`${field} ••••`);
		else {
			args.push("--field", `${field}=${value}`);
			shown.push(`${field} ${isSecretField(kind, field) ? "••••" : forDialog(value, 120)}`);
		}
	}
	const flush = () => {
		// --secret args are re-added on every attempt: the CLI is stateless.
		for (let i = args.length - 1; i >= 0; i--) if (args[i] === "--secret") args.splice(i, 2);
		for (const [field, value] of secrets) args.push("--secret", `${field}=${value}`);
	};
	for (let attempt = 0; attempt < 8; attempt++) {
		flush();
		try {
			const run = await cli.run([...args, "--json"], { signal: req.signal });
			const saved = JSON.parse(run.stdout) as { item?: string; created?: boolean; type?: string };
			if (saved.created) scope.items += 1;
			setStatus(ctx, scope);
			return `saved "${saved.item ?? name}" as a ${saved.type ?? kind} (hidden fields entered in dialogs, not shown)`;
		} catch (error) {
			if (!(error instanceof CliError) || !error.needsUi) {
				if (error instanceof CliError && error.auth) scope.token = undefined;
				return error instanceof CliError && error.denied ? error.message : `ai-vault: ${describe(error)}`;
			}
			if (error.needsUi === "confirm") {
				const meta = [
					...shown,
					req.username?.trim() ? tr(`Username: ${forDialog(req.username, 60)}`, `用户名: ${forDialog(req.username, 60)}`) : "",
					req.uri?.trim() ? `URI: ${forDialog(req.uri, 120)}` : "",
					req.notes?.trim() ? tr(`Notes: ${forDialog(req.notes, 120)}`, `备注: ${forDialog(req.notes, 120)}`) : "",
				]
					.filter(Boolean)
					.join("\n");
				const ok = await confirmWindow(
					dialogs(ctx),
					tr("ai-vault · save to local store", "ai-vault · 保存到本地库"),
					tr(
						`Save the ${kind} entry "${forDialog(name)}".${meta ? `\n${meta}` : ""}\nA window opens next for each hidden field. Nothing enters the conversation.`,
						`保存${kind}条目「${forDialog(name)}」。${meta ? `\n${meta}` : ""}\n接下来每个隐藏字段弹一个窗口。密码不会进入对话。`,
					),
					req.signal,
				);
				if (!ok) return `user denied saving "${name}"`;
				args.push("--yes");
				continue;
			}
			if (error.needsUi === "text") {
				const entered = await promptText(dialogs(ctx), `ai-vault · ${name}`, tr("username (optional)", "用户名（可留空）"), req.signal);
				if (entered === undefined) return "cancelled";
				args.push("--username", entered);
				continue;
			}
			// needsUi === "password": one hidden field at a time, named by the CLI.
			const field = error.field ?? ITEM_TYPES[kind].primary ?? "password";
			const password = await promptSecret(dialogs(ctx), tr("ai-vault · password", "ai-vault · 密码"), `${name} · ${field}`, req.signal);
			if (!password) return "cancelled: no password entered";
			secrets.set(field, password);
		}
	}
	return "cancelled: the save dialog did not settle";
}

async function importBitwarden(
	scope: Scope,
	ctx: Ctx,
	bw: BwState,
	search: string | undefined,
	signal?: AbortSignal,
): Promise<{ text: string; ok: boolean; count: number }> {
	if (!(await ensureUnlocked(scope, ctx, signal))) return { text: LOCKED, ok: false, count: 0 };
	let meta: BitwardenMeta[];
	try {
		meta = await queryBitwarden(bw, ctx, search, signal);
	} catch (error) {
		return { text: `Bitwarden: ${describe(error)}`, ok: false, count: 0 };
	}
	if (meta.length === 0) {
		return { text: search ? `no Bitwarden items match "${search}"` : "Bitwarden vault has no items", ok: false, count: 0 };
	}
	const shown = meta
		.slice(0, 15)
		.map((item) => `• ${item.name}${item.username ? `  user:${item.username}` : ""}${item.uri ? `  ${item.uri}` : ""}`)
		.join("\n");
	const more = meta.length > 15 ? tr(`\n… 还yes ${meta.length - 15} 条`, `\n… 还有 ${meta.length - 15} 条`) : "";
	const allowed = await confirmWindow(
		dialogs(ctx),
		tr("ai-vault · import from Bitwarden", "ai-vault · 从 Bitwarden 导入"),
		tr(`Matched ${meta.length} 条。其中带密码的登录项会写入本地加密库，同名条目会被更新。\n\n${shown}${more}\n\nImport?`, `匹配 ${meta.length} 条。其中带密码的登录项会写入本地加密库，同名条目会被更新。\n\n${shown}${more}\n\n允许导入？`),
		signal,
	);
	if (!allowed) return { text: "user denied the Bitwarden import", ok: false, count: 0 };
	let drafts;
	try {
		drafts = await pullBitwardenItems(bw, ctx, search, signal);
	} catch (error) {
		return { text: `Bitwarden: ${describe(error)}`, ok: false, count: 0 };
	}
	if (drafts.length === 0) {
		return { text: "nothing matched; nothing imported", ok: false, count: 0 };
	}
	try {
		const saved = await cli.json<SaveResult>(["save", "--yes", "--token", scope.token!], {
			stdin: JSON.stringify(drafts),
			signal,
		});
		scope.items += saved.count;
		setStatus(ctx, scope);
		const listed = saved.names.slice(0, 40).join(", ");
		const extra = saved.names.length > 40 ? ` … +${saved.names.length - 40}` : "";
		return {
			text: `imported ${saved.count} login item(s) into the local vault: ${listed}${extra}`,
			ok: true,
			count: saved.count,
		};
	} catch (error) {
		return { text: `ai-vault: ${describe(error)}`, ok: false, count: 0 };
	}
}

// ---------------------------------------------------------------- commands

const HELP = [
	tr("/vault init                        create the machine-wide encrypted store (a dialog sets the master password)", "/vault init                        创建全机共享的本地加密库（弹出窗口设置主密码）"),
	tr("/vault unlock | lock               unlock / lock (clears this session's grants)", "/vault unlock | lock               解锁 / 锁定（清空本会话的授权）"),
	tr("/vault mode [never|time|session]   show/switch the unlock policy (switching needs the master password)", "/vault mode [never|time|session]   查看/切换解锁模式（切换要主密码）"),
	tr("/vault confirm [off|on]           a window per read while unlocked (off asks the master password)", "/vault confirm [off|on]           解锁后每次读取是否弹确认窗（关要主密码）"),
	tr("/vault settings [key value]        show/change settings (vault.unlock, bitwarden.*, ente.* …)", "/vault settings [键 值]            查看/修改设置（vault.unlock、bitwarden.*、ente.* …）"),
	tr("/vault ente-key                    save Ente's ENTE_CLI_VAULT_KEY (no keychain, no login)", "/vault ente-key                    保存 ente 的 ENTE_CLI_VAULT_KEY（免钥匙串/免登录）"),
	tr("/vault status                      state and grants left", "/vault status                      状态与授权剩余时间"),
	tr("/vault list                        local entry metadata", "/vault list                        本地条目元数据"),
	tr("/vault add [name]                  add a local entry (username and password typed in a dialog)", "/vault add [名称]                  新增本地条目（用户名、密码在弹窗里输入）"),
	tr('/vault remove <name>               delete an entry (quote names with spaces: "GitHub (2)")', '/vault remove <名称>               删除本地条目（带空格的名称加引号："GitHub (2)"）'),
	tr("/vault grant <name> [minutes]      a standing read grant (default 5 min, max 60)", "/vault grant <名称> [分钟]         手动授权读取（默认 5 分钟，上限 60）"),
	tr("/vault revoke <name|all>           revoke grants", "/vault revoke <名称|all>           撤销授权"),
	tr("/vault audit [n]                   the last n audit lines (default 30)", "/vault audit [n]                   最近 n 条审计（默认 30）"),
	tr("/vault import <bitwarden.json>     import an unencrypted Bitwarden JSON export", "/vault import <bitwarden.json>     从 Bitwarden 未加密 JSON 导出导入"),
	tr("/vault import-bw [search]          import logins straight from the bw CLI (asks first)", "/vault import-bw [搜索词]          直接从 bw CLI 导入登录项（先弹窗确认）"),
	tr("/bw status|unlock|lock|clear       the live Bitwarden session (see the bw_* tools)", "/bw status|unlock|lock|clear       在线 Bitwarden 会话（见 bw_* 工具）"),
].join("\n");

/** Split a command line into words; quotes keep a name such as "GitHub (2)" intact. */
function words(args: string): string[] {
	const out: string[] = [];
	for (const m of args.trim().matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)) out.push(m[1] ?? m[2] ?? m[3] ?? "");
	return out;
}

async function initStore(scope: Scope, ctx: Ctx, label: string): Promise<void> {
	if (!cli.available) {
		note(ctx, CLI_MISSING, "error");
		return;
	}
	const finish = (result: UnlockResult): void => {
		scope.token = result.token;
		scope.items = 0;
		setStatus(ctx, scope);
		note(ctx, tr(`ai-vault created: ${cli.dir}/store.json`, `ai-vault 已创建: ${cli.dir}/store.json`));
	};
	try {
		finish(await cli.open<UnlockResult>("init", ["--requester", label]));
		return;
	} catch (error) {
		if (!(error instanceof CliError)) {
			note(ctx, `ai-vault: ${describe(error)}`, "error");
			return;
		}
		if (!error.needsUi) {
			note(ctx, `ai-vault: ${error.message}`, "warning");
			return;
		}
	}
	const pass = await promptSecret(dialogs(ctx), tr("ai-vault · set master password", "ai-vault · 创建主密码"), tr("at least 8 characters", "至少 8 位"));
	if (!pass || pass.length < 8) {
		note(ctx, tr("cancelled, or the password is shorter than 8 characters", "已取消，或密码短于 8 位"), "warning");
		return;
	}
	const again = await promptSecret(dialogs(ctx), tr("ai-vault · confirm master password", "ai-vault · 确认主密码"), tr("type it again", "再输入一次"));
	if (again !== pass) {
		note(ctx, tr("the two passwords do not match; cancelled", "两次主密码不一致，已取消"), "warning");
		return;
	}
	try {
		finish(await cli.open<UnlockResult>("init", ["--requester", label, "--password-stdin"], { stdin: `${pass}\n` }));
	} catch (error) {
		note(ctx, `ai-vault: ${error instanceof CliError ? error.message : describe(error)}`, "error");
	}
}

function settingsText(s: Settings): string {
	const persisted = s.bitwarden.persisted
		? s.bitwarden.expiresAt
			? tr(`yes（${Math.max(0, Math.round((s.bitwarden.expiresAt - Date.now()) / 60_000))} 分钟后过期）`, `有（${Math.max(0, Math.round((s.bitwarden.expiresAt - Date.now()) / 60_000))} 分钟后过期）`)
			: tr("yes (no expiry)", "有（不过期）")
		: tr("no", "无");
	return [
		`vault.unlock: ${s.vault.unlock}    (never | time | session)`,
		tr(`vault.hours: ${s.vault.hours}    (time mode)`, `vault.hours: ${s.vault.hours}    (time 模式用)`),
		tr(`vault machine-wide session: ${s.vault.auto ? "yes (no password)" : "no"}`, `vault 机器级会话: ${s.vault.auto ? "有（免密）" : "无"}`),
		`bitwarden.unlock: ${s.bitwarden.unlock}    (never | time | session)`,
		`bitwarden.hours: ${s.bitwarden.hours}`,
		`bitwarden.import: ${s.bitwarden.import}    (ask | always | never)`,
		tr(`bitwarden persisted session: ${persisted}`, `bitwarden 已落盘的会话: ${persisted}`),
		`ente.unlock: ${s.ente.unlock}    (never | time | session)`,
		`ente.hours: ${s.ente.hours}`,
		tr(`ente persisted key: ${s.ente.persisted ? "yes" : "no"}`, `ente 已落盘的密钥: ${s.ente.persisted ? "有" : "无"}`),
	].join("\n");
}

function commandHandler(scope: Scope, bw: BwState) {
	return async (args: string, ctx: ExtensionCommandContext): Promise<void> => {
		const [sub = "status", ...rest] = words(args);
		const label = sessionLabel(ctx);

		switch (sub) {
			case "help": {
				note(ctx, HELP);
				return;
			}
			case "init": {
				await initStore(scope, ctx, label);
				return;
			}
			case "unlock": {
				if (await ensureUnlocked(scope, ctx)) setStatus(ctx, scope);
				return;
			}
			case "lock": {
				await lockNow(scope);
				setStatus(ctx, scope);
				note(ctx, tr("the local store is locked; grants cleared", "本地库已锁定，授权已清空"));
				return;
			}
			case "status": {
				try {
					const status = await cli.json<StatusResult>(["status", ...tokenArgs(scope)]);
					scope.items = status.items;
					scope.mode = status.mode;
					scope.auto = status.auto;
					setStatus(ctx, scope);
					const expiry = status.expiresAt
						? `${Math.max(0, Math.round((status.expiresAt - Date.now()) / 1000))}s`
						: "never";
					const how =
						status.mode === "never"
							? tr("never (no password)", "never（免密）")
							: status.mode === "time"
								? tr(`time (the password every ${status.hours}h)`, `time（每 ${status.hours}h 要一次密码）`)
								: tr("session (once per session)", "session（每个会话一次）");
					const lines = [
						`store: ${cli.dir}/store.json`,
						`session: ${status.requester}`,
						"state: unlocked",
						`mode: ${how}`,
						`items: ${status.items}`,
						`expires: ${expiry}`,
					];
					for (const [name, grant] of Object.entries(status.grants)) {
						lines.push(`grant: ${name} (${Math.ceil(grant.leftMs / 1000)}s left)`);
					}
					note(ctx, lines.join("\n"));
				} catch (error) {
					scope.token = undefined;
					note(
						ctx,
						[
							`store: ${cli.dir}/store.json`,
							`session: ${label}`,
							"state: locked",
							`ai-vault: ${describe(error)}`,
						].join("\n"),
						"warning",
					);
					setStatus(ctx, scope);
				}
				return;
			}
			case "ente-key": {
				// Ente's unattended key: generated by `ente vault key generate`.
				// Saved sealed, so `ente.unlock = never | time` can use it.
				const key = await promptSecret(dialogs(ctx), tr("ai-vault · Ente key", "ai-vault · Ente 密钥"), tr("the key printed by ente vault key generate", "ente vault key generate 输出的密钥"));
				if (!key) {
					note(ctx, tr("cancelled", "已取消"), "warning");
					return;
				}
				try {
					const args = ["ente-session", "put"];
					await cli.run(args, { stdin: key });
					forgetSettings();
					note(ctx, tr("saved (sealed). You can now set /vault settings ente.unlock never", "已保存（封存）。现在可以设置 /vault settings ente.unlock never"));
				} catch (error) {
					note(ctx, `ai-vault: ${describe(error)}`, "error");
				}
				return;
			}
			case "confirm": {
				// /vault confirm            show
				// /vault confirm off|on     turn the per-read window off (asks the master password) / on
				const [arg] = rest;
				if (!arg) {
					try {
						const current = await cli.json<Settings>(["settings", ...tokenArgs(scope)]);
						note(ctx, `vault.confirm: ${current.vault.confirm}${current.vault.confirm ? tr("  (a window per read while unlocked)", "  （解锁后每次读取弹确认窗）") : tr("  (the unlock is the approval; reads are audited)", "  （解锁即授权；读取仍记审计）")}`);
					} catch (error) {
						note(ctx, `ai-vault: ${describe(error)}`, "error");
					}
					return;
				}
				const value = arg.toLowerCase();
				if (!["off", "on", "false", "true"].includes(value)) {
					note(ctx, tr("usage: /vault confirm [off|on]", "用法: /vault confirm [off|on]"), "warning");
					return;
				}
				const turnOff = value === "off" || value === "false";
				try {
					const run = await cli.withPassword(["settings", "vault.confirm", turnOff ? "false" : "true", ...tokenArgs(scope)], () =>
						promptSecret(dialogs(ctx), tr("ai-vault · master password", "ai-vault · 主密码"), tr("turn off the per-read confirmation", "关闭每次读取的确认窗")),
					);
					forgetSettings();
					const updated = JSON.parse(run.stdout) as Settings;
					note(
						ctx,
						updated.vault.confirm
							? tr("vault.confirm is on: every read opens a confirm window.", "vault.confirm 已开：每次读取弹确认窗。")
							: tr(
									"vault.confirm is off: while a session is unlocked, reads return without a window. Each read is still written to the audit log. Turning it back on: /vault confirm on",
									"vault.confirm 已关：会话解锁期间读取不再弹窗。每次读取仍写审计。重新打开：/vault confirm on",
								),
					);
				} catch (error) {
					note(ctx, `ai-vault: ${error instanceof CliError && error.denied ? tr("cancelled", "已取消") : describe(error)}`, "warning");
				}
				return;
			}
			case "settings": {
				const [key, ...valueParts] = rest;
				const value = valueParts.join(" ").trim();
				try {
					if (!key) {
						note(ctx, settingsText(await cli.json<Settings>(["settings", ...tokenArgs(scope)])));
						return;
					}
					if (!value) {
						const one = await cli.json<{ key: string; value: string }>(["settings", key, ...tokenArgs(scope)]);
						note(ctx, `${one.key}: ${one.value}`);
						return;
					}
					// `vault.unlock` opens its own password window (or answers
					// needs-ui); the other keys do not prompt at all.
					const run = await cli.withPassword(["settings", key, value, ...tokenArgs(scope)], () =>
						promptSecret(dialogs(ctx), tr("ai-vault · master password", "ai-vault · 主密码"), tr("changing the unlock policy needs verification", "改变解锁模式需要验证")),
					);
					forgetSettings();
					const updated = JSON.parse(run.stdout) as Settings;
					if (key.startsWith("vault.")) await lockNow(scope);
					note(ctx, settingsText(updated));
				} catch (error) {
					note(ctx, `ai-vault: ${error instanceof CliError && error.denied ? tr("cancelled", "已取消") : describe(error)}`, "warning");
				}
				return;
			}
			case "mode": {
				const [sub, hoursArg] = rest;
				if (!sub || sub === "get" || sub === "status") {
					try {
						const current = await cli.json<{ mode: string; hours: number; auto: boolean }>(["mode"]);
						note(
							ctx,
							[
								`mode: ${current.mode}`,
								tr(`hours: ${current.hours}(time mode)`, `hours: ${current.hours}（time 模式用）`),
								`machine-wide session: ${current.auto ? tr("yes (no password)", "yes（免密）") : "no"}`,
								"",
								tr("/vault mode never|time|session [hours]   switch (needs the master password)", "/vault mode never|time|session [小时]   切换（要主密码）"),
							].join("\n"),
						);
					} catch (error) {
						note(ctx, `ai-vault: ${describe(error)}`, "error");
					}
					return;
				}
				if (!["never", "time", "session", "no-password"].includes(sub)) {
					note(ctx, tr("usage: /vault mode [never|time|session] [hours]", "用法: /vault mode [never|time|session] [小时]"), "warning");
					return;
				}
				const args = ["mode", "set", sub];
				if (hoursArg) args.push("--hours", hoursArg);
				try {
					const run = await cli.withPassword(args, () => promptSecret(dialogs(ctx), tr("ai-vault · master password", "ai-vault · 主密码"), tr("switch the unlock policy", "切换解锁模式")));
					const result = JSON.parse(run.stdout) as { mode: UnlockModeName; hours: number; auto: boolean };
					forgetSettings();
					await lockNow(scope);
					scope.mode = result.mode;
					scope.auto = result.auto;
					setStatus(ctx, scope);
					const how =
						result.mode === "never"
							? tr("no password from now on (the key is on disk: anything that can read your files can read every password in the store)", "以后免密（密钥已写盘，任何能读你文件的程序都能读到库里的密码）")
							: result.mode === "time"
								? tr(`the password is asked again every ${result.hours} hours from now on`, `以后每 ${result.hours} 小时要一次密码`)
								: tr("the password is asked once per session from now on", "以后每个会话要一次密码");
					note(ctx, `mode → ${result.mode}，${how}`);
				} catch (error) {
					note(ctx, `ai-vault: ${error instanceof CliError && error.denied ? tr("cancelled", "已取消") : describe(error)}`, "warning");
				}
				return;
			}
			case "list": {
				if (!(await ensureUnlocked(scope, ctx))) return;
				try {
					const result = await cli.json<ListResult>(["list", "--token", scope.token!]);
					scope.items = result.count;
					const rows = result.items.map((i) => `${i.name}\t${i.username ?? ""}\t${i.uris[0] ?? ""}`);
					note(ctx, rows.join("\n") || "(empty)");
				} catch (error) {
					note(ctx, `ai-vault: ${describe(error)}`, "warning");
				}
				return;
			}
			case "add": {
				// /vault add [type:]name [field=value ...] [field] — a bare
				// `field` is typed in a dialog. /vault add card:Visa brand=Visa code
				const [first, ...pairs] = rest;
				let type: ItemType | undefined;
				let name = first ?? "";
				const m = /^([a-z]+):(.+)$/.exec(first ?? "");
				if (m) {
					const parsed = parseItemType(m[1]);
					if (parsed) {
						type = parsed;
						name = m[2] ?? name;
					}
				}
				const fields: Record<string, string | undefined> = {};
				let notes: string | undefined;
				for (const pair of pairs) {
					const eq = pair.indexOf("=");
					const key = eq < 0 ? pair : pair.slice(0, eq);
					const value = eq < 0 ? "" : pair.slice(eq + 1);
					if (!key) continue;
					if (key === "notes" || key === "note") notes = value;
					else fields[key] = value === "" ? undefined : value;
				}
				const text = await saveLocalEntry(scope, ctx, { name: name.trim() || undefined, type, fields, notes });
				note(ctx, text, text.startsWith("saved ") ? "info" : "warning");
				return;
			}
			case "remove": {
				const name = rest.join(" ");
				if (!(await ensureUnlocked(scope, ctx))) return;
				if (!name) {
					note(ctx, tr("usage: /vault remove <name>", "用法: /vault remove <名称>"), "warning");
					return;
				}
				const args = ["remove", name, "--token", scope.token!];
				try {
					const result = await cli.json<RemovingResult>(args);
					if (result.removed) scope.items = Math.max(0, scope.items - 1);
					setStatus(ctx, scope);
					note(ctx, result.removed ? "removed" : "not found", result.removed ? "info" : "warning");
				} catch (error) {
					if (!(error instanceof CliError) || error.needsUi !== "confirm") {
						note(ctx, `ai-vault: ${describe(error)}`, error instanceof CliError && error.denied ? "warning" : "error");
						return;
					}
					const sure = await confirmWindow(dialogs(ctx), tr("ai-vault · delete entry", "ai-vault · 删除条目"), tr(`Delete "${forDialog(name)}"? This cannot be undone.`, `删除「${forDialog(name)}」？删除后无法恢复。`));
					if (!sure) return;
					try {
						const result = await cli.json<RemovingResult>([...args, "--yes"]);
						if (result.removed) scope.items = Math.max(0, scope.items - 1);
						setStatus(ctx, scope);
						note(ctx, result.removed ? "removed" : "not found", result.removed ? "info" : "warning");
					} catch (inner) {
						note(ctx, `ai-vault: ${describe(inner)}`, "error");
					}
				}
				return;
			}
			case "grant": {
				const last = rest.at(-1) ?? "";
				// A single numeric token is the entry name ("/vault grant 123");
				// minutes are only read when a name comes before them.
				const minutes = rest.length > 1 && /^\d+$/.test(last) ? rest.pop() : undefined;
				const name = rest.join(" ");
				if (!(await ensureUnlocked(scope, ctx)) || !name) {
					note(ctx, tr("unlock first; usage: /vault grant <name> [minutes] (quote names with spaces)", "先解锁；用法: /vault grant <名称> [分钟]（带空格的名称加引号）"), "warning");
					return;
				}
				const args = ["grant", name, "--token", scope.token!];
				if (minutes) args.push("--minutes", minutes);
				try {
					// A standing grant costs the master password, like a mode change.
					const run = await cli.withPassword(args, () =>
						promptSecret(dialogs(ctx), tr("ai-vault · grant read", "ai-vault · 授权读取"), tr("master password (lets this entry be read without confirmation for N minutes)", "主密码（给这条条目 N 分钟免确认）")),
					);
					const result = JSON.parse(run.stdout) as { name: string; minutes: number };
					setStatus(ctx, scope, "·granted");
					note(ctx, `granted "${result.name}" for ${result.minutes}m`);
				} catch (error) {
					note(ctx, `ai-vault: ${describe(error)}`, "warning");
				}
				return;
			}
			case "revoke": {
				if (!(await ensureUnlocked(scope, ctx))) return;
				const target = rest[0] === "all" ? "all" : rest.join(" ").trim();
				const args = ["revoke", "--token", scope.token!];
				if (target === "all") args.push("--all");
				else if (target) args.push(target);
				else {
					note(ctx, tr("usage: /vault revoke <name|all>", "用法: /vault revoke <名称|all>"), "warning");
					return;
				}
				try {
					await cli.json(args);
					setStatus(ctx, scope);
					note(ctx, "revoked");
				} catch (error) {
					note(ctx, `ai-vault: ${describe(error)}`, "warning");
				}
				return;
			}
			case "audit": {
				const asked = Number(rest[0] ?? 30);
				const n = Number.isFinite(asked) && asked > 0 ? Math.min(Math.trunc(asked), 1000) : 30;
				try {
					const result = await cli.json<AuditResult>(["audit", String(n)]);
					const rows = result.entries.map(
						(e) => `${e.ts} ${e.session} ${e.event}${e.item ? ` ${e.item}` : ""}${e.reason ? ` (${e.reason})` : ""}`,
					);
					note(ctx, rows.join("\n") || "(no entries)");
				} catch (error) {
					note(ctx, `ai-vault: ${describe(error)}`, "error");
				}
				return;
			}
			case "import": {
				const path = rest.join(" ");
				if (!path) {
					note(ctx, tr("usage: /vault import <bitwarden-export.json>", "用法: /vault import <bitwarden-export.json>"), "warning");
					return;
				}
				if (!(await ensureUnlocked(scope, ctx))) return;
				const args = ["import", path, "--token", scope.token!];
				try {
					const result = await cli.json<SaveResult>(args);
					scope.items += result.count;
					setStatus(ctx, scope);
					note(ctx, `imported ${result.count} login items`);
				} catch (error) {
					if (!(error instanceof CliError) || error.needsUi !== "confirm") {
						note(ctx, `ai-vault: ${describe(error)}`, error instanceof CliError && error.denied ? "warning" : "error");
						return;
					}
					const sure = await confirmWindow(
						dialogs(ctx),
						tr("ai-vault · import from Bitwarden", "ai-vault · 从 Bitwarden 导入"),
						tr(`Import ${path} Bitwarden logins? Same-name entries are updated.`, `导入 ${path} 里的 Bitwarden 登录项？同名条目会被更新。`),
					);
					if (!sure) return;
					try {
						const result = await cli.json<SaveResult>([...args, "--yes"]);
						scope.items += result.count;
						setStatus(ctx, scope);
						note(ctx, `imported ${result.count} login items`);
					} catch (inner) {
						note(ctx, `ai-vault: ${describe(inner)}`, "error");
					}
				}
				return;
			}
			case "import-bw": {
				const search = rest.join(" ").trim() || undefined;
				const result = await importBitwarden(scope, ctx, bw, search);
				note(ctx, result.text, result.ok ? "info" : "warning");
				return;
			}
			default: {
				note(ctx, `unknown subcommand "${sub}"\n${HELP}`, "warning");
			}
		}
	};
}

export default function aiVault(pi: ExtensionAPI): void {
	const omp = isOmpHost(pi);
	const scope: Scope = { token: undefined, epoch: 0, items: 0, unlocking: undefined };
	const bw = newBwState();
	pi.registerTool(vaultListTool(scope));
	pi.registerTool(vaultGetTool(scope, bw));
	pi.registerTool(vaultAddTool(scope));
	pi.registerTool(vaultImportTool(scope, bw));
	registerBitwarden(pi, bw, omp);
	// Ente Auth: the `ente` CLI keeps its own login; these tools only read codes.
	registerEnte(pi);
	pi.registerCommand("vault", {
		description: tr("local secret store + Bitwarden import (/vault help)", "本地密码库 + Bitwarden 导入（/vault help）"),
		handler: commandHandler(scope, bw),
	});
	// A transcript that starts fresh (/new, /fork) must not inherit this unlock
	// or its grants. A /resume keeps them: same process, same user.
	onSessionLeave(pi, omp, (reason) => {
		if (reason === "resume") return;
		void lockNow(scope);
	});
}

/** Exported for tests: the shared grant window. */
export const grantMs = GRANT_MS_DEFAULT;
