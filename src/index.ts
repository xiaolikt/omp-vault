/**
 * omp-vault — local encrypted vault + live Bitwarden, for omp and pi.
 *
 * Local store (~/.omp/vault): ChaCha20-Poly1305 at rest. The master password,
 * new secrets, and read grants open a desktop window when a display is
 * available.
 *
 * Access is per binding. omp rebinds the extension factory for every session
 * and subagent, and each binding carries its own Scope: a subagent, or a
 * second session in the same process, cannot read on an unlock or a grant that
 * is not its own, and leaving a session (/new, /fork, exit) drops only that
 * binding's access.
 *
 * Bitwarden (bw CLI): bw_list / bw_run / bw_clipboard / bw_reveal (+ bw_inject
 * on pi) query the live vault; vault_import copies login items into the local
 * store after a confirm window.
 */
import type { ExtensionAPI, ExtensionCommandContext, ExtensionToolContext, ToolDefinition } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { appendAudit, readAudit } from "./audit.js";
import { newBwState, pullBitwardenLogins, queryBitwarden, registerBitwarden, type BitwardenMeta, type BwState } from "./bitwarden.js";
import { bitwardenLogins, type LoginDraft } from "./import-map.js";
import { isOmpHost, onSessionLeave, sessionLabel, subagentId, withTier } from "./host.js";
import { confirmWindow, promptSecret, promptText, type PromptHost } from "./prompt.js";
import { Vault, type VaultItem } from "./store.js";

const GRANT_MS_DEFAULT = 5 * 60_000;
const GRANT_MS_MAX = 60 * 60_000;
const AUTO_LOCK_MS = 10 * 60_000;

type Ctx = ExtensionToolContext | ExtensionCommandContext;

/** One store, one key, one item list per process: every binding writes through it. */
const vault = new Vault();

/**
 * What one binding (a session or a subagent) may do. omp rebinds the factory
 * for each; pi has a single binding per process.
 */
export interface Scope {
	/** This binding entered the master password. Another binding's unlock does not count. */
	authed: boolean;
	/** item name (lowercase) -> grant expiry epoch ms */
	grants: Map<string, number>;
	/** Bumped whenever access is dropped; an unlock prompt opened before is discarded. */
	epoch: number;
	unlocking: Promise<boolean> | undefined;
}

const scopes = new Set<Scope>();
let sweeper: NodeJS.Timeout | undefined;

/** Note that `scope` is in use, so the idle sweep covers it. One timer per process. */
function track(scope: Scope): void {
	scopes.add(scope);
	if (sweeper) return;
	sweeper = setInterval(expire, 30_000);
	sweeper.unref?.();
}

/** End grants that ran out; when the store has been idle too long, lock it for everyone. */
function expire(): void {
	for (const scope of scopes) {
		for (const [name, until] of scope.grants) if (until <= Date.now()) scope.grants.delete(name);
	}
	if (vault.maybeAutoLock(AUTO_LOCK_MS)) {
		lockVault();
		appendAudit({ session: "bg", event: "auto_lock" });
	}
}

/** The key leaves memory: no binding keeps access, and every grant ends. */
function lockVault(): void {
	vault.lock();
	for (const scope of scopes) {
		scope.epoch++;
		scope.authed = false;
		scope.grants.clear();
	}
}

/** One binding gives up its access. The key stays only while another binding still has it. */
function release(scope: Scope): void {
	scope.epoch++;
	scope.authed = false;
	scope.grants.clear();
	if (![...scopes].some((other) => other.authed)) lockVault();
}

const unlocked = (scope: Scope): boolean => scope.authed && vault.unlocked;

const dialogs = (ctx: Ctx): PromptHost => ctx as unknown as PromptHost;

const note = (ctx: Ctx, text: string, level: "info" | "warning" | "error" = "info"): void =>
	ctx.ui.notify(text, level);

const LOCKED = "local vault is locked (no master password entered, or the window was cancelled)";

/**
 * Make this binding's unlock happen: its own master-password window, or a
 * prompt already waiting for one. Never throws.
 */
async function ensureUnlocked(scope: Scope, ctx: Ctx, signal?: AbortSignal): Promise<boolean> {
	if (unlocked(scope)) return true;
	if (!vault.initialized) {
		note(ctx, "omp-vault 还没初始化 — 运行 /vault init", "warning");
		return false;
	}
	if (scope.unlocking) return scope.unlocking;
	const epoch = scope.epoch;
	scope.unlocking = (async (): Promise<boolean> => {
		const pass = await promptSecret(dialogs(ctx), "omp-vault · 解锁", "本地库主密码", signal);
		if (!pass) {
			if (!signal?.aborted) note(ctx, "没有输入主密码（窗口已取消，或没有桌面/界面）", "warning");
			return false;
		}
		// /vault lock or a session switch ran while the window was open.
		if (epoch !== scope.epoch || signal?.aborted) return false;
		let opened = false;
		try {
			opened = vault.unlock(pass);
		} catch (e) {
			appendAudit({ session: sessionLabel(ctx), event: "unlock_error" });
			note(ctx, `omp-vault: 本地库读不出来（${e instanceof Error ? e.message : String(e)}）`, "error");
			return false;
		}
		if (!opened) {
			appendAudit({ session: sessionLabel(ctx), event: "unlock_failed" });
			note(ctx, "omp-vault: 主密码错误", "error");
			return false;
		}
		scope.authed = true;
		appendAudit({ session: sessionLabel(ctx), event: "unlock" });
		return true;
	})().finally(() => {
		scope.unlocking = undefined;
	});
	return scope.unlocking;
}

const setStatus = (ctx: Ctx, scope: Scope, suffix = ""): void => {
	const base = unlocked(scope) ? `vault:open(${vault.count})` : "vault:locked";
	ctx.ui.setStatus("omp-vault", `${base}${suffix}`);
};

const itemSummary = (i: VaultItem): Record<string, unknown> => ({
	name: i.name,
	username: i.username,
	uris: i.uris ?? [],
	updatedAt: i.updatedAt,
});

const vaultListParams = Type.Object({});
function vaultListTool(scope: Scope): ToolDefinition<typeof vaultListParams, { ok?: boolean; count?: number }> {
	const tool: ToolDefinition<typeof vaultListParams, { ok?: boolean; count?: number }> = {
		name: "vault_list",
		label: "Vault: list local entries",
		description:
			"List entries in the local omp-vault store (metadata only: name, username, uris). " +
			"This is NOT Bitwarden — use bw_list to query Bitwarden live, and vault_import to copy Bitwarden logins into this store. " +
			"Use vault_get to read a secret; that opens a confirm window and the grant expires.",
		promptSnippet: "List local vault metadata; secrets need vault_get plus a user grant.",
		parameters: vaultListParams,
		async execute(_id, _params, signal, _onUpdate, ctx) {
			track(scope);
			expire();
			if (!(await ensureUnlocked(scope, ctx, signal))) {
				return { content: [{ type: "text" as const, text: LOCKED }], details: { ok: false }, isError: true };
			}
			appendAudit({ session: sessionLabel(ctx), event: "list" });
			const items = vault.list().map(itemSummary);
			setStatus(ctx, scope);
			return {
				content: [{ type: "text" as const, text: JSON.stringify(items, null, 1) }],
				details: { count: items.length },
			};
		},
	};
	return withTier(tool, "read");
}

const vaultGetParams = Type.Object({
	name: Type.String({ description: "Entry name, e.g. 'cloudcone-panel'" }),
	reason: Type.Optional(Type.String({ description: "Why this secret is needed (shown to the user in the confirm window)" })),
});
type VaultGetDetails = { ok?: boolean; denied?: boolean; item?: string; via?: string };
function vaultGetTool(scope: Scope): ToolDefinition<typeof vaultGetParams, VaultGetDetails> {
	const tool: ToolDefinition<typeof vaultGetParams, VaultGetDetails> = {
		name: "vault_get",
		label: "Vault: read a local secret",
		description:
			"Read one secret from the local omp-vault (not Bitwarden). " +
			"The user must approve a desktop confirm window; the grant then lasts 5 minutes for the session or subagent that asked. " +
			"If the user denies, do not retry. Prefer bw_run when the secret should stay out of the chat.",
		parameters: vaultGetParams,
		async execute(_id, params, signal, _onUpdate, ctx) {
			track(scope);
			expire();
			if (!(await ensureUnlocked(scope, ctx, signal))) {
				return { content: [{ type: "text" as const, text: LOCKED }], details: { ok: false }, isError: true };
			}
			const item = vault.find(params.name);
			if (!item) {
				const names = vault.list().map((i) => i.name);
				return {
					content: [{ type: "text" as const, text: `no such entry. available: ${names.join(", ") || "(empty)"}` }],
					details: { ok: false },
					isError: true,
				};
			}
			const key = item.name.toLowerCase();
			const label = sessionLabel(ctx);
			if ((scope.grants.get(key) ?? 0) > Date.now()) {
				appendAudit({ session: label, event: "read_allow", item: item.name, reason: params.reason });
				setStatus(ctx, scope);
				return {
					content: [{ type: "text" as const, text: JSON.stringify(item, null, 1) }],
					details: { item: item.name, via: "existing-grant" },
				};
			}
			const sub = subagentId(ctx);
			const epoch = scope.epoch;
			const allowed = await confirmWindow(
				dialogs(ctx),
				"omp-vault · 读取本地密码",
				`条目: ${item.name}\n请求方: ${sub ? `子代理 ${sub}` : "主会话"}\n原因: ${params.reason ?? "(未说明)"}\n\n` +
					"允许后 5 分钟内同一请求方可再次读取。密码会进入对话。",
				signal,
			);
			if (!allowed) {
				appendAudit({ session: label, event: "read_deny", item: item.name, reason: params.reason ?? "denied" });
				setStatus(ctx, scope, "·denied");
				return {
					content: [{ type: "text" as const, text: `user denied access to "${item.name}" — do not retry, ask the user instead` }],
					details: { ok: false, denied: true },
					isError: true,
				};
			}
			// /vault lock (or the idle sweeper, or a session switch) ran while the
			// window was open: the approval belonged to the old, unlocked state.
			if (scope.epoch !== epoch || !unlocked(scope)) {
				appendAudit({ session: label, event: "read_deny", item: item.name, reason: "locked-during-confirm" });
				setStatus(ctx, scope, "·locked");
				return { content: [{ type: "text" as const, text: LOCKED }], details: { ok: false }, isError: true };
			}
			// Read again after the approval, from the state the user actually approved.
			const approvedItem = vault.find(params.name);
			if (!approvedItem) {
				return {
					content: [{ type: "text" as const, text: `"${item.name}" was removed while the window was open` }],
					details: { ok: false },
					isError: true,
				};
			}
			scope.grants.set(key, Date.now() + GRANT_MS_DEFAULT);
			appendAudit({ session: label, event: "grant", item: approvedItem.name });
			appendAudit({ session: label, event: "read_allow", item: approvedItem.name, reason: params.reason });
			setStatus(ctx, scope, "·granted");
			return {
				content: [{ type: "text" as const, text: JSON.stringify(approvedItem, null, 1) }],
				details: { item: approvedItem.name, via: "interactive-grant" },
			};
		},
	};
	return tool;
}

const vaultAddParams = Type.Object({
	name: Type.String({ description: "Entry name to create or update, e.g. 'github'" }),
	username: Type.Optional(Type.String({ description: "Account username. Omit to let the user type it in a dialog." })),
	uri: Type.Optional(Type.String({ description: "Optional site or host URI" })),
	notes: Type.Optional(Type.String({ description: "Optional non-secret note. Do NOT put the password here." })),
});
function vaultAddTool(scope: Scope): ToolDefinition<typeof vaultAddParams, { ok?: boolean; item?: string }> {
	const tool: ToolDefinition<typeof vaultAddParams, { ok?: boolean; item?: string }> = {
		name: "vault_add",
		label: "Vault: store a secret via dialog",
		description:
			"Create or update an entry in the local omp-vault. You supply the name and optional username, URI, and notes. " +
			"The password is typed by the user in a desktop window and is NEVER accepted from you and NEVER returned. " +
			"Do not ask the user to paste a password into the chat.",
		promptSnippet: "Save a local vault entry; the user types the password in a window.",
		parameters: vaultAddParams,
		async execute(_id, params, signal, _onUpdate, ctx) {
			const text = await saveLocalEntry(scope, ctx, {
				name: params.name,
				username: params.username,
				uri: params.uri,
				notes: params.notes,
				signal,
				confirm: true,
			});
			const ok = text.startsWith("saved ");
			return {
				content: [{ type: "text" as const, text }],
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
			"Copy Bitwarden login items into the local encrypted omp-vault. " +
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
	username?: string;
	uri?: string;
	notes?: string;
	signal?: AbortSignal;
	/** Ask before opening the password window (model-initiated saves). */
	confirm: boolean;
}

async function saveLocalEntry(scope: Scope, ctx: Ctx, req: SaveRequest): Promise<string> {
	track(scope);
	expire();
	if (!(await ensureUnlocked(scope, ctx, req.signal))) return LOCKED;
	let name = req.name?.trim() ?? "";
	if (!name) {
		const entered = await promptText(dialogs(ctx), "omp-vault · 新条目", "名称", req.signal);
		name = entered?.trim() ?? "";
	}
	if (!name) return "cancelled: no entry name";
	const existing = vault.find(name);
	if (req.confirm) {
		const ok = await confirmWindow(
			dialogs(ctx),
			"omp-vault · 保存到本地库",
			existing
				? `更新已有条目「${name}」。\n下一步会弹出窗口，由你输入密码。密码不会进入对话。`
				: `新建条目「${name}」。\n下一步会弹出窗口，由你输入密码。密码不会进入对话。`,
			req.signal,
		);
		if (!ok) return `user denied saving "${name}"`;
	}
	let username = req.username;
	if (username === undefined) {
		const entered = await promptText(
			dialogs(ctx),
			`omp-vault · ${name}`,
			existing?.username ? "用户名（留空保持不变）" : "用户名（可留空）",
			req.signal,
		);
		if (entered === undefined) return "cancelled";
		username = entered;
	}
	const password = await promptSecret(dialogs(ctx), "omp-vault · 密码", name, req.signal);
	if (!password) return "cancelled: no password entered";
	// A blank username keeps the stored one; there is no way to clear it short of removing the entry.
	const user = username.trim() || existing?.username;
	vault.upsert({
		name,
		...(user ? { username: user } : {}),
		password,
		uris: req.uri?.trim() ? [req.uri.trim()] : existing?.uris,
		notes: req.notes?.trim() || existing?.notes,
	});
	appendAudit({ session: sessionLabel(ctx), event: "add", item: name });
	setStatus(ctx, scope);
	return `saved "${name}" (password entered in the dialog, not shown)`;
}

async function importBitwarden(
	scope: Scope,
	ctx: Ctx,
	bw: BwState,
	search: string | undefined,
	signal?: AbortSignal,
): Promise<{ text: string; ok: boolean; count: number }> {
	track(scope);
	expire();
	if (!(await ensureUnlocked(scope, ctx, signal))) return { text: LOCKED, ok: false, count: 0 };
	let meta: BitwardenMeta[];
	try {
		meta = await queryBitwarden(bw, ctx, search, signal);
	} catch (e) {
		return { text: `Bitwarden: ${e instanceof Error ? e.message : String(e)}`, ok: false, count: 0 };
	}
	if (meta.length === 0) {
		return { text: search ? `no Bitwarden items match "${search}"` : "Bitwarden vault has no items", ok: false, count: 0 };
	}
	const shown = meta
		.slice(0, 15)
		.map((item) => `• ${item.name}${item.username ? `  user:${item.username}` : ""}${item.uri ? `  ${item.uri}` : ""}`)
		.join("\n");
	const more = meta.length > 15 ? `\n… 还有 ${meta.length - 15} 条` : "";
	const allowed = await confirmWindow(
		dialogs(ctx),
		"omp-vault · 从 Bitwarden 导入",
		`匹配 ${meta.length} 条。其中带密码的登录项会写入本地加密库，同名条目会被更新。\n\n${shown}${more}\n\n允许导入？`,
		signal,
	);
	if (!allowed) return { text: "user denied the Bitwarden import", ok: false, count: 0 };
	let drafts: LoginDraft[];
	try {
		drafts = await pullBitwardenLogins(bw, ctx, search, signal);
	} catch (e) {
		return { text: `Bitwarden: ${e instanceof Error ? e.message : String(e)}`, ok: false, count: 0 };
	}
	if (drafts.length === 0) {
		return { text: "matched items have no login password; nothing imported", ok: false, count: 0 };
	}
	vault.upsertMany(drafts);
	appendAudit({ session: sessionLabel(ctx), event: "import", item: `bitwarden:${drafts.length}` });
	setStatus(ctx, scope);
	const names = drafts.map((item) => item.name);
	const listed = names.slice(0, 40).join(", ");
	const extra = names.length > 40 ? ` … +${names.length - 40}` : "";
	return {
		text: `imported ${drafts.length} login item(s) into the local vault: ${listed}${extra}`,
		ok: true,
		count: drafts.length,
	};
}

const HELP = [
	"/vault init                        创建本地加密库（弹出窗口设置主密码）",
	"/vault unlock | lock               解锁 / 锁定（清空本会话的授权）",
	"/vault status                      状态与授权剩余时间",
	"/vault list                        本地条目元数据",
	"/vault add [名称]                  新增本地条目（用户名、密码在弹窗里输入）",
	'/vault remove <名称>               删除本地条目（带空格的名称加引号："GitHub (2)"）',
	"/vault grant <名称> [分钟]         手动授权读取（默认 5 分钟，上限 60）",
	"/vault revoke <名称|all>           撤销授权",
	"/vault audit [n]                   最近 n 条审计（默认 30）",
	"/vault import <bitwarden.json>     从 Bitwarden 未加密 JSON 导出导入",
	"/vault import-bw [搜索词]          直接从 bw CLI 导入登录项（先弹窗确认）",
	"/bw status|unlock|lock|clear       在线 Bitwarden 会话（见 bw_* 工具）",
].join("\n");

/** Split a command line into words; quotes keep a name such as "GitHub (2)" intact. */
function words(args: string): string[] {
	const out: string[] = [];
	for (const m of args.trim().matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)) out.push(m[1] ?? m[2] ?? m[3] ?? "");
	return out;
}

/** A Bitwarden JSON export -> vault entries. A leading `~` is expanded. */
function readBitwardenExport(path: string): LoginDraft[] {
	const file = path.replace(/^~(?=$|\/)/, homedir());
	return bitwardenLogins(JSON.parse(readFileSync(file, "utf8")));
}

function commandHandler(scope: Scope, bw: BwState) {
	return async (args: string, ctx: ExtensionCommandContext): Promise<void> => {
		const [sub = "status", ...rest] = words(args);
		const label = sessionLabel(ctx);
		track(scope);
		expire();

		switch (sub) {
			case "help": {
				note(ctx, HELP);
				return;
			}
			case "init": {
				if (vault.initialized) {
					note(ctx, "本地库已经初始化过了", "warning");
					return;
				}
				const pass = await promptSecret(dialogs(ctx), "omp-vault · 创建主密码", "至少 8 位");
				if (!pass || pass.length < 8) {
					note(ctx, "已取消，或密码短于 8 位", "warning");
					return;
				}
				const again = await promptSecret(dialogs(ctx), "omp-vault · 确认主密码", "再输入一次");
				if (again !== pass) {
					note(ctx, "两次主密码不一致，已取消", "warning");
					return;
				}
				vault.init(pass);
				scope.authed = true;
				appendAudit({ session: label, event: "init" });
				setStatus(ctx, scope);
				note(ctx, `omp-vault 已创建: ${vault.path}`);
				return;
			}
			case "unlock": {
				if (await ensureUnlocked(scope, ctx)) setStatus(ctx, scope);
				return;
			}
			case "lock": {
				const was = unlocked(scope);
				release(scope);
				if (was) appendAudit({ session: label, event: "lock" });
				setStatus(ctx, scope);
				note(ctx, "本地库已锁定，授权已清空");
				return;
			}
			case "status": {
				const lines = [`store: ${vault.path}`, `session: ${label}`, `state: ${unlocked(scope) ? "unlocked" : "locked"}`];
				if (unlocked(scope)) {
					lines.push(`items: ${vault.count}`, `idle: ${Math.round(vault.idleMs / 1000)}s / ${AUTO_LOCK_MS / 1000}s`);
				}
				for (const [name, until] of scope.grants) {
					const left = until - Date.now();
					if (left > 0) lines.push(`grant: ${name} (${Math.ceil(left / 1000)}s left)`);
				}
				note(ctx, lines.join("\n"));
				setStatus(ctx, scope);
				return;
			}
			case "list": {
				if (!(await ensureUnlocked(scope, ctx))) return;
				const items = vault.list().map((i) => `${i.name}\t${i.username ?? ""}\t${(i.uris ?? [])[0] ?? ""}`);
				note(ctx, items.join("\n") || "(empty)");
				return;
			}
			case "add": {
				const text = await saveLocalEntry(scope, ctx, { name: rest.join(" ") || undefined, confirm: false });
				note(ctx, text, text.startsWith("saved ") ? "info" : "warning");
				return;
			}
			case "remove": {
				const name = rest.join(" ");
				if (!(await ensureUnlocked(scope, ctx)) || !name) return;
				if (!vault.find(name)) {
					note(ctx, `没有叫「${name}」的条目`, "warning");
					return;
				}
				const sure = await confirmWindow(dialogs(ctx), "omp-vault · 删除条目", `删除「${name}」？删除后无法恢复。`);
				if (!sure) return;
				const removed = vault.remove(name);
				scope.grants.delete(name.toLowerCase());
				appendAudit({ session: label, event: "remove", item: name });
				setStatus(ctx, scope);
				note(ctx, removed ? "removed" : "not found", removed ? "info" : "warning");
				return;
			}
			case "grant": {
				const last = rest.at(-1) ?? "";
				const minutes = /^\d+$/.test(last) ? Number(rest.pop()) : GRANT_MS_DEFAULT / 60_000;
				const name = rest.join(" ");
				if (!name || !unlocked(scope) || !vault.find(name)) {
					note(ctx, "先解锁；用法: /vault grant <名称> [分钟]（带空格的名称加引号）", "warning");
					return;
				}
				const span = Math.min(Math.max(1, minutes), GRANT_MS_MAX / 60_000);
				scope.grants.set(name.toLowerCase(), Date.now() + span * 60_000);
				appendAudit({ session: label, event: "grant", item: name });
				setStatus(ctx, scope, "·granted");
				note(ctx, `granted "${name}" for ${span}m`);
				return;
			}
			case "revoke": {
				if (rest[0] === "all") scope.grants.clear();
				else if (rest[0]) scope.grants.delete(rest.join(" ").toLowerCase());
				setStatus(ctx, scope);
				note(ctx, "revoked");
				return;
			}
			case "audit": {
				const asked = Number(rest[0] ?? 30);
				const n = Number.isFinite(asked) && asked > 0 ? Math.min(Math.trunc(asked), 1000) : 30;
				const rows = readAudit(undefined, n).map(
					(e) => `${e.ts} ${e.session} ${e.event}${e.item ? ` ${e.item}` : ""}${e.reason ? ` (${e.reason})` : ""}`,
				);
				note(ctx, rows.join("\n") || "(no entries)");
				return;
			}
			case "import": {
				const path = rest.join(" ");
				if (!path) {
					note(ctx, "用法: /vault import <bitwarden-export.json>", "warning");
					return;
				}
				if (!(await ensureUnlocked(scope, ctx))) return;
				let imported: number;
				try {
					imported = vault.upsertMany(readBitwardenExport(path));
				} catch (e) {
					note(ctx, `导入失败：${e instanceof Error ? e.message : String(e)}`, "error");
					return;
				}
				appendAudit({ session: label, event: "import", item: `json:${imported}` });
				setStatus(ctx, scope);
				note(ctx, `imported ${imported} login items`);
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

export default function ompVault(pi: ExtensionAPI): void {
	const omp = isOmpHost(pi);
	const scope: Scope = { authed: false, grants: new Map(), epoch: 0, unlocking: undefined };
	const bw = newBwState();
	track(scope);
	pi.registerTool(vaultListTool(scope));
	pi.registerTool(vaultGetTool(scope));
	pi.registerTool(vaultAddTool(scope));
	pi.registerTool(vaultImportTool(scope, bw));
	registerBitwarden(pi, bw, omp);
	pi.registerCommand("vault", {
		description: "本地密码库 + Bitwarden 导入（/vault help）",
		handler: commandHandler(scope, bw),
	});
	// A transcript that starts fresh (/new, /fork) must not inherit this unlock
	// or its grants. A /resume keeps them: same process, same user.
	onSessionLeave(pi, omp, (reason, ctx) => {
		if (reason === "resume") return;
		const was = unlocked(scope);
		release(scope);
		if (was) appendAudit({ session: sessionLabel(ctx), event: "lock", reason: `session-${reason}` });
		if (reason === "quit" || reason === "reload") scopes.delete(scope);
	});
}
