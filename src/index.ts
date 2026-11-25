/**
 * omp-vault — local encrypted vault + live Bitwarden, for omp and pi.
 *
 * Local store (~/.omp/vault): ChaCha20-Poly1305 at rest. Master password,
 * new secrets, and read grants open a desktop window (zenity) when a display
 * is available. vault_get still requires that grant; the password is never
 * taken from the model.
 *
 * Bitwarden (bw CLI): bw_list / bw_inject / bw_run / bw_clipboard / bw_reveal
 * query the live vault and deliver secrets to processes. vault_import copies
 * login items into the local store after a confirm window.
 */
import type { ExtensionAPI, ExtensionCommandContext, ExtensionToolContext, ToolDefinition } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { readFileSync } from "node:fs";
import { appendAudit, readAudit } from "./audit.js";
import { pullBitwardenLogins, queryBitwarden, registerBitwarden, type BitwardenMeta } from "./bitwarden.js";
import { bitwardenLogins } from "./import-map.js";
import { confirmWindow, promptSecret, promptText, type PromptHost } from "./prompt.js";
import { Vault, type VaultItem } from "./store.js";

const GRANT_MS_DEFAULT = 5 * 60_000;
const GRANT_MS_MAX = 60 * 60_000;
const AUTO_LOCK_MS = 10 * 60_000;

const vault = new Vault();
/** item name (lowercase) -> grant expiry epoch ms */
const grants = new Map<string, number>();

const grantRemainingMs = (name: string): number => (grants.get(name.toLowerCase()) ?? 0) - Date.now();

const host = (ctx: ExtensionToolContext | ExtensionCommandContext): PromptHost => ctx as unknown as PromptHost;

const sessionLabel = (ctx: { sessionManager: unknown }): string => {
	const sm = ctx.sessionManager;
	if (sm && typeof sm === "object" && "sessionId" in sm) {
		const id = sm.sessionId;
		if (typeof id === "string" && id.length >= 8) return id.slice(0, 8);
	}
	return "main";
};

const setStatus = (ctx: { ui: { setStatus: (k: string, v: string | undefined) => void } }, suffix = ""): void => {
	const base = vault.unlocked ? `vault:open(${vault.list().length})` : "vault:locked";
	ctx.ui.setStatus("omp-vault", `${base}${suffix}`);
};

const itemSummary = (i: VaultItem): Record<string, unknown> => ({
	name: i.name,
	username: i.username,
	uris: i.uris ?? [],
	updatedAt: i.updatedAt,
});

const ensureUnlocked = async (
	ctx: ExtensionToolContext | ExtensionCommandContext,
	signal?: AbortSignal,
): Promise<boolean> => {
	if (vault.unlocked) return true;
	if (!vault.initialized) {
		ctx.ui.notify("omp-vault 还没初始化 — 运行 /vault init", "warning");
		return false;
	}
	const pass = await promptSecret(host(ctx), "omp-vault · 解锁", "本地库主密码", signal);
	if (!pass) {
		ctx.ui.notify("没有输入主密码（窗口已取消，或没有桌面/界面）", "warning");
		return false;
	}
	if (!vault.unlock(pass)) {
		appendAudit({ session: sessionLabel(ctx), event: "unlock_failed" });
		ctx.ui.notify("omp-vault: 主密码错误", "error");
		return false;
	}
	appendAudit({ session: sessionLabel(ctx), event: "unlock" });
	return true;
};

const vaultListParams = Type.Object({});
const vaultListTool: ToolDefinition<typeof vaultListParams, { ok?: boolean; count?: number }> = {
	name: "vault_list",
	label: "Vault: list local entries",
	description:
		"List entries in the local omp-vault store (metadata only: name, username, uris). " +
		"This is NOT Bitwarden — use bw_list to query Bitwarden live, and vault_import to copy Bitwarden logins into this store. " +
		"Use vault_get to read a secret; that opens a confirm window and the grant expires.",
	promptSnippet: "List local vault metadata; secrets need vault_get plus a user grant.",
	parameters: vaultListParams,
	async execute(_id, _params, signal, _onUpdate, ctx) {
		if (vault.maybeAutoLock(AUTO_LOCK_MS)) appendAudit({ session: sessionLabel(ctx), event: "auto_lock" });
		if (!(await ensureUnlocked(ctx, signal))) {
			return { content: [{ type: "text" as const, text: "local vault is locked and could not be unlocked" }], details: { ok: false }, isError: true };
		}
		appendAudit({ session: sessionLabel(ctx), event: "list" });
		const items = vault.list().map(itemSummary);
		setStatus(ctx);
		return {
			content: [{ type: "text" as const, text: JSON.stringify(items, null, 1) }],
			details: { count: items.length },
		};
	},
};

const vaultGetParams = Type.Object({
	name: Type.String({ description: "Entry name, e.g. 'cloudcone-panel'" }),
	reason: Type.Optional(Type.String({ description: "Why this secret is needed (shown to the user in the confirm window)" })),
});
const vaultGetTool: ToolDefinition<typeof vaultGetParams, { ok?: boolean; denied?: boolean; item?: string; via?: string }> = {
	name: "vault_get",
	label: "Vault: read a local secret",
	description:
		"Read one secret from the local omp-vault (not Bitwarden). " +
		"The user must approve a desktop confirm window; the grant then lasts 5 minutes. " +
		"If the user denies, do not retry. Prefer bw_run / bw_inject when the secret should stay out of the chat.",
	parameters: vaultGetParams,
	async execute(_id, params, signal, _onUpdate, ctx) {
		if (vault.maybeAutoLock(AUTO_LOCK_MS)) appendAudit({ session: sessionLabel(ctx), event: "auto_lock" });
		if (!(await ensureUnlocked(ctx, signal))) {
			return { content: [{ type: "text" as const, text: "vault is locked; ask the user to run /vault unlock" }], details: { ok: false }, isError: true };
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
		if (grantRemainingMs(item.name) > 0) {
			appendAudit({ session: sessionLabel(ctx), event: "read_allow", item: item.name, reason: params.reason });
			setStatus(ctx);
			return {
				content: [{ type: "text" as const, text: JSON.stringify(item, null, 1) }],
				details: { item: item.name, via: "existing-grant" },
			};
		}
		const allowed = await confirmWindow(
			host(ctx),
			"omp-vault · 读取本地密码",
			`条目: ${item.name}\n原因: ${params.reason ?? "(未说明)"}\n\n允许后 5 分钟内可再次读取。密码会进入对话。`,
			signal,
		);
		if (!allowed) {
			appendAudit({ session: sessionLabel(ctx), event: "read_deny", item: item.name, reason: params.reason ?? "denied" });
			setStatus(ctx, "·denied");
			return {
				content: [{ type: "text" as const, text: `user denied access to "${item.name}" — do not retry, ask the user instead` }],
				details: { ok: false, denied: true },
				isError: true,
			};
		}
		grants.set(item.name.toLowerCase(), Date.now() + GRANT_MS_DEFAULT);
		appendAudit({ session: sessionLabel(ctx), event: "grant", item: item.name });
		appendAudit({ session: sessionLabel(ctx), event: "read_allow", item: item.name, reason: params.reason });
		setStatus(ctx, "·granted");
		return {
			content: [{ type: "text" as const, text: JSON.stringify(item, null, 1) }],
			details: { item: item.name, via: "interactive-grant" },
		};
	},
};

const vaultAddParams = Type.Object({
	name: Type.String({ description: "Entry name to create or update, e.g. 'github'" }),
	username: Type.Optional(Type.String({ description: "Account username. Omit to let the user type it in a dialog." })),
	uri: Type.Optional(Type.String({ description: "Optional site or host URI" })),
	notes: Type.Optional(Type.String({ description: "Optional non-secret note. Do NOT put the password here." })),
});

const vaultAddTool: ToolDefinition<typeof vaultAddParams, { ok?: boolean; item?: string }> = {
	name: "vault_add",
	label: "Vault: store a secret via dialog",
	description:
		"Create or update an entry in the local omp-vault. You supply the name and optional username, URI, and notes. " +
		"The password is typed by the user in a desktop window and is NEVER accepted from you and NEVER returned. " +
		"Do not ask the user to paste a password into the chat.",
	promptSnippet: "Save a local vault entry; the user types the password in a window.",
	parameters: vaultAddParams,
	async execute(_id, params, signal, _onUpdate, ctx) {
		const text = await saveLocalEntry(ctx, {
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

const vaultImportParams = Type.Object({
	search: Type.Optional(
		Type.String({ description: "Only import items whose name, username, or URI contains this text. Omit for every login that has a password." }),
	),
});

const vaultImportTool: ToolDefinition<typeof vaultImportParams, { ok?: boolean; count?: number }> = {
	name: "vault_import",
	label: "Vault: import from Bitwarden",
	description:
		"Copy Bitwarden login items into the local encrypted omp-vault. " +
		"Asks the user to approve in a window, then stores passwords locally. Does not return secret values. " +
		"Use bw_list to query Bitwarden without copying it. Same-name local entries are updated.",
	promptSnippet: "Import Bitwarden logins into the local vault after the user confirms.",
	parameters: vaultImportParams,
	async execute(_id, params, signal, _onUpdate, ctx) {
		const result = await importBitwarden(ctx, params.search, signal);
		return {
			content: [{ type: "text" as const, text: result.text }],
			details: { ok: result.ok, count: result.count },
			isError: result.ok ? undefined : true,
		};
	},
};

interface SaveRequest {
	name?: string;
	username?: string;
	uri?: string;
	notes?: string;
	signal?: AbortSignal;
	confirm: boolean;
}

async function saveLocalEntry(ctx: ExtensionToolContext | ExtensionCommandContext, req: SaveRequest): Promise<string> {
	if (vault.maybeAutoLock(AUTO_LOCK_MS)) appendAudit({ session: sessionLabel(ctx), event: "auto_lock" });
	if (!(await ensureUnlocked(ctx, req.signal))) return "local vault is locked";
	let name = req.name?.trim() ?? "";
	if (!name) {
		const entered = await promptText(host(ctx), "omp-vault · 新条目", "名称", req.signal);
		name = entered?.trim() ?? "";
	}
	if (!name) return "cancelled: no entry name";
	const existing = vault.find(name);
	if (req.confirm) {
		const ok = await confirmWindow(
			host(ctx),
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
		const entered = await promptText(host(ctx), `omp-vault · ${name}`, "用户名（可留空）", req.signal);
		if (entered === undefined) return "cancelled";
		username = entered;
	}
	const password = await promptSecret(host(ctx), "omp-vault · 密码", name, req.signal);
	if (!password) return "cancelled: no password entered";
	const uris = req.uri?.trim() ? [req.uri.trim()] : existing?.uris;
	vault.upsert({
		name,
		username: username.trim() ? username.trim() : undefined,
		password,
		uris,
		notes: req.notes?.trim() || existing?.notes,
	});
	appendAudit({ session: sessionLabel(ctx), event: "add", item: name });
	setStatus(ctx);
	return `saved "${name}" (password entered in the dialog, not shown)`;
}

async function importBitwarden(
	ctx: ExtensionToolContext | ExtensionCommandContext,
	search: string | undefined,
	signal?: AbortSignal,
): Promise<{ text: string; ok: boolean; count: number }> {
	if (vault.maybeAutoLock(AUTO_LOCK_MS)) appendAudit({ session: sessionLabel(ctx), event: "auto_lock" });
	if (!(await ensureUnlocked(ctx, signal))) return { text: "local vault is locked", ok: false, count: 0 };
	let meta: BitwardenMeta[];
	try {
		meta = await queryBitwarden(ctx, search, signal);
	} catch (e) {
		const message = e instanceof Error ? e.message : String(e);
		return { text: message, ok: false, count: 0 };
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
		host(ctx),
		"omp-vault · 从 Bitwarden 导入",
		`匹配 ${meta.length} 条。其中带密码的登录项会写入本地加密库，同名条目会被更新。\n\n${shown}${more}\n\n允许导入？`,
		signal,
	);
	if (!allowed) return { text: "user denied the Bitwarden import", ok: false, count: 0 };
	let drafts;
	try {
		drafts = await pullBitwardenLogins(ctx, search, signal);
	} catch (e) {
		const message = e instanceof Error ? e.message : String(e);
		return { text: message, ok: false, count: 0 };
	}
	if (drafts.length === 0) {
		return { text: "matched items have no login password; nothing imported", ok: false, count: 0 };
	}
	for (const item of drafts) vault.upsert(item);
	appendAudit({ session: sessionLabel(ctx), event: "import", item: `bitwarden:${drafts.length}` });
	setStatus(ctx);
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
	"/vault init                     创建本地加密库（弹出窗口设置主密码）",
	"/vault unlock|lock              解锁 / 锁定（清空授权）",
	"/vault status                   状态与授权剩余时间",
	"/vault list                     本地条目元数据",
	"/vault add [name]               新增本地条目（密码在弹窗里输入）",
	"/vault remove <name>            删除本地条目",
	"/vault grant <name> [min]       手动授权读取（默认 5 分钟，上限 60）",
	"/vault revoke <name|all>        撤销授权",
	"/vault audit [n]                最近 n 条审计（默认 30）",
	"/vault import <bitwarden.json>  从 Bitwarden 未加密 JSON 导出导入",
	"/vault import-bw [搜索词]       直接从 bw CLI 导入登录项（先弹窗确认）",
	"/bw status|unlock|lock|clear    在线 Bitwarden 会话（见 bw_* 工具）",
].join("\n");

const parseBitwardenExport = (path: string): ReturnType<typeof bitwardenLogins> =>
	bitwardenLogins(JSON.parse(readFileSync(path, "utf8")));

const commandHandler = async (args: string, ctx: ExtensionCommandContext): Promise<void> => {
	const trimmed = args.trim();
	const [sub = "status", ...rest] = trimmed.split(/\s+/);
	const session = sessionLabel(ctx);
	if (vault.maybeAutoLock(AUTO_LOCK_MS)) appendAudit({ session, event: "auto_lock" });

	switch (sub) {
		case "help": {
			ctx.ui.notify(HELP, "info");
			return;
		}
		case "init": {
			if (vault.initialized) {
				ctx.ui.notify("本地库已经初始化过了", "warning");
				return;
			}
			const pass = await promptSecret(host(ctx), "omp-vault · 创建主密码", "至少 8 位");
			if (!pass || pass.length < 8) {
				ctx.ui.notify("已取消，或密码短于 8 位", "warning");
				return;
			}
			const again = await promptSecret(host(ctx), "omp-vault · 确认主密码", "再输入一次");
			if (again !== pass) {
				ctx.ui.notify("两次主密码不一致，已取消", "warning");
				return;
			}
			vault.init(pass);
			grants.clear();
			appendAudit({ session, event: "init" });
			setStatus(ctx);
			ctx.ui.notify(`omp-vault 已创建: ${vault.path}`, "info");
			return;
		}
		case "unlock": {
			if (await ensureUnlocked(ctx)) setStatus(ctx);
			return;
		}
		case "lock": {
			vault.lock();
			grants.clear();
			appendAudit({ session, event: "lock" });
			setStatus(ctx);
			ctx.ui.notify("本地库已锁定，授权已清空", "info");
			return;
		}
		case "status": {
			const lines = [`store: ${vault.path}`, `state: ${vault.unlocked ? "unlocked" : "locked"}`];
			if (vault.unlocked) lines.push(`items: ${vault.list().length}`, `idle: ${Math.round(vault.idleMs / 1000)}s / ${AUTO_LOCK_MS / 1000}s`);
			for (const [name, exp] of grants) {
				const left = exp - Date.now();
				if (left > 0) lines.push(`grant: ${name} (${Math.ceil(left / 1000)}s left)`);
			}
			ctx.ui.notify(lines.join("\n"), "info");
			setStatus(ctx);
			return;
		}
		case "list": {
			if (!(await ensureUnlocked(ctx))) return;
			const items = vault.list().map((i) => `${i.name}\t${i.username ?? ""}\t${(i.uris ?? [])[0] ?? ""}`);
			ctx.ui.notify(items.join("\n") || "(empty)", "info");
			return;
		}
		case "add": {
			const text = await saveLocalEntry(ctx, { name: rest[0], signal: undefined, confirm: false });
			ctx.ui.notify(text, text.startsWith("saved ") ? "info" : "warning");
			return;
		}
		case "remove": {
			if (!(await ensureUnlocked(ctx)) || !rest[0]) return;
			const removed = vault.remove(rest[0]);
			grants.delete(rest[0].toLowerCase());
			appendAudit({ session, event: "remove", item: rest[0] });
			ctx.ui.notify(removed ? "removed" : "not found", removed ? "info" : "warning");
			return;
		}
		case "grant": {
			const name = rest[0];
			if (!name || !vault.unlocked || !vault.find(name)) {
				ctx.ui.notify("先解锁；用法: /vault grant <name> [minutes]", "warning");
				return;
			}
			const minutes = Math.min(Number(rest[1] ?? 5) || 5, GRANT_MS_MAX / 60_000);
			grants.set(name.toLowerCase(), Date.now() + minutes * 60_000);
			appendAudit({ session, event: "grant", item: name });
			setStatus(ctx, "·granted");
			ctx.ui.notify(`granted "${name}" for ${minutes}m`, "info");
			return;
		}
		case "revoke": {
			if (rest[0] === "all") grants.clear();
			else if (rest[0]) grants.delete(rest[0].toLowerCase());
			setStatus(ctx);
			ctx.ui.notify("revoked", "info");
			return;
		}
		case "audit": {
			const n = Number(rest[0] ?? 30) || 30;
			const rows = readAudit(undefined, n).map(
				(e) => `${e.ts} ${e.event}${e.item ? ` ${e.item}` : ""}${e.reason ? ` (${e.reason})` : ""}`,
			);
			ctx.ui.notify(rows.join("\n") || "(no entries)", "info");
			return;
		}
		case "import": {
			if (!(await ensureUnlocked(ctx))) return;
			const path = rest[0];
			if (!path) {
				ctx.ui.notify("用法: /vault import <bitwarden-export.json>", "warning");
				return;
			}
			let imported = 0;
			for (const item of parseBitwardenExport(path)) {
				vault.upsert(item);
				imported++;
			}
			appendAudit({ session, event: "import", item: `json:${imported}` });
			setStatus(ctx);
			ctx.ui.notify(`imported ${imported} login items`, "info");
			return;
		}
		case "import-bw": {
			const search = rest.join(" ").trim() || undefined;
			const result = await importBitwarden(ctx, search, undefined);
			ctx.ui.notify(result.text, result.ok ? "info" : "warning");
			return;
		}
		default: {
			ctx.ui.notify(`unknown subcommand "${sub}"\n${HELP}`, "warning");
		}
	}
};

export default function ompVault(pi: ExtensionAPI): void {
	pi.registerTool(vaultListTool);
	pi.registerTool(vaultGetTool);
	pi.registerTool(vaultAddTool);
	pi.registerTool(vaultImportTool);
	registerBitwarden(pi);
	pi.registerCommand("vault", {
		description: "本地密码库 + Bitwarden 导入（/vault help）",
		handler: commandHandler,
	});
	const timer = setInterval(() => {
		if (vault.maybeAutoLock(AUTO_LOCK_MS)) {
			grants.clear();
			appendAudit({ session: "bg", event: "auto_lock" });
		}
		for (const [name, exp] of grants) if (exp <= Date.now()) grants.delete(name);
	}, 30_000);
	timer.unref?.();
}
