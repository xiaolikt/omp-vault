/**
 * omp-vault — scoped, user-authorized secret vault for omp/pi agents.
 *
 * Threat model: the agent (LLM) may be steered by untrusted content it reads.
 * This extension makes sure that at worst it can *ask* for a secret: every
 * vault_get requires an interactive grant (TUI confirm dialog) that expires
 * after GRANT_MS, the store auto-locks after AUTO_LOCK_MS idle, and every
 * allow/deny decision lands in an append-only audit log.
 *
 * Tools exposed to the model:
 *   vault_list      metadata only (names, usernames, uris — never secrets)
 *   vault_get       secret values; gated on an unexpired interactive grant
 *
 * Slash commands (human side):
 *   /vault unlock|lock|status|list|add|remove|grant|revoke|audit|import|help
 */
import type { ExtensionAPI, ExtensionCommandContext, ExtensionToolContext, ToolDefinition } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { readFileSync } from "node:fs";
import { Vault, type VaultItem } from "./store.js";
import { appendAudit, readAudit } from "./audit.js";

const GRANT_MS_DEFAULT = 5 * 60_000;
const GRANT_MS_MAX = 60 * 60_000;
const AUTO_LOCK_MS = 10 * 60_000;
const CONFIRM_TIMEOUT_MS = 120_000;

const vault = new Vault();
/** item name (lowercase) -> grant expiry epoch ms */
const grants = new Map<string, number>();

const grantRemainingMs = (name: string): number =>
	(grants.get(name.toLowerCase()) ?? 0) - Date.now();

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

/**
 * Unlock via TUI prompt when possible. Returns true when the vault is
 * unlocked on exit. Never throws.
 */
const ensureUnlocked = async (ctx: ExtensionToolContext | ExtensionCommandContext): Promise<boolean> => {
	if (vault.unlocked) return true;
	if (!vault.initialized) {
		ctx.ui.notify("omp-vault is not initialized — run /vault init", "warning");
		return false;
	}
	if (!ctx.hasUI) return false;
	const pass = await ctx.ui.input("omp-vault 解锁", "主密码", { timeout: CONFIRM_TIMEOUT_MS });
	if (!pass) return false;
	if (!vault.unlock(pass)) {
		appendAudit({ session: sessionLabel(ctx), event: "unlock_failed" });
		ctx.ui.notify("omp-vault: 密码错误", "error");
		return false;
	}
	appendAudit({ session: sessionLabel(ctx), event: "unlock" });
	return true;
};

const vaultListParams = Type.Object({});
const vaultListTool: ToolDefinition<typeof vaultListParams, { ok?: boolean; count?: number }> = {
	name: "vault_list",
	label: "Vault: list entries",
	description:
		"List secret entries in the omp-vault store (metadata only: name, username, uris). " +
		"Use vault_get to read a specific entry; that requires the user to approve a time-limited grant.",
	promptSnippet: "List vault entry metadata; secrets need vault_get + user grant.",
	parameters: vaultListParams,
	async execute(_id: string, _params: Record<string, never>, _signal: AbortSignal | undefined, _onUpdate: unknown, ctx: ExtensionToolContext) {
		if (!(await ensureUnlocked(ctx))) {
			return { content: [{ type: "text" as const, text: "vault is locked and no UI to unlock" }], details: { ok: false }, isError: true };
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
	reason: Type.Optional(Type.String({ description: "Why this secret is needed (shown to the user)" })),
});
const vaultGetTool: ToolDefinition<typeof vaultGetParams, { ok?: boolean; denied?: boolean; item?: string; via?: string }> = {
	name: "vault_get",
	label: "Vault: read a secret",
	description:
		"Read one secret entry (username/password/notes) from omp-vault. " +
		"Each item needs a time-limited grant: the user sees a confirm dialog on first read; " +
		"grants last 5 minutes. If the user denies, do not retry.",
	parameters: vaultGetParams,
	async execute(_id: string, params: { name: string; reason?: string }, _signal: AbortSignal | undefined, _onUpdate: unknown, ctx: ExtensionToolContext) {
		if (vault.maybeAutoLock(AUTO_LOCK_MS)) {
			appendAudit({ session: sessionLabel(ctx), event: "auto_lock" });
		}
		if (!(await ensureUnlocked(ctx))) {
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
				content: [{ type: "text" as const, text: JSON.stringify({ ...item, password: item.password }, null, 1) }],
				details: { item: item.name, via: "existing-grant" },
			};
		}
		if (!ctx.hasUI) {
			appendAudit({ session: sessionLabel(ctx), event: "read_deny", item: item.name, reason: "headless" });
			return {
				content: [{ type: "text" as const, text: "no active grant and no UI; the user must run /vault grant <name>" }],
				details: { ok: false },
				isError: true,
			};
		}
		const allowed = await ctx.ui.confirm(
			`omp 请求读取 "${item.name}"`,
			`原因: ${params.reason ?? "(未说明)"}\n放行后 5 分钟内可重复读取。`,
			{ timeout: CONFIRM_TIMEOUT_MS },
		);
		if (!allowed) {
			appendAudit({ session: sessionLabel(ctx), event: "read_deny", item: item.name, reason: params.reason });
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

const HELP = [
	"/vault init                  创建加密库（设置主密码）",
	"/vault unlock|lock           解锁 / 锁定（清空所有授权）",
	"/vault status                当前状态与授权剩余时间",
	"/vault list                  条目元数据",
	"/vault add [name]            新增条目",
	"/vault remove <name>         删除条目",
	"/vault grant <name> [min]    手动授权（默认 5 分钟，上限 60）",
	"/vault revoke <name|all>     撤销授权",
	"/vault audit [n]             最近 n 条审计记录（默认 30）",
	"/vault import <bitwarden.json>  从 Bitwarden JSON 导出导入",
].join("\n");

/** Bitwarden "unencrypted JSON export" -> vault items (login items only). */
const parseBitwardenExport = (path: string): Omit<VaultItem, "id" | "createdAt" | "updatedAt">[] => {
	const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
	const items: unknown[] = Array.isArray(raw)
		? raw
		: raw && typeof raw === "object" && "items" in raw && Array.isArray(raw.items)
			? raw.items
			: [];
	return items.flatMap((it): Omit<VaultItem, "id" | "createdAt" | "updatedAt">[] => {
		if (!it || typeof it !== "object" || !("login" in it) || !("name" in it)) return [];
		const login = it.login;
		if (!login || typeof login !== "object") return [];
		const password = "password" in login && typeof login.password === "string" ? login.password : "";
		if (!password) return [];
		const username = "username" in login && typeof login.username === "string" && login.username
			? login.username
			: undefined;
		const uris = "uris" in login && Array.isArray(login.uris)
			? login.uris.flatMap((u: unknown) =>
					u && typeof u === "object" && "uri" in u && typeof u.uri === "string" ? [u.uri] : [],
				)
			: [];
		return [{ name: typeof it.name === "string" ? it.name : "unnamed", username, password, uris }];
	});
};

const commandHandler = async (args: string, ctx: ExtensionCommandContext): Promise<void> => {
	const [sub = "status", ...rest] = args.trim().split(/\s+/);
	const session = sessionLabel(ctx);
	if (vault.maybeAutoLock(AUTO_LOCK_MS)) appendAudit({ session, event: "auto_lock" });

	switch (sub) {
		case "help": {
			ctx.ui.notify(HELP, "info");
			return;
		}
		case "init": {
			if (vault.initialized) {
				ctx.ui.notify("vault already initialized", "warning");
				return;
			}
			const pass = await ctx.ui.input("omp-vault 初始化", "设置主密码", { timeout: CONFIRM_TIMEOUT_MS });
			if (!pass || pass.length < 8) {
				ctx.ui.notify("密码至少 8 位，已取消", "warning");
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
			ctx.ui.notify("vault locked, grants cleared", "info");
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
			if (!(await ensureUnlocked(ctx))) return;
			const name = rest[0] ?? (await ctx.ui.input("omp-vault 新条目", "名称", { timeout: CONFIRM_TIMEOUT_MS }));
			if (!name) return;
			const username = await ctx.ui.input(`omp-vault ${name}`, "用户名", { timeout: CONFIRM_TIMEOUT_MS });
			const password = await ctx.ui.input(`omp-vault ${name}`, "密码", { timeout: CONFIRM_TIMEOUT_MS });
			if (!password) return;
			vault.upsert({ name, username: username || undefined, password });
			appendAudit({ session, event: "add", item: name });
			setStatus(ctx);
			ctx.ui.notify(`saved "${name}"`, "info");
			return;
		}
		case "remove": {
			if (!(await ensureUnlocked(ctx)) || !rest[0]) return;
			const removed = vault.remove(rest[0]!);
			grants.delete(rest[0]!.toLowerCase());
			appendAudit({ session, event: "remove", item: rest[0] });
			ctx.ui.notify(removed ? "removed" : "not found", removed ? "info" : "warning");
			return;
		}
		case "grant": {
			const name = rest[0];
			if (!name || !vault.unlocked || !vault.find(name)) {
				ctx.ui.notify("unlock first; usage: /vault grant <name> [minutes]", "warning");
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
			else if (rest[0]) grants.delete(rest[0]!.toLowerCase());
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
				ctx.ui.notify("usage: /vault import <bitwarden-export.json>", "warning");
				return;
			}
			let imported = 0;
			for (const item of parseBitwardenExport(path)) {
				if (!item.password) continue;
				vault.upsert(item);
				imported++;
			}
			appendAudit({ session, event: "add", item: `import:${imported}` });
			setStatus(ctx);
			ctx.ui.notify(`imported ${imported} login items`, "info");
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
	pi.registerCommand("vault", { description: "omp-vault: scoped secret store (help for subcommands)", handler: commandHandler });
	// Background auto-lock + status decay.
	const timer = setInterval(() => {
		if (vault.maybeAutoLock(AUTO_LOCK_MS)) {
			grants.clear();
			appendAudit({ session: "bg", event: "auto_lock" });
		}
		for (const [name, exp] of grants) if (exp <= Date.now()) grants.delete(name);
	}, 30_000);
	timer.unref?.();
}
