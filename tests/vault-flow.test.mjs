import { test, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { answers, bind, cleanUpOnExit, dialogTrace, makeCtx, passwordPrompts, subCtx, textOf, useMocks } from "./helpers.mjs";

const dir = useMocks();
const { default: ompVault } = await import("../src/index.ts");
const { readAudit } = await import("../src/audit.ts");
cleanUpOnExit(dir);

const PW = "correct horse battery";
const PARENT = "a1b2c3d4-0000-4000-8000-000000000000";
const STORE = join(process.env.OMP_VAULT_DIR, "store.json");

before(async () => {
	const boot = bind(ompVault, true);
	answers.master(dir, PW, PW);
	await boot.cmd("init", makeCtx().ctx);
});

/** Create an entry through the human command: the binding unlocks if it has to, then types the password. */
async function addEntry(b, ctx, name, password, username = "") {
	answers.master(dir, PW);
	answers.entries(dir, username);
	answers.entryPassword(dir, password);
	await b.cmd(`add ${name}`, ctx);
}

const names = async (b, ctx) => JSON.parse(textOf(await b.tool("vault_list", {}, ctx))).map((i) => i.name);

test("omp: a subagent never reads on the parent's grant, and /new drops only the session that switched", async () => {
	const parent = bind(ompVault, true);
	const sub = bind(ompVault, true);
	const pc = makeCtx({ sessionId: PARENT });
	const sc = subCtx();
	await addEntry(parent, pc.ctx, "GitHub (2)", "pw-one");
	const prompts = passwordPrompts(dir);

	// omp's session_start carries no reason: it must never be read as a lock.
	await parent.fire("session_start", {}, pc.ctx);
	assert.equal((await parent.tool("vault_list", {}, pc.ctx)).isError, undefined);
	assert.equal(passwordPrompts(dir), prompts, "session_start locked the vault");

	// The parent is granted once, then rides the grant.
	const first = await parent.tool("vault_get", { name: "GitHub (2)" }, pc.ctx);
	assert.equal(first.details.via, "interactive-grant");
	assert.match(textOf(first), /pw-one/);
	assert.equal((await parent.tool("vault_get", { name: "GitHub (2)" }, pc.ctx)).details.via, "existing-grant");

	// A subagent asking for the same entry gets a confirm of its own, and the
	// window says who is asking.
	answers.deny(dir, true);
	answers.master(dir, PW);
	const denied = await sub.tool("vault_get", { name: "GitHub (2)" }, sc.ctx);
	assert.equal(denied.details.denied, true);
	assert.equal(textOf(denied).includes("pw-one"), false);
	assert.equal(passwordPrompts(dir), prompts + 1, "the subagent had to unlock for itself");
	assert.match(dialogTrace(dir), /请求方: 子代理 0-Explore/);
	answers.deny(dir, false);
	assert.match(textOf(await sub.tool("vault_get", { name: "GitHub (2)" }, sc.ctx)), /pw-one/);

	// /new in the parent: the parent is locked, the subagent keeps its own unlock.
	await parent.fire("session_switch", { reason: "new" }, pc.ctx);
	assert.match(textOf(await parent.tool("vault_list", {}, pc.ctx)), /locked/);
	const afterSwitch = passwordPrompts(dir);
	assert.equal((await sub.tool("vault_list", {}, sc.ctx)).isError, undefined);
	assert.equal(passwordPrompts(dir), afterSwitch, "the subagent was locked by the parent's /new");

	// The last binding to leave locks the store: a new binding has to unlock.
	await sub.fire("session_shutdown", {}, sc.ctx);
	const fresh = bind(ompVault, true);
	answers.master(dir, PW);
	assert.equal((await fresh.tool("vault_list", {}, makeCtx().ctx)).isError, undefined);
	assert.equal(passwordPrompts(dir), afterSwitch + 1);

	const entries = readAudit();
	const subLabel = `${sc.sid.replace(/-/g, "").slice(0, 8)}/0-Explore`;
	assert.ok(entries.some((e) => e.session === "a1b2c3d4" && e.event === "read_allow"), "parent audit label");
	assert.ok(entries.some((e) => e.session === subLabel && e.event === "read_deny"), "subagent audit label");
	assert.ok(entries.some((e) => e.session === "a1b2c3d4" && e.event === "lock" && e.reason === "session-new"));
});

test("pi: /new locks on session_start, while startup and /resume keep the unlock", async () => {
	const b = bind(ompVault, false);
	const ctx = makeCtx();
	await addEntry(b, ctx.ctx, "PiEntry", "pw-pi");
	const prompts = passwordPrompts(dir);
	await b.fire("session_start", { reason: "startup" }, ctx.ctx);
	await b.fire("session_shutdown", { reason: "resume" }, ctx.ctx);
	await b.fire("session_start", { reason: "resume" }, ctx.ctx);
	assert.equal((await b.tool("vault_list", {}, ctx.ctx)).isError, undefined);
	assert.equal(passwordPrompts(dir), prompts);
	await b.fire("session_start", { reason: "new" }, ctx.ctx);
	assert.match(textOf(await b.tool("vault_list", {}, ctx.ctx)), /locked/);
});

test("/vault remove takes a name with spaces, and asks before deleting", async () => {
	const b = bind(ompVault, true);
	const ctx = makeCtx();
	await addEntry(b, ctx.ctx, "Mail", "pw-a");
	await addEntry(b, ctx.ctx, "Mail (2)", "pw-b");
	const mail = async () => (await names(b, ctx.ctx)).filter((n) => n.startsWith("Mail"));

	answers.deny(dir, true);
	await b.cmd("remove Mail (2)", ctx.ctx);
	assert.deepEqual(await mail(), ["Mail", "Mail (2)"]);

	answers.deny(dir, false);
	await b.cmd('remove "Mail (2)"', ctx.ctx);
	assert.deepEqual(await mail(), ["Mail"]);
});

test("/vault grant accepts a quoted name and a minute count", async () => {
	const b = bind(ompVault, true);
	const ctx = makeCtx();
	await addEntry(b, ctx.ctx, "Mail (2)", "pw-b");
	await b.cmd('grant "Mail (2)" 7', ctx.ctx);
	assert.match(ctx.last().message, /granted "Mail \(2\)" for 7m/);

	// A confirm would be refused here: only the grant lets the read through.
	answers.deny(dir, true);
	assert.equal((await b.tool("vault_get", { name: "Mail (2)" }, ctx.ctx)).details.via, "existing-grant");
	await b.cmd("status", ctx.ctx);
	assert.match(ctx.last().message, /grant: mail \(2\) \(\d+s left\)/);
	answers.deny(dir, false);
});

test("a blank username keeps the stored one when the password is updated", async () => {
	const b = bind(ompVault, true);
	const ctx = makeCtx();
	await addEntry(b, ctx.ctx, "Srv", "one", "alice");

	// Through the tool, with an explicit blank username.
	answers.entryPassword(dir, "two");
	assert.equal((await b.tool("vault_add", { name: "Srv", username: "" }, ctx.ctx)).isError, undefined);
	// Through the command, with a blank answer in the dialog.
	await addEntry(b, ctx.ctx, "Srv", "three");

	await b.cmd("grant Srv", ctx.ctx);
	const item = JSON.parse(textOf(await b.tool("vault_get", { name: "Srv" }, ctx.ctx)));
	assert.equal(item.username, "alice");
	assert.equal(item.password, "three");
});

test("a corrupt store is reported, not thrown", async () => {
	const b = bind(ompVault, true);
	const ctx = makeCtx();
	const good = readFileSync(STORE);
	writeFileSync(STORE, "{ not json");
	try {
		answers.master(dir, PW);
		const result = await b.tool("vault_list", {}, ctx.ctx);
		assert.equal(result.isError, true);
		assert.match(textOf(result), /locked/);
		assert.ok(ctx.notes.some((n) => n.type === "error" && /读不出来/.test(n.message)));
		assert.ok(readAudit().some((e) => e.event === "unlock_error"));
	} finally {
		writeFileSync(STORE, good);
	}
});

test("a lock that runs while the password dialog is open discards the unlock", async () => {
	// No display: the host dialog is used, and this test decides when it answers.
	delete process.env.DISPLAY;
	delete process.env.WAYLAND_DISPLAY;
	try {
		const b = bind(ompVault, true);
		let answer;
		const ctx = makeCtx({ input: () => new Promise((resolve) => (answer = resolve)) });
		const pending = b.tool("vault_list", {}, ctx.ctx).then(textOf, (error) => error.message);
		for (let i = 0; i < 50 && !answer; i++) await new Promise((resolve) => setImmediate(resolve));
		assert.equal(typeof answer, "function", "the password dialog opened");

		await b.cmd("lock", ctx.ctx);
		answer(PW);
		assert.match(await pending, /locked/);

		// The dialog that was open during the lock did not auth this binding.
		let again;
		const next = b.tool("vault_list", {}, makeCtx({ input: () => new Promise((resolve) => (again = resolve)) }).ctx);
		for (let i = 0; i < 50 && !again; i++) await new Promise((resolve) => setImmediate(resolve));
		assert.equal(typeof again, "function", "the vault asked for the password again");
		again(PW);
		assert.doesNotMatch(await next.then(textOf, (error) => error.message), /locked/);
	} finally {
		process.env.DISPLAY = ":99";
	}
});
