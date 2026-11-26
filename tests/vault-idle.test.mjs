// The idle lock can fire while a dialog is open. This file keeps its own
// process so the vault really is locked between tests: no earlier binding is
// left unlocked by a test that ran before.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { bind, cleanUpOnExit, makeCtx, textOf, useMocks } from "./helpers.mjs";

const dir = useMocks();
const { default: ompVault } = await import("../src/index.ts");
cleanUpOnExit(dir);
const PW = "correct horse battery";

before(async () => {
	// No display: the host input dialog is used, and each test decides when it answers.
	delete process.env.DISPLAY;
	delete process.env.WAYLAND_DISPLAY;
	const boot = bind(ompVault, true);
	await boot.cmd("init", makeCtx({ input: () => Promise.resolve(PW) }).ctx);
	await boot.cmd("lock", makeCtx().ctx);
});

test("a save whose password dialog outlasts the idle lock unlocks again instead of failing", async () => {
	const b = bind(ompVault, true);
	const typed = [];
	const ctx = makeCtx({
		input: (title) =>
			title.includes("解锁") ? Promise.resolve(PW) : new Promise((resolve) => typed.push(resolve)),
		confirm: () => Promise.resolve(true),
	});
	const pending = b.tool("vault_add", { name: "Slow", username: "" }, ctx.ctx);
	for (let i = 0; i < 100 && typed.length === 0; i++) await new Promise((resolve) => setImmediate(resolve));
	assert.equal(typed.length, 1, "the password dialog opened");

	await b.cmd("lock", ctx.ctx); // what the idle sweeper does while the window is open
	typed[0]("slow-secret");
	const saved = await pending;
	assert.equal(saved.isError, undefined, textOf(saved));
	assert.match(textOf(saved), /saved "Slow"/);

	// The entry was written, and reading it does not need another unlock.
	await b.cmd("grant Slow", ctx.ctx);
	assert.match(textOf(await b.tool("vault_get", { name: "Slow" }, ctx.ctx)), /slow-secret/);
	await b.cmd("lock", ctx.ctx);
});

test("a remove whose confirmation outlasts the idle lock unlocks again instead of throwing", async () => {
	const b = bind(ompVault, true);
	const add = makeCtx({ input: () => Promise.resolve(PW), confirm: () => Promise.resolve(true) });
	assert.match(textOf(await b.tool("vault_add", { name: "Gone", username: "" }, add.ctx)), /saved "Gone"/);

	let answer;
	const ctx = makeCtx({
		input: () => Promise.resolve(PW),
		confirm: () => new Promise((resolve) => (answer = resolve)),
	});
	const pending = b.cmd("remove Gone", ctx.ctx);
	for (let i = 0; i < 100 && !answer; i++) await new Promise((resolve) => setImmediate(resolve));
	assert.equal(typeof answer, "function", "the confirm dialog opened");

	await b.cmd("lock", ctx.ctx);
	answer(true);
	await pending;
	assert.match(ctx.last().message, /removed/);
	assert.equal(textOf(await b.tool("vault_list", {}, ctx.ctx)).includes("Gone"), false);
	await b.cmd("lock", ctx.ctx);
});
