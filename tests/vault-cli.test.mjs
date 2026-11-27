import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { answers, bind, cleanUpOnExit, dialogTrace, makeCtx, subCtx, textOf, useMocks } from "./helpers.mjs";

// The extension is only a client: these drive the real ai-vault binary (built
// by `npm test`) plus the mock zenity, with a throwaway store.
const dir = useMocks();
const { default: aiVault } = await import("../packages/pi-ai-vault/src/index.ts");
cleanUpOnExit(dir);

const PW = "correct horse battery";
const STORE = join(process.env.AI_VAULT_DIR, "store.json");
const prompts = (prefix) => dialogTrace(dir).split("\n").filter((line) => line.startsWith(prefix)).length;
const masterPrompts = () => prompts("--password");

before(async () => {
	const boot = bind(aiVault, true);
	answers.master(dir, PW, PW);
	await boot.cmd("init", makeCtx().ctx);
	assert.ok(existsSync(STORE), "init created the shared store");
});

after(() => answers.deny(dir, false));

/** Add GitHub through the human command: unlock, allow, type a username and password. */
async function addGitHub(b, ctx) {
	answers.master(dir, PW);
	answers.entries(dir, "octo");
	answers.entryPassword(dir, "pw-one");
	await b.cmd("add GitHub", ctx);
}

test("one machine-wide store, reported by /vault status", async () => {
	const b = bind(aiVault, true);
	const { ctx, notes } = makeCtx();
	answers.master(dir, PW);
	await b.cmd("unlock", ctx);
	await b.cmd("status", ctx);
	assert.match(notes.at(-1).message, /state: unlocked/);
	assert.match(notes.at(-1).message, new RegExp(process.env.AI_VAULT_DIR.replace(/[.\\/]/g, "\\$&")));
});

test("add stores an entry without a password in the tool call", async () => {
	const b = bind(aiVault, true);
	const ctx = makeCtx().ctx;
	await addGitHub(b, ctx);

	answers.master(dir, PW);
	const listed = await b.tool("vault_list", {}, ctx);
	assert.equal(listed.isError, undefined);
	assert.deepEqual(
		JSON.parse(textOf(listed)).map((i) => i.name),
		["GitHub"],
	);
	// The entry password only ever existed inside a dialog answer.
	assert.doesNotMatch(JSON.stringify(listed.details ?? {}), /pw-one/);
});

test("vault_get: a confirm window, then a grant reused without another window", async () => {
	const b = bind(aiVault, true);
	const ctx = makeCtx().ctx;
	answers.master(dir, PW);
	const before = prompts("--question");
	const first = await b.tool("vault_get", { name: "GitHub", reason: "test" }, ctx);
	assert.equal(first.details.via, "interactive-grant");
	assert.match(textOf(first), /pw-one/);

	const second = await b.tool("vault_get", { name: "GitHub" }, ctx);
	assert.equal(second.details.via, "existing-grant");
	assert.equal(prompts("--question"), before + 1, "a live grant must not open a second window");
});

test("a denied window is reported and not retried", async () => {
	const b = bind(aiVault, true);
	const ctx = makeCtx().ctx;
	answers.master(dir, PW);
	answers.deny(dir);
	const result = await b.tool("vault_get", { name: "GitHub" }, ctx);
	assert.equal(result.isError, true);
	assert.equal(result.details.denied, true);
	assert.match(textOf(result), /do not retry/);
	answers.deny(dir, false);
});

test("a subagent has its own session: the parent's grant is not inherited", async () => {
	const parent = bind(aiVault, true);
	const sub = bind(aiVault, true);
	const pc = makeCtx().ctx;
	answers.master(dir, PW);
	await parent.tool("vault_get", { name: "GitHub" }, pc);

	const before = prompts("--question");
	answers.master(dir, PW);
	const result = await sub.tool("vault_get", { name: "GitHub" }, subCtx().ctx);
	assert.match(textOf(result), /pw-one/);
	assert.equal(prompts("--question"), before + 1, "the subagent needs its own approval");
});

test("/new drops only the binding that switched", async () => {
	const a = bind(aiVault, true);
	const b = bind(aiVault, true);
	const ac = makeCtx({ sessionId: "11111111-0000-4000-8000-000000000001" }).ctx;
	const bc = makeCtx({ sessionId: "22222222-0000-4000-8000-000000000002" }).ctx;
	answers.master(dir, PW);
	await a.cmd("unlock", ac);
	answers.master(dir, PW);
	await b.cmd("unlock", bc);

	await a.fire("session_switch", { reason: "new" }, ac);

	answers.master(dir, PW);
	const before = masterPrompts();
	assert.equal((await a.tool("vault_list", {}, ac)).isError, undefined);
	assert.equal(masterPrompts(), before + 1, "the switched binding unlocks again");

	const untouched = await b.tool("vault_list", {}, bc);
	assert.equal(untouched.isError, undefined);
	assert.equal(masterPrompts(), before + 1, "the other binding keeps its token");
});

test("a missing entry names what is available", async () => {
	const b = bind(aiVault, true);
	const ctx = makeCtx().ctx;
	answers.master(dir, PW);
	const result = await b.tool("vault_get", { name: "nope" }, ctx);
	assert.equal(result.isError, true);
	assert.match(textOf(result), /no such entry/);
	assert.match(textOf(result), /GitHub/);
});
