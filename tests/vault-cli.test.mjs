import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { answers, bind, cleanUpOnExit, dialogTrace, makeCtx, subCtx, textOf, useMocks } from "./helpers.mjs";

// The extension is only a client: these drive the real ai-vault binary (built
// by `npm test`) plus the mock zenity, with a throwaway store.
const dir = useMocks();
const { default: aiVault } = await import("../packages/pi-ai-vault/src/index.ts");
const { forgetSettings } = await import("../packages/pi-ai-vault/src/settings.ts");
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

test("a local miss falls back to Bitwarden: read once, no import", async () => {
	const b = bind(aiVault, true);
	const ctx = makeCtx().ctx;
	answers.master(dir, PW);
	await b.cmd("unlock", ctx);
	// The Bitwarden mock unlocks with "testmaster"; the two windows are the
	// read approval (yes) and the import offer (no).
	answers.master(dir, "testmaster");
	answers.questions(dir, "y", "n");
	const result = await b.tool("vault_get", { name: "TestService" }, ctx);
	assert.equal(result.details.via, "bitwarden-once");
	assert.match(textOf(result), /supersecret-value-123/);

	answers.master(dir, PW);
	const listed = await b.tool("vault_list", {}, ctx);
	assert.equal(
		JSON.parse(textOf(listed)).some((i) => i.name === "TestService"),
		false,
		"a one-off read must not write the entry",
	);
});

test("a local miss can be imported from Bitwarden", async () => {
	const b = bind(aiVault, true);
	const ctx = makeCtx().ctx;
	answers.master(dir, PW);
	await b.cmd("unlock", ctx);
	answers.master(dir, "testmaster");
	answers.questions(dir, "y", "y");
	const result = await b.tool("vault_get", { name: "TestService" }, ctx);
	assert.equal(result.details.via, "imported-from-bitwarden");
	assert.match(textOf(result), /supersecret-value-123/);

	answers.master(dir, PW);
	const listed = await b.tool("vault_list", {}, ctx);
	assert.equal(
		JSON.parse(textOf(listed)).some((i) => i.name === "TestService"),
		true,
		"the import must land in the local vault",
	);
});

test("a denied Bitwarden read is not retried", async () => {
	const b = bind(aiVault, true);
	const ctx = makeCtx().ctx;
	answers.master(dir, PW);
	await b.cmd("unlock", ctx);
	answers.master(dir, "testmaster");
	answers.questions(dir, "n");
	const result = await b.tool("vault_get", { name: "OtherService" }, ctx);
	assert.equal(result.isError, true);
	assert.match(textOf(result), /do not retry/);
});

test("never mode reads without any window, and the switch needs the password", async () => {
	const bin = process.env.AI_VAULT_BIN;
	const switchMode = (mode) =>
		spawnSync(bin, ["mode", "set", mode, "--password-stdin"], {
			input: `${PW}\n`,
			env: process.env,
			encoding: "utf8",
		});
	const toNever = switchMode("never");
	assert.equal(toNever.status, 0, toNever.stderr);

	const b = bind(aiVault, true);
	const ctx = makeCtx().ctx;
	const before = prompts("--question") + prompts("--password");
	const result = await b.tool("vault_get", { name: "GitHub" }, ctx);
	assert.equal(result.details.via, "no-password");
	assert.match(textOf(result), /pw-one/);
	assert.equal(prompts("--question") + prompts("--password"), before, "no window in never mode");

	// A wrong password must not change the policy.
	const wrong = spawnSync(bin, ["mode", "set", "session", "--password-stdin"], {
		input: "definitely-wrong\n",
		env: process.env,
		encoding: "utf8",
	});
	assert.equal(wrong.status, 5);

	const back = switchMode("session");
	assert.equal(back.status, 0, back.stderr);
});

test("bitwarden.import=never reads once with a single window", async () => {
	const bin = process.env.AI_VAULT_BIN;
	spawnSync(bin, ["settings", "bitwarden.import", "never"], { env: process.env });
	forgetSettings();
	const b = bind(aiVault, true);
	const ctx = makeCtx().ctx;
	answers.master(dir, PW);
	await b.cmd("unlock", ctx);
	answers.master(dir, "testmaster");
	const before = prompts("--question");
	answers.questions(dir, "y");
	const result = await b.tool("vault_get", { name: "OtherService" }, ctx);
	assert.equal(result.details.via, "bitwarden-once");
	assert.equal(prompts("--question"), before + 1, "never: read approval only, no import question");
});

test("bitwarden.import=always pulls the entry in without a window", async () => {
	const bin = process.env.AI_VAULT_BIN;
	spawnSync(bin, ["settings", "bitwarden.import", "always"], { env: process.env });
	forgetSettings();
	const b = bind(aiVault, true);
	const ctx = makeCtx().ctx;
	answers.master(dir, PW);
	await b.cmd("unlock", ctx);
	answers.master(dir, "testmaster");
	const before = prompts("--question");
	const result = await b.tool("vault_get", { name: "OtherService" }, ctx);
	assert.equal(result.details.via, "imported-from-bitwarden");
	assert.equal(prompts("--question"), before, "always: no window at all");

	answers.master(dir, PW);
	const listed = await b.tool("vault_list", {}, ctx);
	assert.equal(
		JSON.parse(textOf(listed)).some((i) => i.name === "OtherService"),
		true,
	);
	spawnSync(bin, ["settings", "bitwarden.import", "ask"], { env: process.env });
	forgetSettings();
});

test("a persisted Bitwarden session costs no password", async () => {
	const bin = process.env.AI_VAULT_BIN;
	const set = (key, value) => spawnSync(bin, ["settings", key, value], { env: process.env, encoding: "utf8" });
	assert.equal(set("bitwarden.unlock", "never").status, 0);
	forgetSettings();
	const put = spawnSync(bin, ["bw-session", "put"], { input: "GOOD_SESSION", env: process.env, encoding: "utf8" });
	assert.equal(put.status, 0, put.stderr);

	const b = bind(aiVault, true);
	const ctx = makeCtx().ctx;
	answers.master(dir, PW);
	answers.master(dir, PW); // would be consumed only by a Bitwarden prompt
	const before = prompts("--password");
	const listed = await b.tool("bw_list", {}, ctx);
	assert.equal(listed.isError, undefined);
	assert.equal(prompts("--password"), before, "the stored bw session must be used silently");

	// Restoring the session policy drops the key from disk.
	assert.equal(set("bitwarden.unlock", "session").status, 0);
	forgetSettings();
	const get = spawnSync(bin, ["bw-session", "get"], { env: process.env, encoding: "utf8" });
	assert.equal(get.status, 5, "switching back to session must remove the stored key");
});

test("a relayed read approval is signed by the host: the raw CLI refuses a bare 'y'", async () => {
	const bin = process.env.AI_VAULT_BIN;
	// A session opened by a human (no host identity): the attacker's position.
	const human = spawnSync(bin, ["unlock", "--password-stdin", "--json"], {
		input: `${PW}\n`,
		env: { ...process.env, AI_VAULT_HOST: "", AI_VAULT_HOST_SECRET: "" },
		encoding: "utf8",
	});
	const token = JSON.parse(human.stdout).token;
	assert.equal(JSON.parse(human.stdout).hostSecret ?? null, null, "a human caller is not handed a secret");
	const bare = spawnSync(bin, ["get", "GitHub", "--token", token, "--answer-stdin", "--json"], {
		input: "y\n",
		env: { ...process.env, AI_VAULT_HOST: "", AI_VAULT_HOST_SECRET: "" },
		encoding: "utf8",
	});
	assert.equal(bare.status, 2, bare.stderr);
	assert.match(bare.stderr, /--approval/);

	// The same token, with the file edited to carry a grant: rejected on load.
	const { readdirSync, readFileSync, writeFileSync } = await import("node:fs");
	const { join } = await import("node:path");
	const dir = join(process.env.XDG_RUNTIME_DIR ?? "/tmp", "ai-vault", "sessions");
	const file = join(dir, `${token}.json`);
	const edited = JSON.parse(readFileSync(file, "utf8"));
	edited.grants = { github: 9999999999999 };
	edited.requester = "主会话";
	writeFileSync(file, JSON.stringify(edited));
	const tampered = spawnSync(bin, ["get", "GitHub", "--token", token, "--json"], { encoding: "utf8" });
	assert.equal(tampered.status, 5);
	assert.match(tampered.stderr, /modified outside ai-vault/);
	assert.equal(readdirSync(dir).includes(`${token}.json`), false, "the tampered file is deleted");
});
