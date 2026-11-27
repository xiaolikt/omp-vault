import { test } from "node:test";
import assert from "node:assert/strict";
import { bind, cleanUpOnExit, useMocks } from "./helpers.mjs";

const dir = useMocks();
const { default: ompVault } = await import("../packages/pi-ai-vault/src/index.ts");
cleanUpOnExit(dir);

test("omp: one extension registers the local vault and live Bitwarden, without bw_inject", () => {
	const b = bind(ompVault, true);
	assert.deepEqual([...b.tools.keys()], [
		"vault_list",
		"vault_get",
		"vault_add",
		"vault_import",
		"bw_list",
		"bw_run",
		"bw_clipboard",
		"bw_reveal",
	]);
	assert.deepEqual([...b.commands.keys()].sort(), ["bw", "vault"]);
	// omp reads the reason from session_switch; its session_start has none.
	assert.equal(b.has("session_switch"), true);
	assert.equal(b.has("session_start"), false);
});

test("pi: bash and bw_inject are registered, and the lifecycle comes from session_start", () => {
	const b = bind(ompVault, false);
	const names = [...b.tools.keys()];
	assert.equal(names.includes("bash"), true);
	assert.equal(names.includes("bw_inject"), true);
	assert.equal(names.includes("bw_run"), true);
	assert.equal(b.has("session_start"), true);
	assert.equal(b.has("session_switch"), false);
});

test("tools declare the approval tier omp prompts by: reads read, writes write", () => {
	const b = bind(ompVault, true);
	assert.equal(b.tools.get("vault_list").approval, "read");
	assert.equal(b.tools.get("bw_list").approval, "read");
	assert.equal(b.tools.get("vault_add").approval, "write");
	assert.equal(b.tools.get("vault_import").approval, "write");
	assert.equal(b.tools.get("bw_clipboard").approval, "write");
	assert.equal(b.tools.get("bw_run").approval, "exec");
	// A secret handed to the model keeps the strictest tier.
	assert.equal(b.tools.get("vault_get").approval, undefined);
	assert.equal(b.tools.get("bw_reveal").approval, undefined);
});
