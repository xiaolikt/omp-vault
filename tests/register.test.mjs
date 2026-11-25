import { test } from "node:test";
import assert from "node:assert/strict";
import ompVault from "../src/index.ts";

test("one extension registers the local vault and live Bitwarden on omp", () => {
	const tools = [];
	const commands = [];
	// `"pi" in api` is how this package recognizes omp. That host already has bash.
	const api = {
		pi: {},
		registerTool(tool) {
			tools.push(tool.name);
		},
		registerCommand(name) {
			commands.push(name);
		},
		on() {
			return () => {};
		},
	};
	ompVault(api);
	assert.deepEqual(tools, [
		"vault_list",
		"vault_get",
		"vault_add",
		"vault_import",
		"bw_list",
		"bw_inject",
		"bw_run",
		"bw_clipboard",
		"bw_reveal",
	]);
	assert.equal(tools.includes("bash"), false);
	assert.deepEqual(commands.sort(), ["bw", "vault"]);
});

test("pi registers bash so bw_inject can reach the child env", () => {
	const tools = [];
	const api = {
		registerTool(tool) {
			tools.push(tool.name);
		},
		registerCommand() {},
		on() {
			return () => {};
		},
	};
	ompVault(api);
	assert.equal(tools.includes("bash"), true);
	assert.equal(tools.includes("bw_inject"), true);
});
