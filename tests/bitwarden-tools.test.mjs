import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { answers, bind, cleanUpOnExit, dialogTrace, makeCtx, passwordPrompts, textOf, useMocks } from "./helpers.mjs";

const dir = useMocks();
const { default: ompVault } = await import("../src/index.ts");
cleanUpOnExit(dir);

const SECRET = "supersecret-value-123";
const bwAudit = () => {
	const file = join(process.env.HOME, ".bw", "pi-extension", "audit.log");
	return existsSync(file) ? readFileSync(file, "utf8") : "";
};

test("one binding's lock does not destroy another binding's Bitwarden key", async () => {
	// First test in the file: no earlier binding has left a key behind.
	const first = bind(ompVault, true);
	const second = bind(ompVault, true);
	answers.master(dir, "testmaster", "testmaster");
	await first.tool("bw_list", {}, makeCtx().ctx);
	await second.tool("bw_list", {}, makeCtx().ctx);

	await first.commands.get("bw").handler("lock", makeCtx().ctx);
	assert.equal(existsSync(join(dir, "locked")), false, "the first lock ran a global bw lock");

	await second.commands.get("bw").handler("lock", makeCtx().ctx);
	assert.equal(existsSync(join(dir, "locked")), true, "the last lock did not run bw lock");
	// Leave the mock back at its default password for the tests that follow.
	answers.master(dir);
});

test("omp: bw_run gives one command the secret and scrubs it and its base64, for short passwords too", async () => {
	const b = bind(ompVault, true);
	assert.equal(b.tools.has("bw_inject"), false, "bw_inject cannot work on omp, so it is not offered");

	const out = textOf(
		await b.tool("bw_run", {
			item: "TestService",
			command: 'echo LEN=${#VAULT_SECRET}; printf %s "$VAULT_SECRET" | base64; printf "\\n%s\\n" "$VAULT_SECRET"',
		}),
	);
	assert.match(out, /LEN=21/);
	assert.match(out, /\[BW_SCRUBBED:VAULT_SECRET\]/);
	assert.match(out, /\[BW_SCRUBBED-B64:VAULT_SECRET\]/);
	assert.equal(out.includes("c3VwZXJzZWNyZXQ"), false, "base64 of the secret leaked");

	// 12 characters: below the old 16-character threshold for base64 scrubbing.
	const short = textOf(await b.tool("bw_run", { item: "OtherService", command: 'printf %s "$VAULT_SECRET" | base64' }));
	assert.equal(short.includes("b3RoZXItcHctOTk5"), false, "base64 of a short secret leaked");
	assert.match(short, /\[BW_SCRUBBED-B64:VAULT_SECRET\]/);
});

test("a BW_SESSION exported in the host shell does not reach bw_run", async () => {
	const b = bind(ompVault, true);
	answers.master(dir, "testmaster");
	answers.deny(dir, false);
	const saved = process.env.BW_SESSION;
	process.env.BW_SESSION = "LEAKED_HOST_SESSION";
	try {
		const out = textOf(
			await b.tool("bw_run", { item: "TestService", command: 'printf "session=%s\\n" "${BW_SESSION:-unset}"' }),
		);
		assert.equal(out.includes("LEAKED_HOST_SESSION"), false);
		assert.match(out, /session=unset/);
	} finally {
		if (saved === undefined) delete process.env.BW_SESSION;
		else process.env.BW_SESSION = saved;
	}
});

test("only bash's own temp output artifact can be scrubbed or removed", async () => {
	const b = bind(ompVault, true);
	answers.master(dir, "testmaster");
	answers.deny(dir, false);
	await b.tool("bw_run", { item: "TestService", command: "true" });

	// A real bash artifact: scrubbed in place.
	const artifact = join(tmpdir(), `pi-bash-${randomBytes(8).toString("hex")}.log`);
	writeFileSync(artifact, `before ${SECRET} after`);
	try {
		await b.fire("tool_result", {
			toolName: "bash",
			content: [{ type: "text", text: "ok" }],
			details: { fullOutputPath: artifact },
		});
		const text = readFileSync(artifact, "utf8");
		assert.equal(text.includes(SECRET), false);
		assert.match(text, /BW_SCRUBBED/);
	} finally {
		rmSync(artifact, { force: true });
	}

	// A non-bash result, or a bash result pointing outside the temp dir, is ignored.
	const outside = mkdtempSync(join(tmpdir(), "omp-vault-artifact-"));
	const big = join(outside, "big.log");
	writeFileSync(big, "x".repeat(9 * 1024 * 1024));
	try {
		await b.fire("tool_result", {
			toolName: "read",
			content: [{ type: "text", text: "ok" }],
			details: { fullOutputPath: big },
		});
		assert.equal(existsSync(big), true, "a non-bash result deleted a file");
		await b.fire("tool_result", {
			toolName: "bash",
			content: [{ type: "text", text: "ok" }],
			details: { fullOutputPath: big },
		});
		assert.equal(existsSync(big), true, "a bash result deleted a file outside the temp dir");
	} finally {
		rmSync(outside, { recursive: true, force: true });
	}

	// A symlink with an artifact name is not followed.
	const targetDir = mkdtempSync(join(tmpdir(), "omp-vault-artifact-"));
	const target = join(targetDir, "target");
	writeFileSync(target, `target ${SECRET}`);
	const link = join(tmpdir(), `pi-bash-${randomBytes(8).toString("hex")}.log`);
	symlinkSync(target, link);
	try {
		await b.fire("tool_result", {
			toolName: "bash",
			content: [{ type: "text", text: "ok" }],
			details: { fullOutputPath: link },
		});
		assert.match(readFileSync(target, "utf8"), /target/);
	} finally {
		rmSync(link, { force: true });
		rmSync(targetDir, { recursive: true, force: true });
	}
});

test("the confirm window names the entry that was really matched", async () => {
	const b = bind(ompVault, true);
	await b.tool("bw_run", { item: "Test", command: "true" });
	assert.match(dialogTrace(dir), /--question .*Item:   TestService \(user: alice\)⏎Field:  password⏎Env:     \$VAULT_SECRET/);

	answers.deny(dir, true);
	await assert.rejects(b.tool("bw_run", { item: "Test", command: "true" }), /User declined/);
	assert.match(bwAudit(), /run deny item="TestService" field=password/);
	answers.deny(dir, false);
});

test("omp: /new and /fork lock Bitwarden; session_start and /resume do not", async () => {
	const b = bind(ompVault, true);
	const ctx = makeCtx();
	await b.tool("bw_list", {}, ctx.ctx);
	const prompts = passwordPrompts(dir);

	await b.fire("session_start", {}, ctx.ctx);
	await b.fire("session_switch", { reason: "resume" }, ctx.ctx);
	await b.tool("bw_list", {}, ctx.ctx);
	assert.equal(passwordPrompts(dir), prompts, "session_start or /resume locked Bitwarden");

	await b.fire("session_switch", { reason: "new" }, ctx.ctx);
	await b.tool("bw_list", {}, ctx.ctx);
	assert.equal(passwordPrompts(dir), prompts + 1, "/new did not lock Bitwarden");

	await b.fire("session_switch", { reason: "fork" }, ctx.ctx);
	await b.tool("bw_list", {}, ctx.ctx);
	assert.equal(passwordPrompts(dir), prompts + 2, "/fork did not lock Bitwarden");
	assert.match(bwAudit(), /lock reason=session-new/);
});

test("a second binding, a subagent or another session, does not inherit the unlock", async () => {
	const first = bind(ompVault, true);
	const second = bind(ompVault, true);
	await first.tool("bw_list", {}, makeCtx().ctx);
	const prompts = passwordPrompts(dir);
	await second.tool("bw_list", {}, makeCtx().ctx);
	assert.equal(passwordPrompts(dir), prompts + 1, "the second binding used the first one's unlock");
});

test("bw_reveal stays off until allowReveal is set", async () => {
	const b = bind(ompVault, true);
	await assert.rejects(b.tool("bw_reveal", { item: "TestService", reason: "test" }), /disabled/);
});

test("a session switch while the master password is being typed discards the unlock", async () => {
	delete process.env.DISPLAY;
	delete process.env.WAYLAND_DISPLAY;
	try {
		const b = bind(ompVault, true);
		let answer;
		const ctx = makeCtx({ input: () => new Promise((resolve) => (answer = resolve)) });
		const pending = b.tool("bw_list", {}, ctx.ctx).then(
			() => "resolved",
			(error) => error.message,
		);
		for (let i = 0; i < 50 && !answer; i++) await new Promise((resolve) => setImmediate(resolve));
		assert.equal(typeof answer, "function", "the password dialog opened");

		await b.fire("session_switch", { reason: "new" }, ctx.ctx);
		answer("testmaster");
		assert.equal(await pending, "Cancelled.");
	} finally {
		process.env.DISPLAY = ":99";
	}
});

test("bw_run stops buffering runaway output instead of growing without bound", async () => {
	const b = bind(ompVault, true);
	const result = await b.tool("bw_run", { item: "TestService", command: "head -c 10485760 /dev/zero | tr '\\0' x" });
	assert.equal(result.details.truncated, true);
	assert.match(textOf(result), /output past 8 MiB was dropped/);
});

test("a timed-out bw_run takes the processes it spawned down with it", async () => {
	const b = bind(ompVault, true);
	await assert.rejects(b.tool("bw_run", { item: "TestService", command: "sleep 987 & wait", timeout: 1 }), /timed out/);
	await new Promise((resolve) => setTimeout(resolve, 200));
	assert.equal(spawnSync("pgrep", ["-f", "sleep 987"]).status, 1, "the spawned sleep outlived the command");
});

test("bw_clipboard copies the value without it entering the result, and registers it for scrubbing", async () => {
	delete process.env.DISPLAY;
	process.env.WAYLAND_DISPLAY = "wayland-99";
	// A custom field that no earlier test has put in the scrub list.
	const CLIP = "hf_sk-abc987xyz456";
	try {
		const b = bind(ompVault, true);
		const out = textOf(await b.tool("bw_clipboard", { item: "TestService", field: "field:API_KEY" }));
		assert.match(out, /Copied "TestService" \(field:API_KEY\) to clipboard/);
		assert.equal(out.includes(CLIP), false);
		assert.equal(readFileSync(join(dir, "clipboard"), "utf8"), CLIP);

		// `pbpaste`/`xclip -o`/`wl-paste` in bash can now read the value back,
		// so its appearance in any tool result must be scrubbed.
		const [scrubbed] = await b.fire("tool_result", {
			toolName: "bash",
			content: [{ type: "text", text: `clip=${CLIP}` }],
			details: {},
		});
		assert.match(textOf(scrubbed), /\[BW_SCRUBBED:CLIPBOARD\]/);
		assert.equal(textOf(scrubbed).includes(CLIP), false);
	} finally {
		delete process.env.WAYLAND_DISPLAY;
		process.env.DISPLAY = ":99";
	}
});
