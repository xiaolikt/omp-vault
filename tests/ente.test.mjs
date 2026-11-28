import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { answers, bind, cleanUpOnExit, dialogTrace, makeCtx, textOf, useMocks } from "./helpers.mjs";

const dir = useMocks();
const { default: aiVault } = await import("../packages/pi-ai-vault/src/index.ts");
cleanUpOnExit(dir);

const enteLog = () => {
	try {
		return readFileSync(join(dir, "ente.log"), "utf8");
	} catch {
		return "";
	}
};
const codePrompts = () => dialogTrace(dir).split("\n").filter((line) => line.includes("Ente Auth")).length;

test("ente_list returns metadata and never touches a code", async () => {
	const b = bind(aiVault, true);
	const result = await b.tool("ente_list", {}, makeCtx().ctx);
	assert.equal(result.isError, undefined);
	const items = JSON.parse(textOf(result));
	assert.deepEqual(items.map((i) => i.name), ["GitHub", "Cloudflare", "Steam"]);
	assert.equal(items[0].otp, undefined, "listing must not leak a code");
	assert.equal(/auth code view/.test(enteLog()), false, "listing must not run a code view");
});

test("ente_code asks a window naming the entry, then returns the code", async () => {
	const b = bind(aiVault, true);
	const ctx = makeCtx().ctx;
	const before = codePrompts();
	answers.questions(dir, "y");
	const result = await b.tool("ente_code", { name: "github" }, ctx);
	const body = JSON.parse(textOf(result));
	assert.equal(result.details.via ?? body.via, "ente");
	assert.equal(body.code, "00420731", "leading zeroes survive");
	assert.match(dialogTrace(dir), /GitHub/);
	assert.equal(codePrompts(), before + 1);
});

test("ente_code denial is reported and not retried", async () => {
	const b = bind(aiVault, true);
	answers.questions(dir, "n");
	const result = await b.tool("ente_code", { name: "Cloudflare" }, makeCtx().ctx);
	assert.equal(result.isError, true);
	assert.equal(result.details.denied, true);
	assert.match(textOf(result), /do not retry/);
});

test("ente_code reports the candidates when the name matches more than one", async () => {
	const b = bind(aiVault, true);
	answers.questions(dir, "y");
	const result = await b.tool("ente_code", { name: "example.com" }, makeCtx().ctx);
	// "example.com" is part of two account names, so no single entry is chosen.
	assert.equal(result.isError, true);
	assert.match(textOf(result), /no single Ente entry matches/);
	assert.match(textOf(result), /Cloudflare/);
});

test("ente tools say what to do when the CLI has no account", async () => {
	writeFileSync(join(dir, "unauthenticated"), "");
	writeFileSync(join(dir, "no-cache"), "");
	const b = bind(aiVault, true);
	const result = await b.tool("ente_list", {}, makeCtx().ctx);
	assert.equal(result.isError, true, textOf(result));
	assert.match(textOf(result), /ente account login|no account/i);
	rmSync(join(dir, "unauthenticated"), { force: true });
	rmSync(join(dir, "no-cache"), { force: true });
});

test("a secrets audit line exists for allow and deny, without the code", async () => {
	const log = readFileSync(join(process.env.HOME, ".bw", "pi-extension", "audit.log"), "utf8");
	assert.match(log, /ente\.code session=\S+ allow item="GitHub"/);
	assert.match(log, /ente\.code session=\S+ deny item="Cloudflare"/);
	assert.equal(log.includes("00420731"), false, "the audit log must not carry the code");
});

test("a failed sync falls back to the offline cache", async () => {
	writeFileSync(join(dir, "list-fails-once"), "");
	const b = bind(aiVault, true);
	const result = await b.tool("ente_list", {}, makeCtx().ctx);
	assert.equal(result.isError, undefined, textOf(result));
	assert.equal(JSON.parse(textOf(result)).length, 3);
});
