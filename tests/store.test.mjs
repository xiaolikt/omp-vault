import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Vault } from "../src/store.ts";
import { appendAudit, readAudit } from "../src/audit.ts";
const newVault = () => new Vault(mkdtempSync(join(tmpdir(), "omp-vault-")));
const PW = "correct horse battery";

test("init + reopen roundtrip keeps items", () => {
	const dir = mkdtempSync(join(tmpdir(), "omp-vault-"));
	const v = new Vault(dir);
	v.init(PW);
	v.upsert({ name: "CloudCone", username: "root", password: "s3cret", uris: ["ssh://1.2.3.4"] });
	assert.ok(existsSync(join(dir, "store.json")));

	// On-disk bytes must not contain the secret.
	const raw = readFileSync(join(dir, "store.json"), "utf8");
	assert.ok(!raw.includes("s3cret"), "ciphertext leaked the secret");

	const reopened = new Vault(dir);
	assert.equal(reopened.unlocked, false);
	assert.equal(reopened.unlock("wrong"), false);
	assert.equal(reopened.unlock(PW), true);
	const item = reopened.find("cloudcone"); // case-insensitive
	assert.equal(item?.password, "s3cret");
	rmSync(dir, { recursive: true, force: true });
});

test("upsert updates by name, remove deletes", () => {
	const v = newVault();
	v.init("passphrase-1");
	v.upsert({ name: "a", password: "1" });
	v.upsert({ name: "a", password: "2" });
	assert.equal(v.list().length, 1);
	assert.equal(v.find("a")?.password, "2");
	assert.equal(v.remove("a"), true);
	assert.equal(v.list().length, 0);
});

test("upsertMany stores every entry", () => {
	const v = newVault();
	v.init("passphrase-1");
	assert.equal(v.upsertMany([]), 0);
	assert.equal(
		v.upsertMany([
			{ name: "a", password: "1" },
			{ name: "b", password: "2" },
			{ name: "a", password: "3" },
		]),
		3,
	);
	assert.deepEqual(
		v.list().map((i) => [i.name, i.password]),
		[
			["a", "3"],
			["b", "2"],
		],
	);
});

test("a re-import follows the Bitwarden id when the duplicate numbering shifts", () => {
	const v = newVault();
	v.init("passphrase-1");
	const bw = (id) => ({ kind: "bitwarden", id });
	v.upsertMany([
		{ name: "GitHub", password: "a", source: bw("id-1") },
		{ name: "GitHub (2)", password: "b", source: bw("id-2") },
	]);
	// In Bitwarden the first entry is gone, so the second one is now the only "GitHub".
	v.upsertMany([{ name: "GitHub", password: "b2", source: bw("id-2") }]);
	// The row that came from id-2 is the one updated, and its name does not collide.
	assert.deepEqual(
		v.list().map((i) => [i.name, i.password]),
		[
			["GitHub", "a"],
			["GitHub (2)", "b2"],
		],
	);
	// With no clash the new name is taken over.
	v.upsertMany([{ name: "GitLab", password: "b3", source: bw("id-2") }]);
	assert.equal(v.find("GitLab")?.password, "b3");
	assert.equal(v.find("GitHub (2)"), undefined);
});

test("the KDF parameters are stored, and a file from before that still opens", () => {
	const dir = mkdtempSync(join(tmpdir(), "omp-vault-"));
	const file = join(dir, "store.json");
	new Vault(dir).init(PW);
	assert.deepEqual(JSON.parse(readFileSync(file, "utf8")).kdf, { N: 32768, r: 8, p: 1 });
	// Drop the field, as a store written by the previous version would not have it.
	const legacy = JSON.parse(readFileSync(file, "utf8"));
	delete legacy.kdf;
	writeFileSync(file, JSON.stringify(legacy));
	const v = new Vault(dir);
	assert.equal(v.unlock(PW), true);
	rmSync(dir, { recursive: true, force: true });
});

test("copies do not share mutable state with the store", () => {
	const v = newVault();
	v.init("passphrase-3");
	v.upsert({ name: "a", password: "x", uris: ["u1"] });
	for (const copy of [v.find("a"), v.list()[0]]) {
		copy.uris.push("injected");
		copy.password = "changed";
	}
	assert.deepEqual(v.find("a")?.uris, ["u1"]);
	assert.equal(v.find("a")?.password, "x");
});

test("a wrong passphrase leaves an unlocked store as it is", () => {
	const v = newVault();
	v.init("passphrase-4");
	v.upsert({ name: "a", password: "x" });
	assert.equal(v.unlock("wrong"), false);
	assert.equal(v.unlocked, true);
	assert.equal(v.find("a")?.password, "x");
});

test("init counts as activity, so a long-running process does not lock a new store at once", () => {
	const v = newVault();
	const now = Date.now;
	Date.now = () => now() + 11 * 60_000;
	try {
		v.init("passphrase-5");
		assert.equal(v.maybeAutoLock(10 * 60_000), false);
	} finally {
		Date.now = now;
	}
});

test("a corrupt store fails with an error instead of opening", () => {
	const dir = mkdtempSync(join(tmpdir(), "omp-vault-"));
	writeFileSync(join(dir, "store.json"), "{ not json");
	assert.throws(() => new Vault(dir).unlock(PW));
	rmSync(dir, { recursive: true, force: true });
});

test("lock drops secrets; auto-lock triggers on idle", () => {
	const v = newVault();
	v.init("passphrase-2");
	v.upsert({ name: "b", password: "x" });
	v.lock();
	assert.equal(v.unlocked, false);
	assert.throws(() => v.list());
	assert.equal(v.maybeAutoLock(0), false); // already locked
	v.unlock("passphrase-2");
	assert.equal(v.maybeAutoLock(0), true); // idle threshold 0 -> locks
	assert.equal(v.unlocked, false);
});

test("audit append + read", () => {
	const dir = mkdtempSync(join(tmpdir(), "omp-vault-"));
	const file = join(dir, "audit.log");
	assert.equal(appendAudit({ session: "t", event: "read_allow", item: "x" }, file), true);
	appendAudit({ session: "t", event: "read_deny", item: "y" }, file);
	const entries = readAudit(file, 10);
	assert.equal(entries.length, 2);
	assert.equal(entries[0]?.event, "read_allow");
	assert.ok(entries[1]?.ts);
	rmSync(dir, { recursive: true, force: true });
});

test("an audit log that cannot be written does not fail the caller", () => {
	const dir = mkdtempSync(join(tmpdir(), "omp-vault-"));
	// A directory where the log file would go: every append fails.
	const blocked = join(dir, "audit.log");
	mkdirSync(blocked);
	assert.equal(appendAudit({ session: "t", event: "list" }, blocked), false);
	rmSync(dir, { recursive: true, force: true });
});
