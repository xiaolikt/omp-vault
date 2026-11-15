import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Vault } from "../src/store.ts";
import { appendAudit, readAudit } from "../src/audit.ts";
const newVault = () => new Vault(mkdtempSync(join(tmpdir(), "omp-vault-")));

test("init + reopen roundtrip keeps items", () => {
	const dir = mkdtempSync(join(tmpdir(), "omp-vault-"));
	const v = new Vault(dir);
	v.init("correct horse battery");
	v.upsert({ name: "CloudCone", username: "root", password: "s3cret", uris: ["ssh://1.2.3.4"] });
	assert.ok(existsSync(join(dir, "store.json")));

	// On-disk bytes must not contain the secret.
	const raw = readFileSync(join(dir, "store.json"), "utf8");
	assert.ok(!raw.includes("s3cret"), "ciphertext leaked the secret");

	const reopened = new Vault(dir);
	assert.equal(reopened.unlocked, false);
	assert.equal(reopened.unlock("wrong"), false);
	assert.equal(reopened.unlock("correct horse battery"), true);
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
	appendAudit({ session: "t", event: "read_allow", item: "x" }, file);
	appendAudit({ session: "t", event: "read_deny", item: "y" }, file);
	const entries = readAudit(file, 10);
	assert.equal(entries.length, 2);
	assert.equal(entries[0]?.event, "read_allow");
	assert.ok(entries[1]?.ts);
	rmSync(dir, { recursive: true, force: true });
});
