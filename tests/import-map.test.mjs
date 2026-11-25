import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bitwardenLogins, filterLogins } from "../src/import-map.ts";
import { Vault } from "../src/store.ts";

const item = (name, extra = {}) => ({
	name,
	login: { username: extra.username, password: extra.password ?? "pw-value-1", uris: extra.uri ? [{ uri: extra.uri }] : [] },
	notes: extra.notes,
});

test("reads a Bitwarden export object and a raw array", () => {
	const fromExport = bitwardenLogins({ items: [item("GitHub", { username: "me", uri: "https://github.com", notes: "n" })] });
	const fromArray = bitwardenLogins([item("GitHub", { username: "me", uri: "https://github.com", notes: "n" })]);
	assert.equal(fromExport.length, 1);
	assert.deepEqual(fromExport[0], {
		name: "GitHub",
		username: "me",
		password: "pw-value-1",
		uris: ["https://github.com"],
		notes: "n",
	});
	assert.deepEqual(fromArray, fromExport);
});

test("skips items with no login password and blank names", () => {
	const drafts = bitwardenLogins({
		items: [
			{ name: "note-only", notes: "x" },
			{ name: "empty-login", login: { username: "a", password: "" } },
			{ name: "  \n", login: { password: "pw-value-1" } },
		],
	});
	assert.equal(drafts.length, 1);
	assert.equal(drafts[0].name, "unnamed");
});

test("disambiguates duplicate names in a stable order", () => {
	const drafts = bitwardenLogins([
		item("GitHub", { username: "b" }),
		item("GitHub", { username: "a" }),
		item("Other", { username: "z" }),
	]);
	assert.deepEqual(
		drafts.map((d) => `${d.name}|${d.username}`),
		["GitHub|a", "GitHub (2)|b", "Other|z"],
	);
});

test("filter matches name, username, and uri", () => {
	const drafts = bitwardenLogins([
		item("GitHub", { username: "octo", uri: "https://github.com" }),
		item("Mail", { username: "me", uri: "https://mail.example" }),
	]);
	assert.equal(filterLogins(drafts, "octo").length, 1);
	assert.equal(filterLogins(drafts, "mail.example")[0].name, "Mail");
	assert.equal(filterLogins(drafts, "nope").length, 0);
	assert.equal(filterLogins(drafts, "  ").length, 2);
});

test("imported password is not stored in plaintext", () => {
	const [draft] = bitwardenLogins([item("Cloud", { password: "hunter2-extra", username: "root" })]);
	const dir = mkdtempSync(join(tmpdir(), "omp-vault-import-"));
	const vault = new Vault(dir);
	vault.init("correct horse battery");
	vault.upsert(draft);
	const raw = readFileSync(join(dir, "store.json"), "utf8");
	assert.equal(raw.includes("hunter2-extra"), false);
	const reopened = new Vault(dir);
	assert.equal(reopened.unlock("correct horse battery"), true);
	assert.equal(reopened.find("cloud")?.password, "hunter2-extra");
	rmSync(dir, { recursive: true, force: true });
});
