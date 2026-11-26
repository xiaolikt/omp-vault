import { test } from "node:test";
import assert from "node:assert/strict";
import { bitwardenLogins, filterLogins } from "../src/import-map.ts";

const item = (name, extra = {}) => ({
	id: extra.id,
	name,
	login: { username: extra.username, password: extra.password ?? "pw-value-1", uris: extra.uri ? [{ uri: extra.uri }] : [] },
	notes: extra.notes,
});

test("reads a Bitwarden export object and a raw array", () => {
	const fromExport = bitwardenLogins({
		items: [item("GitHub", { username: "me", uri: "https://github.com", notes: "n" })],
	});
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

test("each entry keeps the id of the Bitwarden item it came from", () => {
	const [draft] = bitwardenLogins({ items: [item("Cloud", { id: "bw-1", username: "root" })] });
	assert.deepEqual(draft.source, { kind: "bitwarden", id: "bw-1" });
});

test("an encrypted export is refused instead of importing nothing", () => {
	assert.throws(
		() => bitwardenLogins({ encrypted: true, encKeyValidation: "…", data: "2.0|…" }),
		/encrypted Bitwarden export/,
	);
});

test("a payload that is neither an export nor an item array is refused", () => {
	assert.throws(() => bitwardenLogins({ hello: "world" }), /Not a Bitwarden export/);
	assert.throws(() => bitwardenLogins(null), /Not a Bitwarden export/);
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
	const drafts = bitwardenLogins([item("GitHub", { username: "b" }), item("GitHub", { username: "a" }), item("Other", { username: "z" })]);
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
