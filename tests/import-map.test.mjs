import { test } from "node:test";
import assert from "node:assert/strict";
import { bitwardenItems, filterItems, isSecretField, parseItemType } from "../packages/pi-ai-vault/src/import-map.ts";

const login = (name, extra = {}) => ({
	id: extra.id,
	type: 1,
	name,
	login: { username: extra.username, password: extra.password ?? "pw-value-1", uris: extra.uri ? [{ uri: extra.uri }] : [] },
	notes: extra.notes,
	fields: extra.fields,
});

test("reads a Bitwarden export object and a raw array", () => {
	const fromExport = bitwardenItems({ items: [login("GitHub", { username: "me", uri: "https://github.com", notes: "n" })] });
	const fromArray = bitwardenItems([login("GitHub", { username: "me", uri: "https://github.com", notes: "n" })]);
	assert.equal(fromExport.length, 1);
	assert.deepEqual(fromExport[0], {
		name: "GitHub",
		type: "login",
		username: "me",
		password: "pw-value-1",
		uris: ["https://github.com"],
		notes: "n",
	});
	assert.deepEqual(fromArray, fromExport);
});

test("every item type maps field for field, by Bitwarden's names", () => {
	const drafts = bitwardenItems({
		items: [
			{ id: "n", type: 2, name: "Wifi", secureNote: {}, notes: "guest: hunter2" },
			{ id: "c", type: 3, name: "Visa", card: { cardholderName: "Li", brand: "Visa", number: "4111", expMonth: "12", expYear: "2029", code: "123" } },
			{ id: "i", type: 4, name: "Me", identity: { title: "Mr", firstName: "Jun", lastName: "Li", ssn: "123-45-6789" } },
			{ id: "k", type: 5, name: "key", sshKey: { privateKey: "PEM", publicKey: "ssh-ed25519 AAA", keyFingerprint: "SHA256:x" } },
			{ id: "b", type: 6, name: "Bank", bankAccount: { bankName: "ICBC", accountNumber: "6222", pin: "9080", iban: null } },
			{ id: "d", type: 7, name: "Licence", driversLicense: { licenseNumber: "110101", expirationDate: "2030-01-01" } },
			{ id: "p", type: 8, name: "Passport", passport: { passportNumber: "E123", nationality: "CN" } },
		],
	});
	const byName = Object.fromEntries(drafts.map((d) => [d.name, d]));
	assert.equal(byName.Wifi.type, "secureNote");
	assert.equal(byName.Wifi.notes, "guest: hunter2");
	assert.equal(byName.Wifi.data, undefined, "a secure note has no fields of its own");
	assert.deepEqual(byName.Visa.data, { cardholderName: "Li", brand: "Visa", number: "4111", expMonth: "12", expYear: "2029", code: "123" });
	assert.equal(byName.Me.data.ssn, "123-45-6789");
	assert.equal(byName["key"].data.privateKey, "PEM");
	assert.deepEqual(byName.Bank.data, { bankName: "ICBC", accountNumber: "6222", pin: "9080" }, "a null field is dropped");
	assert.equal(byName.Licence.data.licenseNumber, "110101");
	assert.equal(byName.Passport.data.passportNumber, "E123");
	assert.equal(byName.Me.password, undefined, "only a login carries the flat password mirror");
});

test("custom fields keep their Bitwarden type, so a hidden one stays hidden", () => {
	const [draft] = bitwardenItems([login("GH", { fields: [{ name: "API_KEY", value: "hf_abc", type: 1 }, { name: "Plan", value: "Team", type: 0 }] })]);
	assert.deepEqual(draft.fields, [
		{ name: "API_KEY", value: "hf_abc", type: 1 },
		{ name: "Plan", value: "Team", type: 0 },
	]);
});

test("each entry keeps the id of the Bitwarden item it came from", () => {
	const [draft] = bitwardenItems({ items: [login("Cloud", { id: "bw-1", username: "root" })] });
	assert.deepEqual(draft.source, { kind: "bitwarden", id: "bw-1" });
});

test("an encrypted export is refused instead of importing nothing", () => {
	assert.throws(() => bitwardenItems({ encrypted: true, encKeyValidation: "…", data: "2.0|…" }), /encrypted Bitwarden export/);
});

test("a payload that is neither an export nor an item array is refused", () => {
	assert.throws(() => bitwardenItems({ hello: "world" }), /Not a Bitwarden export/);
	assert.throws(() => bitwardenItems(null), /Not a Bitwarden export/);
});

test("an unknown type number is an error, a blank name becomes 'unnamed'", () => {
	assert.throws(() => bitwardenItems([{ type: 99, name: "x" }]), /unsupported Bitwarden item type 99/);
	const [draft] = bitwardenItems([{ type: 1, name: "  \n", login: { password: "p" } }]);
	assert.equal(draft.name, "unnamed");
});

test("disambiguates duplicate names within a type, not across types", () => {
	const drafts = bitwardenItems([login("GitHub", { username: "b" }), login("GitHub", { username: "a" }), { type: 2, name: "GitHub", secureNote: {} }]);
	const names = drafts.map((d) => `${d.type}:${d.name}|${d.username ?? ""}`);
	assert.deepEqual(names, ["login:GitHub|a", "login:GitHub (2)|b", "secureNote:GitHub|"]);
});

test("type names parse the way a human writes them", () => {
	assert.equal(parseItemType(undefined), "login");
	assert.equal(parseItemType("SSH key"), "sshKey");
	assert.equal(parseItemType("secure-note"), "secureNote");
	assert.equal(parseItemType("driver's licence"), "driversLicense");
	assert.equal(parseItemType("wifi"), undefined);
});

test("secret fields are known per type", () => {
	assert.equal(isSecretField("login", "password"), true);
	assert.equal(isSecretField("card", "number"), true);
	assert.equal(isSecretField("card", "brand"), false);
	assert.equal(isSecretField("bankAccount", "pin"), true);
	assert.equal(isSecretField("identity", "ssn"), true);
	assert.equal(isSecretField("passport", "passportNumber"), true);
	assert.equal(isSecretField("passport", "nationality"), false);
});

test("filterItems matches name, username, and URIs across every type", () => {
	const items = bitwardenItems([login("GitHub", { username: "me", uri: "https://github.com" }), { type: 3, name: "Visa", card: { brand: "Visa" } }]);
	assert.equal(filterItems(items, "visa")[0]?.name, "Visa");
	assert.equal(filterItems(items, "github.com")[0]?.name, "GitHub");
	assert.equal(filterItems(items).length, 2);
});
