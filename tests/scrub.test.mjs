import { test } from "node:test";
import assert from "node:assert/strict";
import { scrubDeep, scrubText } from "../packages/pi-ai-vault/src/scrub.ts";

const SECRET = "supersecret-value-123";
const values = [{ env: "T1", value: SECRET }];

test("redacts the raw value", () => {
	const result = scrubText(`out: ${SECRET}\n`, values);
	assert.equal(result.changed, true);
	assert.equal(result.text, "out: [BW_SCRUBBED:T1]\n");
});

test("redacts base64 and base64url", () => {
	const raw = `${SECRET}x`;
	const b64 = Buffer.from(raw).toString("base64");
	const b64url = b64.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
	const result = scrubText(`${b64} ${b64url}`, [{ env: "T1", value: raw }]);
	assert.equal(result.text, "[BW_SCRUBBED-B64:T1] [BW_SCRUBBED-B64URL:T1]");
});

test("redacts base64 and hex that are wrapped or spaced", () => {
	// GNU base64 wraps at 76 columns; xxd/od put spaces between hex bytes.
	const raw = `${"correct-horse-battery-staple-".repeat(4)}end`;
	const b64 = Buffer.from(raw).toString("base64");
	assert.ok(b64.length > 76, "the fixture is long enough to wrap");
	const wrapped = b64.match(/.{1,76}/g).join("\n");
	const hex = Buffer.from(raw).toString("hex");
	const spaced = hex.match(/.{1,2}/g).join(" ");
	const result = scrubText(`b64:\n${wrapped}\nhex: ${spaced}\n`, [{ env: "W", value: raw }]);
	assert.equal(result.changed, true);
	assert.equal(result.text.includes("correct-horse"), false);
	assert.match(result.text, /\[BW_SCRUBBED-B64:W\]/);
	assert.match(result.text, /\[BW_SCRUBBED-HEX:W\]/);
});

test("redacts base64 of a short password", () => {
	// `echo -n "$VAULT_SECRET" | base64` must not leak an everyday password.
	const raw = "hunter2abcd";
	const result = scrubText(`| ${Buffer.from(raw).toString("base64")} |`, [{ env: "T1", value: raw }]);
	assert.equal(result.text, "| [BW_SCRUBBED-B64:T1] |");
});

test("redacts URL-encoded and hex forms", () => {
	const raw = "a b&c=d/e";
	const result = scrubText(`${encodeURIComponent(raw)} ${Buffer.from(raw).toString("hex")}`, [{ env: "U", value: raw }]);
	assert.equal(result.text, "[BW_SCRUBBED-URL:U] [BW_SCRUBBED-HEX:U]");
});

test("leaves short values and unrelated text alone", () => {
	assert.equal(scrubText("abc abc", [{ env: "S", value: "abc" }]).changed, false);
	assert.equal(scrubText("nothing here", values).changed, false);
});

test("scrubs nested details and preserves unchanged objects", () => {
	const input = { trace: { units: [{ source: `export T1='${SECRET}'` }], history: [["argv", SECRET]] } };
	const result = scrubDeep(input, values);
	assert.equal(result.changed, true);
	assert.equal(JSON.stringify(result.value).includes(SECRET), false);
	const plain = { ok: true, count: 3, list: [null, "plain"] };
	const same = scrubDeep(plain, values);
	assert.equal(same.changed, false);
	assert.equal(same.value, plain);
});

test("leaves a Date, a Buffer, or a class instance as the object it was", () => {
	class Handle {
		constructor() {
			this.fd = 3;
		}
	}
	const date = new Date(0);
	const blob = Buffer.from("abc");
	const handle = new Handle();
	const result = scrubDeep({ at: date, blob, handle, note: SECRET }, values);
	assert.equal(result.changed, true);
	assert.equal(result.value.at, date);
	assert.equal(result.value.blob, blob);
	assert.equal(result.value.handle, handle);
	assert.equal(result.value.note, "[BW_SCRUBBED:T1]");
});

test("scrubs a Buffer, Map, Set, and Error that carry a secret", () => {
	const blob = Buffer.from(`raw ${SECRET}`);
	const map = new Map([[SECRET, "value"], ["key", SECRET]]);
	const set = new Set([SECRET, "plain"]);
	const err = new Error(`failed with ${SECRET}`);
	const result = scrubDeep({ blob, map, set, err }, values);
	assert.equal(result.changed, true);
	assert.equal(result.value.blob.toString("utf8").includes(SECRET), false);
	assert.equal([...result.value.map.keys()].some((k) => String(k).includes(SECRET)), false);
	assert.equal([...result.value.map.values()].some((v) => String(v).includes(SECRET)), false);
	assert.equal([...result.value.set].some((v) => String(v).includes(SECRET)), false);
	assert.equal(result.value.err.message.includes(SECRET), false);
	assert.ok(result.value.err instanceof Error);
	// The clean forms keep their identity, so the host's own objects are not replaced.
	assert.equal(scrubDeep(blob, []).value, blob);
});
