/**
 * Map a Bitwarden item onto a local vault entry, for every item type, field
 * for field — the same table the CLI's `import.rs` uses, so both import paths
 * (the CLI's `import` and this extension's `import-bw` / `vault_get` fallback)
 * write identical entries.
 *
 * Type numbers and field names are Bitwarden's own, read out of its CLI:
 *   1 login · 2 secureNote · 3 card · 4 identity · 5 sshKey
 *   6 bankAccount · 7 driversLicense · 8 passport   (behind its "new item types" flag)
 * A secure note has no fields of its own: its content is the item's `notes`.
 */
import type { Draft, Field, ItemType } from "./types.js";

export const ITEM_TYPES: Record<ItemType, { code: number; key: string; fields: string[]; primary?: string }> = {
	login: { code: 1, key: "login", fields: ["username", "password", "totp"], primary: "password" },
	secureNote: { code: 2, key: "secureNote", fields: [] },
	card: { code: 3, key: "card", fields: ["cardholderName", "brand", "number", "expMonth", "expYear", "code"], primary: "code" },
	identity: {
		code: 4,
		key: "identity",
		fields: [
			"title", "firstName", "middleName", "lastName", "address1", "address2", "address3", "city", "state",
			"postalCode", "country", "company", "email", "phone", "ssn", "username", "passportNumber", "licenseNumber",
		],
	},
	sshKey: { code: 5, key: "sshKey", fields: ["privateKey", "publicKey", "keyFingerprint"], primary: "privateKey" },
	bankAccount: {
		code: 6,
		key: "bankAccount",
		fields: ["bankName", "nameOnAccount", "accountType", "accountNumber", "routingNumber", "branchNumber", "pin", "swiftCode", "iban", "bankContactPhone"],
		primary: "pin",
	},
	driversLicense: {
		code: 7,
		key: "driversLicense",
		fields: ["firstName", "middleName", "lastName", "dateOfBirth", "licenseNumber", "issuingCountry", "issuingState", "issueDate", "expirationDate", "issuingAuthority", "licenseClass"],
	},
	passport: {
		code: 8,
		key: "passport",
		fields: [
			"surname", "givenName", "dateOfBirth", "sex", "birthPlace", "nationality", "issuingCountry", "passportNumber",
			"passportType", "nationalIdentificationNumber", "issuingAuthority", "issueDate", "expirationDate",
		],
	},
};

const BY_CODE = new Map(Object.entries(ITEM_TYPES).map(([name, spec]) => [spec.code, name as ItemType]));

/** The item type for Bitwarden's `.type`, as a human types it: note, ssh key, … */
export function parseItemType(raw: string | undefined): ItemType | undefined {
	if (!raw) return "login";
	const key = raw.toLowerCase().replace(/[^a-z0-9]/g, "");
	const aliases: Record<string, ItemType> = {
		login: "login",
		password: "login",
		note: "secureNote",
		securenote: "secureNote",
		card: "card",
		creditcard: "card",
		identity: "identity",
		person: "identity",
		sshkey: "sshKey",
		ssh: "sshKey",
		key: "sshKey",
		bankaccount: "bankAccount",
		bank: "bankAccount",
		driverslicense: "driversLicense",
		driverlicense: "driversLicense",
		driverslicence: "driversLicense",
		drivinglicence: "driversLicense",
		license: "driversLicense",
		passport: "passport",
	};
	return aliases[key] ?? (key === "" ? "login" : undefined);
}

/** Fields whose value never appears in a listing or a confirm window. */
export function isSecretField(type: ItemType, field: string): boolean {
	if (["password", "privateKey", "totp", "ssn", "licenseNumber", "passportNumber"].includes(field)) return true;
	if (type === "card") return field === "code" || field === "number";
	if (type === "bankAccount") return ["pin", "accountNumber", "routingNumber"].includes(field);
	if (type === "passport") return field === "nationalIdentificationNumber";
	return false;
}

const asRecord = (value: unknown): Record<string, unknown> | undefined =>
	value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
const text = (value: unknown): string | undefined => (typeof value === "string" && value.length > 0 ? value : undefined);

function asItems(raw: unknown): unknown[] {
	if (Array.isArray(raw)) return raw;
	const rec = asRecord(raw);
	if (rec) {
		if (rec.encrypted === true) {
			throw new Error("This is an encrypted Bitwarden export. Use `bw export --format json` (unencrypted) or /vault import-bw.");
		}
		if (Array.isArray(rec.items)) return rec.items;
	}
	throw new Error("Not a Bitwarden export: expected an array of items or an object with `items`.");
}

/** Custom fields as Bitwarden stores them: 0 text · 1 hidden · 2 boolean · 3 linked. */
function customFields(rec: Record<string, unknown>): Field[] | undefined {
	const list = Array.isArray(rec.fields) ? rec.fields : [];
	const out: Field[] = [];
	for (const raw of list) {
		const f = asRecord(raw);
		if (!f) continue;
		out.push({
			name: text(f.name) ?? "",
			value: typeof f.value === "string" ? f.value : "",
			type: typeof f.type === "number" ? f.type : 0,
			...(typeof f.linkedId === "number" ? { linkedId: String(f.linkedId) } : {}),
		});
	}
	return out.length > 0 ? out : undefined;
}

const cleanName = (raw: unknown): string => {
	const cleaned = (typeof raw === "string" ? raw : "").replace(/[\r\n]+/g, " ").trim().slice(0, 200);
	return cleaned || "unnamed";
};

/**
 * Every item of a Bitwarden export (or `bw list items` payload) as a draft.
 * Items are matched to local entries by Bitwarden id, so a re-import updates
 * the same row after a rename. Duplicate names within a type become `Name (2)`.
 */
export function bitwardenItems(raw: unknown): Draft[] {
	const drafts: Draft[] = [];
	for (const item of asItems(raw)) {
		const rec = asRecord(item);
		if (!rec) continue;
		const code = typeof rec.type === "number" ? rec.type : 1;
		const type = BY_CODE.get(code);
		if (!type) throw new Error(`unsupported Bitwarden item type ${code}`);
		const spec = ITEM_TYPES[type];

		const data: Record<string, string> = {};
		const block = asRecord(rec[spec.key]);
		if (block) {
			for (const [field, value] of Object.entries(block)) {
				if (field === "uris") continue;
				const t = text(value);
				if (t !== undefined) data[field] = t;
			}
		}
		// A login carries username/password at the top level as well; the CLI
		// mirrors those into `data`, so the block here keeps only `totp`.
		if (type === "login") {
			delete data.username;
			delete data.password;
		}
		const loginUsername = type === "login" ? block?.username : undefined;
		const loginPassword = type === "login" ? block?.password : undefined;
		const uris = block && Array.isArray(block.uris)
			? block.uris.map((u) => text(asRecord(u)?.uri)).filter((u): u is string => u !== undefined)
			: undefined;
		const notes = text(rec.notes);
		const source = text(rec.id) ? { kind: "bitwarden", id: text(rec.id) as string } : undefined;
		const fields = customFields(rec);

		drafts.push({
			name: cleanName(rec.name),
			type,
			...(text(loginUsername) !== undefined ? { username: text(loginUsername) } : {}),
			...(text(loginPassword) !== undefined ? { password: text(loginPassword) } : {}),
			...(uris && uris.length > 0 ? { uris } : {}),
			...(Object.keys(data).length > 0 ? { data } : {}),
			...(notes !== undefined ? { notes } : {}),
			...(fields ? { fields } : {}),
			...(source ? { source } : {}),
		});
	}

	drafts.sort((a, b) =>
		a.name.localeCompare(b.name) ||
		a.type.localeCompare(b.type) ||
		(a.username ?? "").localeCompare(b.username ?? ""),
	);
	const seen = new Map<string, number>();
	for (const d of drafts) {
		const k = `${d.name.toLowerCase()}\n${d.type}`;
		const n = (seen.get(k) ?? 0) + 1;
		seen.set(k, n);
		if (n > 1) d.name = `${d.name} (${n})`;
	}
	return drafts;
}

/** Case-insensitive substring match on name, username, and URIs. */
export function filterItems(items: Draft[], search?: string): Draft[] {
	const query = (search ?? "").trim().toLowerCase();
	if (!query) return items;
	return items.filter((item) =>
		`${item.name}\n${item.username ?? ""}\n${(item.uris ?? []).join("\n")}`.toLowerCase().includes(query),
	);
}
