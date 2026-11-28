/**
 * The shape of a vault entry, shared by the extension's import mapping and
 * its tools. Mirrors the CLI's `store.rs` and Bitwarden's own item envelope:
 * a type, the type's own fields under `data`, plus `notes` and custom
 * `fields` that every type carries.
 */
export type ItemType =
	| "login"
	| "secureNote"
	| "card"
	| "identity"
	| "sshKey"
	| "bankAccount"
	| "driversLicense"
	| "passport";

/** A custom field, as Bitwarden stores it: 0 text · 1 hidden · 2 boolean · 3 linked. */
export interface Field {
	name: string;
	value: string;
	type: number;
	linkedId?: string;
}

export interface Source {
	kind: string;
	id: string;
}

/** What a tool hands to `ai-vault save` / `add`: the same envelope, sparse. */
export interface Draft {
	name: string;
	type: ItemType;
	username?: string;
	password?: string;
	uris?: string[];
	data?: Record<string, string>;
	notes?: string;
	fields?: Field[];
	source?: Source;
}

/** What `list` returns: metadata only, every secret masked. */
export interface ItemSummary {
	name: string;
	type: ItemType;
	username?: string | null;
	uris: string[];
	fields: Record<string, string>;
	hasNotes?: boolean;
	updatedAt: string;
}
