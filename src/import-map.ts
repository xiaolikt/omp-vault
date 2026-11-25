/**
 * Map a Bitwarden JSON export or `bw list items` payload onto local vault
 * drafts. Secrets stay in the returned objects for the caller to encrypt;
 * this module never writes them.
 */
export interface LoginDraft {
	name: string;
	username?: string;
	password: string;
	uris: string[];
	notes?: string;
}

function asItems(raw: unknown): unknown[] {
	if (Array.isArray(raw)) return raw;
	if (raw && typeof raw === "object" && "items" in raw) {
		const items = (raw as { items?: unknown }).items;
		if (Array.isArray(items)) return items;
	}
	return [];
}

function uriList(login: Record<string, unknown>): string[] {
	if (!Array.isArray(login.uris)) return [];
	return login.uris.flatMap((entry) => {
		if (!entry || typeof entry !== "object" || !("uri" in entry)) return [];
		const uri = (entry as { uri?: unknown }).uri;
		return typeof uri === "string" && uri ? [uri] : [];
	});
}

/**
 * Login items that have a password. Names are sorted, then duplicates become
 * `Name (2)`, `Name (3)`, … so a later import updates the same rows.
 */
export function bitwardenLogins(raw: unknown): LoginDraft[] {
	const drafts: LoginDraft[] = [];
	for (const item of asItems(raw)) {
		if (!item || typeof item !== "object") continue;
		const rec = item as Record<string, unknown>;
		if (!rec.login || typeof rec.login !== "object") continue;
		const login = rec.login as Record<string, unknown>;
		const password = typeof login.password === "string" ? login.password : "";
		if (!password) continue;
		const username = typeof login.username === "string" && login.username ? login.username : undefined;
		const notes = typeof rec.notes === "string" && rec.notes ? rec.notes : undefined;
		const nameRaw = typeof rec.name === "string" ? rec.name : "";
		const name = nameRaw.replace(/[\r\n]+/g, " ").trim().slice(0, 200) || "unnamed";
		drafts.push({ name, username, password, uris: uriList(login), notes });
	}
	drafts.sort(
		(a, b) =>
			a.name.localeCompare(b.name) ||
			(a.username ?? "").localeCompare(b.username ?? "") ||
			(a.uris[0] ?? "").localeCompare(b.uris[0] ?? ""),
	);
	const seen = new Map<string, number>();
	for (const item of drafts) {
		const key = item.name.toLowerCase();
		const n = (seen.get(key) ?? 0) + 1;
		seen.set(key, n);
		if (n > 1) item.name = `${item.name} (${n})`;
	}
	return drafts;
}

/** Case-insensitive substring match on name, username, and URIs. */
export function filterLogins(items: LoginDraft[], search?: string): LoginDraft[] {
	const query = (search ?? "").trim().toLowerCase();
	if (!query) return items;
	return items.filter((item) =>
		`${item.name}\n${item.username ?? ""}\n${item.uris.join("\n")}`.toLowerCase().includes(query),
	);
}
