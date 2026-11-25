/** Append-only JSONL audit log for omp-vault. */
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface AuditEntry {
	ts: string;
	session: string;
	event:
		| "init"
		| "unlock"
		| "unlock_failed"
		| "unlock_error"
		| "lock"
		| "auto_lock"
		| "add"
		| "remove"
		| "grant"
		| "revoke"
		| "read_allow"
		| "read_deny"
		| "list"
		| "import";
	item?: string;
	reason?: string;
}

export const defaultAuditPath = (): string =>
	join(process.env.OMP_VAULT_DIR ?? join(homedir(), ".omp", "vault"), "audit.log");

/** Append one entry. Best-effort: a full or read-only disk returns false. */
export function appendAudit(entry: Omit<AuditEntry, "ts">, file = defaultAuditPath()): boolean {
	try {
		const dir = join(file, "..");
		mkdirSync(dir, { recursive: true, mode: 0o700 });
		try {
			chmodSync(dir, 0o700);
		} catch {
			/* best-effort */
		}
		appendFileSync(
			file,
			JSON.stringify({ ...entry, ts: new Date().toISOString() }) + "\n",
			{ mode: 0o600 },
		);
		return true;
	} catch {
		return false;
	}
}

export function readAudit(file = defaultAuditPath(), limit = 50): AuditEntry[] {
	if (!existsSync(file)) return [];
	const lines = readFileSync(file, "utf8").split("\n").filter(Boolean);
	return lines
		.slice(-limit)
		.map((l) => {
			try {
				return JSON.parse(l) as AuditEntry;
			} catch {
				return undefined;
			}
		})
		.filter((e): e is AuditEntry => e !== undefined);
}
