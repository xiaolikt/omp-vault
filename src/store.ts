/**
 * Encrypted secret store for omp-vault.
 *
 * On-disk format (store.json):
 *   { "v": 1, "salt": "<hex>", "kdf": { "N", "r", "p" },
 *     "ct": "<base64 iv(12) || ciphertext || tag(16)>" }
 *
 * Key derivation: scrypt(passphrase, salt, kdf) -> 32 bytes. `kdf` is absent
 * from files written before it was recorded; those used DEFAULT_KDF.
 * Cipher: ChaCha20-Poly1305 (AEAD) via node:crypto. No native dependencies.
 *
 * The derived key and decrypted items live only in module memory and are
 * dropped on lock() or after the idle timeout.
 */
import {
	createCipheriv,
	createDecipheriv,
	randomBytes,
	scryptSync,
} from "node:crypto";
import {
	chmodSync,
	closeSync,
	existsSync,
	fsyncSync,
	mkdirSync,
	openSync,
	readFileSync,
	renameSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface VaultItem {
	id: string;
	name: string;
	username?: string;
	password: string;
	uris?: string[];
	notes?: string;
	/** Where the entry was copied from, so a re-import updates it after a rename. */
	source?: { kind: "bitwarden"; id: string };
	createdAt: string;
	updatedAt: string;
}

export type VaultUpsert = Omit<VaultItem, "id" | "createdAt" | "updatedAt"> & { id?: string };

interface KdfParams {
	N: number;
	r: number;
	p: number;
}

interface StoreFile {
	v: 1;
	salt: string;
	ct: string;
	kdf?: KdfParams;
}

export const defaultVaultDir = (): string =>
	process.env.OMP_VAULT_DIR ?? join(homedir(), ".omp", "vault");

const DEFAULT_KDF: KdfParams = { N: 1 << 15, r: 8, p: 1 };

const isKdf = (value: unknown): value is KdfParams => {
	if (!value || typeof value !== "object") return false;
	const { N, r, p } = value as KdfParams;
	return [N, r, p].every((n) => Number.isSafeInteger(n) && n > 0);
};

const deriveKey = (passphrase: string, salt: Buffer, kdf: KdfParams): Buffer =>
	scryptSync(passphrase, salt, 32, { ...kdf, maxmem: 128 * 1024 * 1024 });

export class Vault {
	private readonly file: string;
	private key: Buffer | undefined;
	private salt: Buffer | undefined;
	private kdf: KdfParams = DEFAULT_KDF;
	private items: VaultItem[] = [];
	private lastActivity = Date.now();

	constructor(dir: string = defaultVaultDir()) {
		this.file = join(dir, "store.json");
	}

	get path(): string {
		return this.file;
	}

	get initialized(): boolean {
		return existsSync(this.file);
	}

	get unlocked(): boolean {
		return this.key !== undefined;
	}

	/** Number of stored entries, without decrypting copies for a count. */
	get count(): number {
		this.requireUnlocked();
		return this.items.length;
	}

	/** Seconds since the last successful operation; used for idle auto-lock. */
	get idleMs(): number {
		return Date.now() - this.lastActivity;
	}

	/** Create a new empty store. Throws if one already exists. */
	init(passphrase: string): void {
		if (this.initialized) throw new Error("vault already initialized");
		this.salt = randomBytes(16);
		this.kdf = DEFAULT_KDF;
		this.key = deriveKey(passphrase, this.salt, this.kdf);
		this.items = [];
		this.persist();
		this.touch();
	}

	/**
	 * Decrypt the store into memory. Returns false on a wrong passphrase and
	 * leaves the current state untouched. Throws when the file is unreadable.
	 */
	unlock(passphrase: string): boolean {
		const store = this.readStore();
		if (!store) throw new Error("vault not initialized");
		const kdf = store.kdf ?? DEFAULT_KDF;
		if (!isKdf(kdf)) throw new Error("unsupported vault format");
		const salt = Buffer.from(store.salt, "hex");
		const key = deriveKey(passphrase, salt, kdf);
		const buf = Buffer.from(store.ct, "base64");
		if (buf.length < 28) return false;
		const iv = buf.subarray(0, 12);
		const body = buf.subarray(12);
		let items: unknown;
		try {
			const decipher = createDecipheriv("chacha20-poly1305", key, iv, {
				authTagLength: 16,
			});
			const tag = body.subarray(body.length - 16);
			const ct = body.subarray(0, body.length - 16);
			decipher.setAuthTag(tag);
			const json = Buffer.concat([decipher.update(ct), decipher.final()]);
			items = JSON.parse(json.toString("utf8"));
		} catch {
			return false;
		}
		if (!Array.isArray(items)) {
			key.fill(0);
			throw new Error("unsupported vault format");
		}
		this.salt = salt;
		this.kdf = kdf;
		this.key = key;
		this.items = items as VaultItem[];
		this.touch();
		return true;
	}

	/** Drop the key and plaintext items from memory. */
	lock(): void {
		this.key?.fill(0);
		this.key = undefined;
		this.items = [];
	}

	/** Lock if idle for longer than maxIdleMs. Returns true when it locked. */
	maybeAutoLock(maxIdleMs: number): boolean {
		if (this.unlocked && this.idleMs >= maxIdleMs) {
			this.lock();
			return true;
		}
		return false;
	}

	touch(): void {
		this.lastActivity = Date.now();
	}

	/** Copies: a caller must not be able to mutate stored items through them. */
	list(): VaultItem[] {
		this.requireUnlocked();
		this.touch();
		return structuredClone(this.items);
	}

	find(name: string): VaultItem | undefined {
		this.requireUnlocked();
		this.touch();
		const lower = name.toLowerCase();
		const item = this.items.find((i) => i.name.toLowerCase() === lower);
		return item ? structuredClone(item) : undefined;
	}

	upsert(item: VaultUpsert): VaultItem {
		this.requireUnlocked();
		const stored = this.apply(item, new Date().toISOString());
		this.persist();
		this.touch();
		return structuredClone(stored);
	}

	/** Insert or update many entries with a single write of the store file. */
	upsertMany(items: readonly VaultUpsert[]): number {
		this.requireUnlocked();
		if (items.length === 0) return 0;
		const now = new Date().toISOString();
		for (const item of items) this.apply(item, now);
		this.persist();
		this.touch();
		return items.length;
	}

	remove(name: string): boolean {
		this.requireUnlocked();
		const lower = name.toLowerCase();
		const idx = this.items.findIndex((i) => i.name.toLowerCase() === lower);
		if (idx === -1) return false;
		this.items.splice(idx, 1);
		this.persist();
		this.touch();
		return true;
	}

	/** An entry is matched by local id, else by its source, else by name. */
	private apply(item: VaultUpsert, now: string): VaultItem {
		const lower = item.name.toLowerCase();
		const source = item.source;
		const existing = item.id
			? this.items.find((i) => i.id === item.id)
			: source
				? (this.items.find((i) => i.source?.kind === source.kind && i.source.id === source.id) ??
					this.items.find((i) => i.name.toLowerCase() === lower))
				: this.items.find((i) => i.name.toLowerCase() === lower);
		if (existing) {
			const before = existing.name;
			Object.assign(existing, item, { id: existing.id, updatedAt: now });
			// Matched by source under a new name: keep the old one if another entry has it.
			if (before !== existing.name && this.items.some((i) => i !== existing && i.name.toLowerCase() === lower)) {
				existing.name = before;
			}
			return existing;
		}
		const full: VaultItem = {
			...item,
			id: randomBytes(8).toString("hex"),
			createdAt: now,
			updatedAt: now,
		};
		this.items.push(full);
		return full;
	}

	private requireUnlocked(): void {
		if (!this.unlocked) throw new Error("vault is locked");
	}

	private readStore(): StoreFile | undefined {
		if (!existsSync(this.file)) return undefined;
		const parsed = JSON.parse(readFileSync(this.file, "utf8")) as StoreFile;
		if (parsed?.v !== 1) throw new Error("unsupported vault format");
		return parsed;
	}

	private persist(): void {
		if (!this.key || !this.salt) throw new Error("vault is locked");
		const dir = join(this.file, "..");
		mkdirSync(dir, { recursive: true, mode: 0o700 });
		try {
			chmodSync(dir, 0o700);
		} catch {
			/* best-effort; the store file itself is 0600 */
		}
		const iv = randomBytes(12);
		const cipher = createCipheriv("chacha20-poly1305", this.key, iv, {
			authTagLength: 16,
		});
		const ct = Buffer.concat([
			cipher.update(JSON.stringify(this.items), "utf8"),
			cipher.final(),
		]);
		const store: StoreFile = {
			v: 1,
			salt: this.salt.toString("hex"),
			kdf: this.kdf,
			ct: Buffer.concat([iv, ct, cipher.getAuthTag()]).toString("base64"),
		};
		// Atomic write: temp file, flushed to disk, then rename. The temp name is
		// unique per process and write, so two omp processes cannot truncate each
		// other's temp file; the last rename still wins (see README).
		const tmp = `${this.file}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
		try {
			const fd = openSync(tmp, "w", 0o600);
			try {
				writeFileSync(fd, JSON.stringify(store));
				fsyncSync(fd);
			} finally {
				closeSync(fd);
			}
			renameSync(tmp, this.file);
		} catch (e) {
			rmSync(tmp, { force: true });
			throw e;
		}
		// Make the rename itself durable where the platform allows opening a directory.
		try {
			const dirFd = openSync(dir, "r");
			try {
				fsyncSync(dirFd);
			} finally {
				closeSync(dirFd);
			}
		} catch {
			/* best-effort: Windows cannot open a directory this way */
		}
	}
}
