/**
 * Encrypted secret store for omp-vault.
 *
 * On-disk format (store.json):
 *   { "v": 1, "salt": "<hex>", "ct": "<base64 iv(12) || ciphertext || tag(16)>" }
 *
 * Key derivation: scrypt(passphrase, salt) -> 32 bytes.
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
	existsSync,
	mkdirSync,
	readFileSync,
	renameSync,
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
	createdAt: string;
	updatedAt: string;
}

interface StoreFile {
	v: 1;
	salt: string;
	ct: string;
}

export const defaultVaultDir = (): string =>
	process.env.OMP_VAULT_DIR ?? join(homedir(), ".omp", "vault");

const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };

const deriveKey = (passphrase: string, salt: Buffer): Buffer =>
	scryptSync(passphrase, salt, 32, SCRYPT);

export class Vault {
	private readonly file: string;
	private key: Buffer | undefined;
	private salt: Buffer | undefined;
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

	/** Seconds since the last successful operation; used for idle auto-lock. */
	get idleMs(): number {
		return Date.now() - this.lastActivity;
	}

	/** Create a new empty store. Throws if one already exists. */
	init(passphrase: string): void {
		if (this.initialized) throw new Error("vault already initialized");
		this.salt = randomBytes(16);
		this.key = deriveKey(passphrase, this.salt);
		this.items = [];
		this.persist();
	}

	/** Decrypt the store into memory. Returns false on a wrong passphrase. */
	unlock(passphrase: string): boolean {
		const store = this.readStore();
		if (!store) throw new Error("vault not initialized");
		this.salt = Buffer.from(store.salt, "hex");
		const key = deriveKey(passphrase, this.salt);
		const buf = Buffer.from(store.ct, "base64");
		const iv = buf.subarray(0, 12);
		const body = buf.subarray(12);
		try {
			const decipher = createDecipheriv("chacha20-poly1305", key, iv, {
				authTagLength: 16,
			});
			const tag = body.subarray(body.length - 16);
			const ct = body.subarray(0, body.length - 16);
			decipher.setAuthTag(tag);
			const json = Buffer.concat([decipher.update(ct), decipher.final()]);
			this.items = JSON.parse(json.toString("utf8")) as VaultItem[];
			this.key = key;
			this.touch();
			return true;
		} catch {
			this.key = undefined;
			this.items = [];
			return false;
		}
	}

	/** Drop the key and plaintext items from memory. */
	lock(): void {
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

	list(): VaultItem[] {
		this.requireUnlocked();
		this.touch();
		return this.items.map((i) => ({ ...i }));
	}

	find(name: string): VaultItem | undefined {
		this.requireUnlocked();
		this.touch();
		const lower = name.toLowerCase();
		const item = this.items.find((i) => i.name.toLowerCase() === lower);
		return item ? { ...item } : undefined;
	}

	upsert(item: Omit<VaultItem, "id" | "createdAt" | "updatedAt"> & { id?: string }): VaultItem {
		this.requireUnlocked();
		const now = new Date().toISOString();
		const existing = item.id
			? this.items.find((i) => i.id === item.id)
			: this.items.find((i) => i.name.toLowerCase() === item.name.toLowerCase());
		if (existing) {
			Object.assign(existing, item, { id: existing.id, updatedAt: now });
			this.persist();
			this.touch();
			return { ...existing };
		}
		const full: VaultItem = {
			...item,
			id: randomBytes(8).toString("hex"),
			createdAt: now,
			updatedAt: now,
		};
		this.items.push(full);
		this.persist();
		this.touch();
		return { ...full };
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
			ct: Buffer.concat([iv, ct, cipher.getAuthTag()]).toString("base64"),
		};
		// Atomic write: temp file + rename.
		const tmp = `${this.file}.tmp`;
		writeFileSync(tmp, JSON.stringify(store), { mode: 0o600 });
		renameSync(tmp, this.file);
	}
}
