/**
 * Machine-wide settings, owned by the CLI (`ai-vault settings`), read here.
 *
 * The vault decides when to ask for its password; the Bitwarden side decides
 * separately whether its `bw` session key may live on disk, and whether a hit
 * may be imported into the vault without a window.
 */
import { VaultCli } from "./cli.js";

export type UnlockModeName = "never" | "time" | "session";
export type ImportPolicy = "ask" | "always" | "never";

export interface Settings {
	vault: { unlock: UnlockModeName; hours: number; auto: boolean };
	bitwarden: {
		unlock: UnlockModeName;
		hours: number;
		import: ImportPolicy;
		persisted: boolean;
		expiresAt: number | null;
	};
	/** Ente's ENTE_CLI_VAULT_KEY: session leaves it to the OS keychain. */
	ente: { unlock: UnlockModeName; hours: number; persisted: boolean; expiresAt: number | null };
}

export const DEFAULT_SETTINGS: Settings = {
	vault: { unlock: "session", hours: 8, auto: false },
	bitwarden: { unlock: "session", hours: 8, import: "ask", persisted: false, expiresAt: null },
	ente: { unlock: "session", hours: 8, persisted: false, expiresAt: null },
};

const cli = new VaultCli();
let cache: { at: number; value: Settings } | undefined;

/** The shared CLI client, for the pieces that read and write the settings. */
export function settingsCli(): VaultCli {
	return cli;
}

/**
 * Settings change rarely, so a short cache keeps a Bitwarden call from paying
 * for the read. `/vault settings ...` drops it explicitly.
 */
export async function getSettings(signal?: AbortSignal, options: { fresh?: boolean } = {}): Promise<Settings> {
	if (!options.fresh && cache && Date.now() - cache.at < 30_000) return cache.value;
	const value = await cli.json<Settings>(["settings"], { signal });
	cache = { at: Date.now(), value };
	return value;
}

/** For paths that must keep working when the CLI is missing: defaults instead. */
export async function getSettingsSafe(signal?: AbortSignal): Promise<Settings> {
	try {
		return await getSettings(signal);
	} catch {
		return DEFAULT_SETTINGS;
	}
}

export function forgetSettings(): void {
	cache = undefined;
}
