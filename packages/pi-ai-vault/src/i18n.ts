/**
 * User-facing strings: English by default, Chinese with `AI_VAULT_LANG=zh`
 * (or a `zh_*` locale). The same rule as the CLI's i18n.rs, and the language
 * is passed down to the CLI so its windows and messages agree with ours.
 *
 * Texts a *host* parses (exit codes, `needs-ui:`, error patterns such as
 * "no such entry") never change; only what a human reads does.
 */

export type Lang = "en" | "zh";

function detect(): Lang {
	const explicit = (process.env.AI_VAULT_LANG ?? "").toLowerCase();
	if (explicit.startsWith("zh")) return "zh";
	if (explicit) return "en";
	const locale = ["LC_ALL", "LC_MESSAGES", "LANG"]
		.map((name) => (process.env[name] ?? "").toLowerCase())
		.find((value) => value.length > 0);
	return locale?.startsWith("zh") ? "zh" : "en";
}

let cached: Lang | undefined;

export function lang(): Lang {
	return (cached ??= detect());
}

/** Pick the English or the Chinese text. */
export function tr(en: string, zh: string): string {
	return lang() === "zh" ? zh : en;
}
