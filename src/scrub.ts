/** Values the output scrubber must keep hiding. */
export type ScrubValue = { env: string; value: string };

const escapeRegExp = (input: string): string => input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** `needle` with any whitespace allowed between characters (base64/xxd line wrapping). */
const spacedPattern = (needle: string, flags: string): RegExp =>
	new RegExp(needle.split("").map(escapeRegExp).join("\\s*"), `${flags}g`);

/**
 * Replace a secret and its common encodings (base64, base64url, URL, hex) in
 * text. A form shorter than 6 characters is deliberately skipped: replacing
 * it would corrupt ordinary output more often than it protects anything.
 *
 * Encoded forms are matched both contiguously and with whitespace between
 * characters: GNU `base64` wraps at 76 columns and `xxd`/`od` separate hex
 * bytes, so a line-broken encoding must still be found.
 */
export function scrubText(input: string, values: Iterable<ScrubValue>): { text: string; changed: boolean } {
	let text = input;
	let changed = false;
	// A whitespace-free copy makes the "is this encoding present?" check cheap;
	// the regex below is only built when there is something to replace.
	const compact = input.replace(/\s+/g, "");
	const replace = (needle: string, label: string) => {
		if (needle.length < 6 || !text.includes(needle)) return;
		text = text.split(needle).join(label);
		changed = true;
	};
	const replaceSpaced = (needle: string, label: string, flags = "") => {
		if (needle.length < 6 || !compact.includes(needle)) return;
		const next = text.replace(spacedPattern(needle, flags), label);
		if (next !== text) {
			text = next;
			changed = true;
		}
	};
	for (const { env, value } of values) {
		replace(value, `[BW_SCRUBBED:${env}]`);
		const b64 = Buffer.from(value, "utf-8").toString("base64");
		const b64url = b64.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
		replace(b64, `[BW_SCRUBBED-B64:${env}]`);
		replace(b64url, `[BW_SCRUBBED-B64URL:${env}]`);
		replaceSpaced(b64, `[BW_SCRUBBED-B64:${env}]`);
		replaceSpaced(b64url, `[BW_SCRUBBED-B64URL:${env}]`);
		const url = encodeURIComponent(value);
		if (url !== value) replace(url, `[BW_SCRUBBED-URL:${env}]`);
		const hex = Buffer.from(value, "utf-8").toString("hex");
		replace(hex, `[BW_SCRUBBED-HEX:${env}]`);
		replaceSpaced(hex, `[BW_SCRUBBED-HEX:${env}]`, "i");
		if (hex !== hex.toUpperCase()) {
			replaceSpaced(hex.toUpperCase(), `[BW_SCRUBBED-HEX:${env}]`, "i");
		}
	}
	return { text, changed };
}

/** A Buffer's text may hold a secret; only replace it when something changed. */
function scrubBuffer(value: Buffer, values: Iterable<ScrubValue>): { value: unknown; changed: boolean } {
	const result = scrubText(value.toString("utf-8"), values);
	return result.changed ? { value: Buffer.from(result.text, "utf-8"), changed: true } : { value, changed: false };
}

/** Rebuild a Map/Set/Error only when a contained string changed, so identity is kept otherwise. */
function scrubMap(
	value: Map<unknown, unknown>,
	values: Iterable<ScrubValue>,
	depth: number,
): { value: unknown; changed: boolean } {
	let changed = false;
	const next = new Map<unknown, unknown>();
	for (const [key, entry] of value) {
		const k = scrubDeep(key, values, depth + 1);
		const v = scrubDeep(entry, values, depth + 1);
		if (k.changed || v.changed) changed = true;
		next.set(k.value, v.value);
	}
	return { value: changed ? next : value, changed };
}

function scrubSet(
	value: Set<unknown>,
	values: Iterable<ScrubValue>,
	depth: number,
): { value: unknown; changed: boolean } {
	let changed = false;
	const next = new Set<unknown>();
	for (const entry of value) {
		const result = scrubDeep(entry, values, depth + 1);
		if (result.changed) changed = true;
		next.add(result.value);
	}
	return { value: changed ? next : value, changed };
}

function scrubError(
	value: Error,
	values: Iterable<ScrubValue>,
	depth: number,
): { value: unknown; changed: boolean } {
	const message = scrubText(value.message, values);
	const stack = typeof value.stack === "string" ? scrubText(value.stack, values) : undefined;
	const cause =
		"cause" in value
			? scrubDeep((value as Error & { cause?: unknown }).cause, values, depth + 1)
			: undefined;
	if (!message.changed && !stack?.changed && !cause?.changed) return { value, changed: false };
	const copy = Object.create(Object.getPrototypeOf(value)) as Error;
	Object.defineProperties(copy, Object.getOwnPropertyDescriptors(value));
	if (message.changed) Object.defineProperty(copy, "message", { value: message.text, writable: true, configurable: true });
	if (stack?.changed) Object.defineProperty(copy, "stack", { value: stack.text, writable: true, configurable: true });
	if (cause?.changed) {
		Object.defineProperty(copy, "cause", { value: cause.value, writable: true, configurable: true });
	}
	return { value: copy, changed: true };
}

/** OMP's bash `details.trace` can echo the sourced env file; scrub nested values. */
export function scrubDeep(
	value: unknown,
	values: Iterable<ScrubValue>,
	depth = 0,
): { value: unknown; changed: boolean } {
	if (depth > 12) return { value, changed: false };
	if (typeof value === "string") {
		const result = scrubText(value, values);
		return { value: result.text, changed: result.changed };
	}
	if (Array.isArray(value)) {
		let changed = false;
		const next = value.map((entry) => {
			const result = scrubDeep(entry, values, depth + 1);
			if (result.changed) changed = true;
			return result.value;
		});
		return { value: changed ? next : value, changed };
	}
	if (Buffer.isBuffer(value)) return scrubBuffer(value, values);
	if (value instanceof Map) return scrubMap(value, values, depth);
	if (value instanceof Set) return scrubSet(value, values, depth);
	if (value instanceof Error) return scrubError(value, values, depth);
	if (value && typeof value === "object") {
		// Only plain data is rebuilt. A Date or another class instance keeps its
		// prototype: it is returned as is instead of being turned into `{}`.
		const proto = Object.getPrototypeOf(value);
		if (proto !== Object.prototype && proto !== null) return { value, changed: false };
		let changed = false;
		const next: Record<string, unknown> = {};
		for (const [key, entry] of Object.entries(value)) {
			const result = scrubDeep(entry, values, depth + 1);
			if (result.changed) changed = true;
			next[key] = result.value;
		}
		return { value: changed ? next : value, changed };
	}
	return { value, changed: false };
}
