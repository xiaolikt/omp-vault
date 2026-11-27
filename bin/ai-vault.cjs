#!/usr/bin/env node
/**
 * npm shim for the Rust binary (CommonJS on purpose: the package is ESM and
 * this file must run without an import graph).
 *
 * The real program ships in a platform package (@xiaolikt/ai-vault-linux-x64
 * and friends). This file only picks the right one and hands over argv, stdio
 * and the exit code — exit codes 3/4/5 are the host contract, so they must not
 * be rewritten.
 */
"use strict";
const { spawn } = require("node:child_process");
const { existsSync } = require("node:fs");
const { dirname, join } = require("node:path");

const PACKAGE = "@xiaolikt/ai-vault";
const PLATFORM = `${process.platform}-${process.arch}`;
const EXE = process.platform === "win32" ? "ai-vault.exe" : "ai-vault";

function candidates() {
	const found = [];
	if (process.env.AI_VAULT_BIN) found.push(process.env.AI_VAULT_BIN);
	try {
		const manifest = require.resolve(`${PACKAGE}-${PLATFORM}/package.json`);
		found.push(join(dirname(manifest), "bin", EXE));
	} catch {
		/* that platform package is not installed */
	}
	// A source checkout: package root/target/{release,debug}/ai-vault.
	const root = join(__dirname, "..");
	found.push(join(root, "target", "release", EXE), join(root, "target", "debug", EXE));
	return found.filter((path) => path && path !== __filename);
}

const bin = candidates().find((path) => existsSync(path));
if (!bin) {
	console.error(
		[
			`ai-vault: no binary for ${PLATFORM}.`,
			`Expected the optional package ${PACKAGE}-${PLATFORM}.`,
			"Build it from source instead:",
			"  cargo install --path <repo>/crates/ai-vault",
			"or point AI_VAULT_BIN at a compiled ai-vault.",
		].join("\n"),
	);
	process.exit(1);
}

const child = spawn(bin, process.argv.slice(2), { stdio: "inherit" });
// The dialogs and the terminal belong to the child; forward interruption so a
// cancelled window does not leave it running.
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
	process.on(signal, () => {
		try {
			child.kill(signal);
		} catch {
			/* already gone */
		}
	});
}
child.on("error", (error) => {
	console.error(`ai-vault: cannot run ${bin}: ${error.message}`);
	process.exit(1);
});
child.on("exit", (code, signal) => {
	if (signal) {
		process.kill(process.pid, signal);
		return;
	}
	process.exit(code ?? 1);
});
