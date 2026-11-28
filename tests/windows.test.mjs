// Windows: how the extension finds and starts things there.
//
// The other suites answer through POSIX shell-script mocks, which cannot run
// on Windows; these use the real npm wrapper format, the real Windows
// PowerShell and, when it is installed, the real Bitwarden CLI and Git Bash.
// The first group is plain parsing and runs everywhere; the rest skip off
// Windows.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { cleanUpOnExit, cliBinary, useMocks } from "./helpers.mjs";

const WIN32 = process.platform === "win32";
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
/** Taken once, before any test clears AI_VAULT_BIN. */
const CLI_BINARY = cliBinary();
const PS = join(process.env.SystemRoot ?? "C:/", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
const PS_ARGS = ["-NoProfile", "-NonInteractive", "-STA"];
const windowsOnly = { skip: WIN32 ? false : "Windows only" };

const { npmShimLaunch } = await import("../packages/pi-ai-vault/src/cli.ts");

/** npm's `.cmd` wrapper, byte for byte in the parts that matter. */
function cmdShim(target) {
	return [
		"@ECHO off",
		"GOTO start",
		":find_dp0",
		"SET dp0=%~dp0",
		"EXIT /b",
		":start",
		"SETLOCAL",
		"CALL :find_dp0",
		'IF EXIST "%dp0%\\node.exe" (',
		'  SET "_prog=%dp0%\\node.exe"',
		") ELSE (",
		'  SET "_prog=node"',
		")",
		`endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  "%dp0%\\${target}" %*`,
	].join("\r\n");
}

/**
 * A small but faithful npm tree: the plugin, the dispatcher package with its
 * JavaScript shim, the prebuilt platform package, and the `.cmd` wrapper npm
 * links into .bin.
 */
function fakeNpm(dir, { wrapper = true, platform = "hoisted", dispatcher = true } = {}) {
	const nm = join(dir, "node_modules");
	const plugin = join(nm, "pi-ai-vault", "src");
	mkdirSync(plugin, { recursive: true });
	const src = join(ROOT, "packages", "pi-ai-vault", "src");
	for (const name of readdirSync(src)) copyFileSync(join(src, name), join(plugin, name));
	if (dispatcher) {
		const pkg = join(nm, "@xiaolikt", "ai-vault");
		mkdirSync(join(pkg, "bin"), { recursive: true });
		writeFileSync(
			join(pkg, "package.json"),
			JSON.stringify({ name: "@xiaolikt/ai-vault", version: "0.0.0", bin: { "ai-vault": "./bin/ai-vault.cjs" } }),
		);
		copyFileSync(join(ROOT, "bin", "ai-vault.cjs"), join(pkg, "bin", "ai-vault.cjs"));
	}
	if (platform !== "none") {
		// "hoisted": resolvable from the plugin. "nested": only from the dispatcher.
		const pkg =
			platform === "nested"
				? join(nm, "@xiaolikt", "ai-vault", "node_modules", "@xiaolikt", `ai-vault-${process.platform}-${process.arch}`)
				: join(nm, "@xiaolikt", `ai-vault-${process.platform}-${process.arch}`);
		mkdirSync(join(pkg, "bin"), { recursive: true });
		writeFileSync(
			join(pkg, "package.json"),
			JSON.stringify({ name: `@xiaolikt/ai-vault-${process.platform}-${process.arch}`, version: "0.0.0", os: [process.platform], cpu: [process.arch] }),
		);
		copyFileSync(CLI_BINARY, join(pkg, "bin", WIN32 ? "ai-vault.exe" : "ai-vault"));
	}
	if (wrapper) {
		mkdirSync(join(nm, ".bin"), { recursive: true });
		writeFileSync(join(nm, ".bin", WIN32 ? "ai-vault.cmd" : "ai-vault"), cmdShim("..\\@xiaolikt\\ai-vault\\bin\\ai-vault.cjs"));
	}
	return { nm, cli: join(plugin, "cli.ts") };
}

function scratch() {
	return mkdtempSync(join(tmpdir(), "ai-vault-windows-"));
}

/**
 * Remove a scratch directory. On Windows a binary that just ran from it can
 * still be held for a moment (an antivirus scanning the fresh copy), so the
 * removal is retried before it is left to the temp cleaner.
 */
function removeScratch(dir) {
	for (let attempt = 0; attempt < 30; attempt++) {
		try {
			rmSync(dir, { recursive: true, force: true });
			return;
		} catch {
			Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
		}
	}
}

/** Run `fn` with these variables unset: `AI_VAULT_BIN` in particular always wins, and the tests set it. */
async function withoutEnv(names, fn) {
	const saved = Object.fromEntries(names.map((name) => [name, process.env[name]]));
	for (const name of names) delete process.env[name];
	try {
		return await fn();
	} finally {
		Object.assign(process.env, saved);
	}
}

// ---------------------------------------------------------------- parsing the wrapper

test("an npm .cmd wrapper is read, not run: it names a script for this Node, or a program", async (t) => {
	const dir = scratch();
	const sep = WIN32 ? "\\" : "/";
	const shim = join(dir, "tool.cmd");
	const script = join(dir, "node_modules", "pkg", "bin", "tool.cjs");
	const program = join(dir, "node_modules", "pkg", "bin", "tool.exe");
	try {
		mkdirSync(dirname(script), { recursive: true });
		writeFileSync(script, "");
		writeFileSync(program, "");
		writeFileSync(shim, cmdShim(["node_modules", "pkg", "bin", "tool.cjs"].join(sep)));
		assert.deepEqual(npmShimLaunch(shim), { program: process.execPath, pre: [script] }, "a .cjs is started with this Node");

		writeFileSync(shim, cmdShim(["node_modules", "pkg", "bin", "tool.exe"].join(sep)));
		assert.deepEqual(npmShimLaunch(shim), { program, pre: [] }, "a program is started as itself");

		writeFileSync(shim, cmdShim(["node_modules", "pkg", "bin", "missing.js"].join(sep)));
		assert.equal(npmShimLaunch(shim), undefined, "what it names must exist");

		writeFileSync(shim, "@ECHO off\r\nsomething else entirely\r\n");
		assert.equal(npmShimLaunch(shim), undefined, "not npm's format");
		assert.equal(npmShimLaunch(join(dir, "no-such.cmd")), undefined, "no wrapper at all");

		// The other place npm puts one: node_modules/.bin, where it points with `..\\`.
		const binShim = join(dir, "node_modules", ".bin", "tool.cmd");
		mkdirSync(dirname(binShim), { recursive: true });
		writeFileSync(binShim, cmdShim(["..", "pkg", "bin", "tool.cjs"].join(sep)));
		assert.deepEqual(npmShimLaunch(binShim), { program: process.execPath, pre: [join(dir, "node_modules", "pkg", "bin", "tool.cjs")] });
	} finally {
		removeScratch(dir);
	}
});

// ---------------------------------------------------------------- starting the CLI

test("Windows: npm layout, everything hoisted: the prebuilt ai-vault.exe is started directly", windowsOnly, async (t) => {
	if (!WIN32) return t.skip();
	const dir = scratch();
	return withoutEnv(["AI_VAULT_BIN"], async () => {
	try {
		const tree = fakeNpm(dir);
		const mod = await import(pathToFileURL(tree.cli).href);
		const cli = new mod.VaultCli();
		assert.equal(cli.bin, join(tree.nm, "@xiaolikt", "ai-vault-win32-x64", "bin", "ai-vault.exe"));
		const run = await cli.run(["--version"]);
		assert.equal(run.code, 0, run.stderr);
		assert.match(run.stdout, /^ai-vault \d+\.\d+\.\d+/, "the real binary answered, not a wrapper error");
	} finally {
		removeScratch(dir);
	}
	});
});

test("Windows: platform package nested under the dispatcher: the .cmd is unwrapped to Node + its script", windowsOnly, async (t) => {
	if (!WIN32) return t.skip();
	const dir = scratch();
	return withoutEnv(["AI_VAULT_BIN"], async () => {
	try {
		const tree = fakeNpm(dir, { platform: "nested" });
		const mod = await import(pathToFileURL(tree.cli).href);
		const cli = new mod.VaultCli();
		assert.equal(cli.bin, process.execPath, "never the .cmd itself");
		const launch = mod.resolveLaunch();
		assert.deepEqual(launch.pre, [join(tree.nm, "@xiaolikt", "ai-vault", "bin", "ai-vault.cjs")]);
		const run = await cli.run(["--version"]);
		assert.equal(run.code, 0, run.stderr);
		assert.match(run.stdout, /^ai-vault \d+\.\d+\.\d+/);
	} finally {
		removeScratch(dir);
	}
	});
});

test("Windows: only a .ps1 and a sh wrapper, nothing on PATH: the CLI is reported missing, and run() says so", windowsOnly, async (t) => {
	if (!WIN32) return t.skip();
	const dir = scratch();
	return withoutEnv(["AI_VAULT_BIN"], async () => {
	const saved = { PATH: process.env.PATH, USERPROFILE: process.env.USERPROFILE };
	try {
		const tree = fakeNpm(dir, { wrapper: false, platform: "none", dispatcher: false });
		mkdirSync(join(tree.nm, ".bin"), { recursive: true });
		writeFileSync(join(tree.nm, ".bin", "ai-vault.ps1"), "# a wrapper Node cannot start either");
		writeFileSync(join(tree.nm, ".bin", "ai-vault"), "#!/bin/sh\n");
		process.env.PATH = "";
		process.env.USERPROFILE = join(dir, "home"); // the "usual install spots" look under the profile
		const mod = await import(pathToFileURL(tree.cli).href);
		assert.equal(mod.resolveLaunch(), undefined);
		const cli = new mod.VaultCli();
		assert.equal(cli.available, false);
		await assert.rejects(cli.run(["--version"]), (error) => error instanceof mod.CliError && error.code === 1 && /not found/.test(error.message));
	} finally {
		Object.assign(process.env, saved);
		removeScratch(dir);
	}
	});
});

test("Windows: AI_VAULT_BIN pointing at a wrapper is unwrapped too; at nothing, it is ignored", windowsOnly, async (t) => {
	if (!WIN32) return t.skip();
	const dir = scratch();
	return withoutEnv(["AI_VAULT_BIN"], async () => {
	const saved = process.env.AI_VAULT_BIN;
	try {
		const tree = fakeNpm(dir, { platform: "none" });
		const mod = await import(pathToFileURL(tree.cli).href);
		process.env.AI_VAULT_BIN = join(tree.nm, ".bin", "ai-vault.cmd");
		assert.equal(mod.resolveLaunch().program, process.execPath);
		process.env.AI_VAULT_BIN = join(dir, "nowhere", "ai-vault.exe");
		assert.equal(mod.resolveLaunch(), undefined);
	} finally {
		if (saved === undefined) delete process.env.AI_VAULT_BIN;
		else process.env.AI_VAULT_BIN = saved;
		removeScratch(dir);
	}
	});
});

// ---------------------------------------------------------------- the Bitwarden half, with the real machine

const mocks = useMocks();
const { clipboardBackend, killTree, resolveBash, resolveBw } = await import("../packages/pi-ai-vault/src/bitwarden.ts");
cleanUpOnExit(mocks);

test("Windows: npm's bw.cmd is found and started through Node", windowsOnly, async (t) => {
	if (!WIN32) return t.skip();
	const bw = await resolveBw().catch(() => undefined);
	if (!bw) return t.skip("no Bitwarden CLI on this machine");
	const r = spawnSync(bw.program, [...bw.pre, "--version"], { encoding: "utf8", timeout: 60_000, windowsHide: true });
	assert.equal(r.status, 0, r.stderr);
	assert.match(r.stdout, /\d{4}\.\d+\.\d+/);
});

test("Windows: the clipboard carries a non-ASCII value byte for byte", windowsOnly, async (t) => {
	if (!WIN32) return t.skip();
	// No interactive session (a CI runner): there is no clipboard anyone could read.
	const interactive = spawnSync(PS, ["-NoProfile", "-NonInteractive", "-Command", "[Environment]::UserInteractive"], { encoding: "utf8", windowsHide: true, timeout: 20_000 });
	if (interactive.stdout.trim() !== "True") return t.skip("not an interactive session");
	// The real clipboard is used: put back whatever text the user had, and
	// leave alone anything that is not text.
	const probe = spawnSync(
		PS,
		[...PS_ARGS, "-Command", "Add-Type -AssemblyName System.Windows.Forms; if ([System.Windows.Forms.Clipboard]::ContainsImage() -or [System.Windows.Forms.Clipboard]::ContainsFileDropList() -or [System.Windows.Forms.Clipboard]::ContainsAudio()) { 'nontext'; exit 0 }; [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([System.Windows.Forms.Clipboard]::GetText()))"],
		{ encoding: "utf8", timeout: 20_000, windowsHide: true },
	);
	if (probe.stdout.trim() === "nontext") return t.skip("the clipboard holds something that is not text");
	// GetText() throws when the clipboard cannot be opened (a locked or
	// disconnected session, another tool holding it): nothing to test against then.
	if (probe.status !== 0) return t.skip("the clipboard cannot be opened right now (a locked session?)");
	const saved = probe.stdout.trim();
	const backend = clipboardBackend();
	assert.ok(backend, "Windows has a clipboard backend");
	const read = () => {
		const r = spawnSync(backend.read[0], backend.read[1], { windowsHide: true, timeout: 20_000 });
		assert.equal(r.status, 0, r.stderr?.toString());
		return new TextDecoder().decode(r.stdout);
	};
	const value = "密码-Pässw0rd-42";
	try {
		await new Promise((resolve, reject) => {
			const child = spawn(backend.copy[0], backend.copy[1], { stdio: ["pipe", "ignore", "pipe"], windowsHide: true });
			let stderr = "";
			child.stderr.on("data", (chunk) => (stderr += chunk));
			child.on("error", reject);
			child.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`copy exited with ${code}: ${stderr}`))));
			child.stdin.on("error", reject);
			child.stdin.end(value);
		});
		assert.equal(read(), value);
		assert.equal(backend.lingers, false, "the copy command exits after setting the clipboard");
		assert.equal(spawnSync(backend.clear[0], backend.clear[1], { windowsHide: true, timeout: 20_000 }).status, 0);
		assert.equal(read(), "", "cleared");
	} finally {
		const restore = saved
			? `$t = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${saved}')); [System.Windows.Forms.Clipboard]::SetText($t)`
			: "[System.Windows.Forms.Clipboard]::Clear()";
		spawnSync(PS, [...PS_ARGS, "-Command", `Add-Type -AssemblyName System.Windows.Forms; ${restore}`], { windowsHide: true, timeout: 20_000 });
	}
});

test("Windows: bw_run's shell is found even when bash.exe is not on PATH", windowsOnly, async (t) => {
	if (!WIN32) return t.skip();
	const gitCmd = join(process.env.ProgramFiles ?? "", "Git", "cmd");
	if (!existsSync(join(gitCmd, "git.exe"))) return t.skip("Git for Windows is not in its default place");
	const saved = process.env.PATH;
	process.env.PATH = gitCmd; // git.exe only: Git's installer does not add bin\bash.exe
	try {
		const bash = resolveBash();
		assert.equal(bash.program, join(process.env.ProgramFiles, "Git", "bin", "bash.exe"), "derived from where git.exe came from");
	} finally {
		process.env.PATH = saved;
	}
});

test("Windows: a command that is killed takes what it started with it", windowsOnly, async (t) => {
	if (!WIN32) return t.skip();
	const bash = resolveBash();
	if (!existsSync(bash.program)) return t.skip("no bash on this machine");
	const child = spawn(bash.program, [...bash.pre, "-c", "sleep 60 & wait"], { stdio: "ignore", windowsHide: true });
	await new Promise((resolve) => setTimeout(resolve, 1500)); // let `sleep` start
	killTree(child.pid);
	await new Promise((resolve) => setTimeout(resolve, 800));
	assert.notEqual(child.exitCode, null, "the shell itself is gone");
	const left = spawnSync(
		PS,
		[...PS_ARGS, "-Command", `(Get-CimInstance Win32_Process -Filter "Name='sleep.exe'" | Where-Object { $_.ParentProcessId -eq ${child.pid} } | Measure-Object).Count`],
		{ encoding: "utf8", timeout: 20_000, windowsHide: true },
	);
	assert.equal(left.stdout.trim(), "0", "the sleep it started is gone as well");
});
