import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { confirmWindow, promptSecret, promptText } from "../src/prompt.ts";

const saved = {
	PATH: process.env.PATH,
	DISPLAY: process.env.DISPLAY,
	WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY,
	ZENITY_CODE: process.env.ZENITY_CODE,
	ZENITY_VALUE: process.env.ZENITY_VALUE,
	ZENITY_STDERR: process.env.ZENITY_STDERR,
	XDPYINFO_FAIL: process.env.XDPYINFO_FAIL,
};

function restore() {
	const env = process.env;
	env.PATH = saved.PATH;
	for (const key of ["DISPLAY", "WAYLAND_DISPLAY", "ZENITY_CODE", "ZENITY_VALUE", "ZENITY_STDERR", "XDPYINFO_FAIL"]) {
		if (saved[key] === undefined) delete env[key];
		else env[key] = saved[key];
	}
}

function mockZenity() {
	const dir = mkdtempSync(join(tmpdir(), "ai-vault-zenity-"));
	const log = join(dir, "log");
	writeFileSync(
		join(dir, "zenity"),
		`#!/bin/sh
printf '%s\\n' "$*" >> "${log}"
if [ -n "$ZENITY_STDERR" ]; then printf '%s\\n' "$ZENITY_STDERR" >&2; fi
if [ -n "$ZENITY_CODE" ]; then exit "$ZENITY_CODE"; fi
printf '%s\\n' "$ZENITY_VALUE"
`,
		{ mode: 0o755 },
	);
	// A deterministic X display probe: the tests run without a real X server.
	writeFileSync(
		join(dir, "xdpyinfo"),
		`#!/bin/sh
if [ -n "$XDPYINFO_FAIL" ]; then exit 1; fi
exit 0
`,
		{ mode: 0o755 },
	);
	process.env.PATH = `${dir}:${saved.PATH}`;
	process.env.DISPLAY = ":99";
	delete process.env.WAYLAND_DISPLAY;
	return { dir, log };
}

function tui(calls) {
	return {
		hasUI: true,
		ui: {
			async input(title, placeholder) {
				calls.push(["input", title, placeholder]);
				return "from-tui";
			},
			async confirm(title) {
				calls.push(["confirm", title]);
				return true;
			},
		},
	};
}

test("promptSecret reads the zenity window and does not ask the TUI", async () => {
	const { dir, log } = mockZenity();
	process.env.ZENITY_VALUE = "window-secret";
	delete process.env.ZENITY_CODE;
	const calls = [];
	try {
		const value = await promptSecret(tui(calls), "ai-vault", "主密码");
		assert.equal(value, "window-secret");
		assert.equal(calls.length, 0);
		assert.match(readFileSync(log, "utf8"), /--password/);
	} finally {
		restore();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("cancelling the window does not fall through to the TUI", async () => {
	const { dir } = mockZenity();
	process.env.ZENITY_CODE = "1";
	const calls = [];
	try {
		assert.equal(await promptSecret(tui(calls), "ai-vault", "主密码"), undefined);
		assert.equal(await confirmWindow(tui(calls), "导入", "允许？"), false);
		assert.equal(calls.length, 0);
	} finally {
		restore();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("a silent zenity failure on an unreachable display falls back to the TUI", async () => {
	const { dir } = mockZenity();
	process.env.ZENITY_CODE = "1";
	process.env.XDPYINFO_FAIL = "1";
	delete process.env.ZENITY_STDERR;
	const calls = [];
	try {
		assert.equal(await promptSecret(tui(calls), "ai-vault", "主密码"), "from-tui");
		assert.equal(calls[0][0], "input");
	} finally {
		restore();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("a zenity crash falls back to the TUI, a deny does not", async () => {
	const { dir } = mockZenity();
	process.env.ZENITY_CODE = "255";
	process.env.ZENITY_STDERR = "This option is not available. Please see --help for all possible usages.";
	const calls = [];
	try {
		assert.equal(await confirmWindow(tui(calls), "确认", "允许？"), true);
		assert.equal(calls.length, 1);
	} finally {
		restore();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("exit 1 with only GTK diagnostics is a cancel, not a failed window", async () => {
	const { dir } = mockZenity();
	process.env.ZENITY_CODE = "1";
	process.env.ZENITY_STDERR =
		"(zenity:4242): Gtk-WARNING **: 10:00:00.000: Trying to measure GtkLabel 0x1 for height of 9";
	const calls = [];
	try {
		assert.equal(await promptSecret(tui(calls), "ai-vault", "主密码"), undefined);
		assert.equal(await confirmWindow(tui(calls), "确认", "允许？"), false);
		assert.equal(calls.length, 0, "a cancel was re-asked in the terminal");
	} finally {
		restore();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("exit 1 with a startup error means no window opened: fall back to the TUI", async () => {
	const { dir } = mockZenity();
	process.env.ZENITY_CODE = "1";
	process.env.ZENITY_STDERR = "This option is not available. Please see --help for all possible usages.";
	const calls = [];
	try {
		assert.equal(await promptSecret(tui(calls), "ai-vault", "主密码"), "from-tui");
		assert.equal(calls[0][0], "input");
	} finally {
		restore();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("exit 1 with 'cannot open display' falls back even behind a GTK prefix", async () => {
	const { dir } = mockZenity();
	process.env.ZENITY_CODE = "1";
	process.env.ZENITY_STDERR = "** (zenity:4242): WARNING **: cannot open display: :99";
	const calls = [];
	try {
		assert.equal(await confirmWindow(tui(calls), "确认", "允许？"), true);
		assert.equal(calls.length, 1);
	} finally {
		restore();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("missing zenity falls back to the TUI", async () => {
	const dir = mkdtempSync(join(tmpdir(), "ai-vault-empty-"));
	process.env.PATH = dir;
	process.env.DISPLAY = ":99";
	delete process.env.WAYLAND_DISPLAY;
	const calls = [];
	try {
		assert.equal(await promptText(tui(calls), "名称", "条目名"), "from-tui");
		assert.equal(calls[0][0], "input");
		assert.equal(await confirmWindow(tui(calls), "确认", "允许？"), true);
		assert.equal(calls[1][0], "confirm");
	} finally {
		restore();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("no display and no UI fails closed", async () => {
	delete process.env.DISPLAY;
	delete process.env.WAYLAND_DISPLAY;
	try {
		assert.equal(await promptSecret(undefined, "t", "l"), undefined);
		assert.equal(await confirmWindow({ hasUI: false, ui: tui([]).ui }, "t", "m"), false);
	} finally {
		restore();
	}
});
