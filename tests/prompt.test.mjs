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
};

function restore() {
	process.env.PATH = saved.PATH;
	if (saved.DISPLAY === undefined) delete process.env.DISPLAY;
	else process.env.DISPLAY = saved.DISPLAY;
	if (saved.WAYLAND_DISPLAY === undefined) delete process.env.WAYLAND_DISPLAY;
	else process.env.WAYLAND_DISPLAY = saved.WAYLAND_DISPLAY;
	if (saved.ZENITY_CODE === undefined) delete process.env.ZENITY_CODE;
	else process.env.ZENITY_CODE = saved.ZENITY_CODE;
	if (saved.ZENITY_VALUE === undefined) delete process.env.ZENITY_VALUE;
	else process.env.ZENITY_VALUE = saved.ZENITY_VALUE;
}

function mockZenity() {
	const dir = mkdtempSync(join(tmpdir(), "omp-vault-zenity-"));
	const log = join(dir, "log");
	writeFileSync(
		join(dir, "zenity"),
		`#!/bin/sh
printf '%s\\n' "$*" >> "${log}"
if [ -n "$ZENITY_CODE" ]; then exit "$ZENITY_CODE"; fi
printf '%s\\n' "$ZENITY_VALUE"
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
		const value = await promptSecret(tui(calls), "omp-vault", "主密码");
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
		assert.equal(await promptSecret(tui(calls), "omp-vault", "主密码"), undefined);
		assert.equal(await confirmWindow(tui(calls), "导入", "允许？"), false);
		assert.equal(calls.length, 0);
	} finally {
		restore();
		rmSync(dir, { recursive: true, force: true });
	}
});

test("a zenity crash falls back to the TUI, a deny does not", async () => {
	const { dir } = mockZenity();
	process.env.ZENITY_CODE = "99";
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
	const dir = mkdtempSync(join(tmpdir(), "omp-vault-empty-"));
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
