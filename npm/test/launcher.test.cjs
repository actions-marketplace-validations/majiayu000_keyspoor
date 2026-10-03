"use strict";

const assert = require("node:assert/strict");
const { spawn, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { after, test } = require("node:test");
const { binaryPath } = require("../cli.cjs");

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "keyspoor-npm-"));
after(() => fs.rmSync(temporary, { recursive: true, force: true }));
const launcher = path.join(temporary, "cli.cjs");
fs.copyFileSync(path.join(__dirname, "..", "cli.cjs"), launcher);
const target = path.join(temporary, "bin", `${process.platform}-${process.arch}`);
fs.mkdirSync(target, { recursive: true });
const native = path.join(target, process.platform === "win32" ? "keyspoor.exe" : "keyspoor");
// Node itself is the test executable, so the fixture does not depend on a shell.
if (process.platform === "win32") fs.copyFileSync(process.execPath, native);
else fs.symlinkSync(process.execPath, native);

for (const code of [0, 1, 2]) {
  test(`preserves native exit ${code}`, () => {
    const result = spawnSync(process.execPath, [launcher, "-e", `process.exit(${code})`], { encoding: "utf8" });
    assert.equal(result.status, code);
    assert.equal(result.stderr, "");
  });
}

test("passes argv, stdin, stdout and stderr without shell interpretation", () => {
  const args = ["space in path", "$(printf unexpected)", "semi;colon", "中文"];
  const script = "process.stdout.write(JSON.stringify(process.argv.slice(1))); process.stdin.pipe(process.stdout); process.stderr.write('fixture stderr');";
  const result = spawnSync(process.execPath, [launcher, "-e", script, "--", ...args], {
    encoding: "utf8",
    input: "\nfixture stdin\n",
  });
  assert.equal(result.status, 0);
  assert.equal(result.stdout, `${JSON.stringify(args)}\nfixture stdin\n`);
  assert.equal(result.stderr, "fixture stderr");
});

test("missing bundled binary fails with exit 2", () => {
  const missing = path.join(temporary, "missing", "cli.cjs");
  fs.mkdirSync(path.dirname(missing));
  fs.copyFileSync(launcher, missing);
  const result = spawnSync(process.execPath, [missing, "private-input"], { encoding: "utf8" });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /cannot start bundled scanner \(ENOENT\)/);
  assert.doesNotMatch(result.stderr, /private-input/);
  assert.equal(result.stdout, "");
});

test("unsupported platform cannot resolve a bundled executable", () => {
  assert.throws(() => binaryPath("freebsd", "x64"), /Unsupported platform: freebsd-x64/);
  assert.throws(() => binaryPath("win32", "arm64"), /Unsupported platform: win32-arm64/);
  assert.match(binaryPath("win32", "x64"), /keyspoor\.exe$/);
});

test("unsupported platform exits 2 before launching a process", () => {
  const preload = path.join(temporary, "unsupported.cjs");
  fs.writeFileSync(preload, "Object.defineProperty(process, 'platform', { value: 'freebsd' });");
  const result = spawnSync(process.execPath, ["--require", preload, launcher], { encoding: "utf8" });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unsupported platform: freebsd-/);
  assert.equal(result.stdout, "");
});

test("forwards SIGTERM and preserves signal termination", { skip: process.platform === "win32", timeout: 5000 }, async () => {
  const child = spawn(process.execPath, [launcher, "-e", "process.stdout.write('ready'); setInterval(() => {}, 1000)"]);
  let output = "";
  child.stdout.on("data", (chunk) => {
    output += chunk;
    if (output === "ready") child.kill("SIGTERM");
  });
  const result = await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code, signal) => resolve({ code, signal }));
  });
  assert.equal(output, "ready");
  assert.deepEqual(result, { code: null, signal: "SIGTERM" });
});
