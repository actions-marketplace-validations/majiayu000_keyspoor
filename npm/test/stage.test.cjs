"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");

test("stages exactly the five release targets and refuses an incomplete release set", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "keyspoor-stage-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const packageRoot = path.join(root, "npm");
  const script = path.join(packageRoot, "scripts", "stage.mjs");
  const assets = path.join(root, "assets");
  fs.mkdirSync(path.dirname(script), { recursive: true });
  fs.mkdirSync(assets);
  fs.copyFileSync(path.join(__dirname, "..", "scripts", "stage.mjs"), script);
  fs.writeFileSync(path.join(packageRoot, "package.json"), JSON.stringify({ version: "0.1.0" }));
  fs.writeFileSync(path.join(root, "LICENSE"), "fixture license");
  fs.writeFileSync(path.join(root, "THIRD_PARTY_NOTICES"), "fixture notices");
  const targets = [
    ["linux-x64", "x86_64-unknown-linux-gnu"],
    ["linux-arm64", "aarch64-unknown-linux-gnu"],
    ["darwin-x64", "x86_64-apple-darwin"],
    ["darwin-arm64", "aarch64-apple-darwin"],
    ["win32-x64", "x86_64-pc-windows-msvc"],
  ];
  for (const [platform, target] of targets.slice(0, 4)) {
    fs.writeFileSync(path.join(assets, `keyspoor-v0.1.0-${target}`), `fixture ${platform}`);
  }
  const incomplete = spawnSync(process.execPath, [script, assets], { encoding: "utf8" });
  assert.equal(incomplete.status, 2);
  assert.match(incomplete.stderr, /Cannot stage Keyspoor release:/);
  assert.equal(fs.existsSync(path.join(packageRoot, "bin")), false);

  fs.writeFileSync(path.join(assets, "keyspoor-v0.1.0-x86_64-pc-windows-msvc.exe"), "fixture win32-x64");
  const complete = spawnSync(process.execPath, [script, assets], { encoding: "utf8" });
  assert.equal(complete.status, 0, complete.stderr);
  for (const [platform] of targets) {
    const binary = path.join(packageRoot, "bin", platform, platform === "win32-x64" ? "keyspoor.exe" : "keyspoor");
    assert.equal(fs.readFileSync(binary, "utf8"), `fixture ${platform}`);
    if (process.platform !== "win32") assert.equal(fs.statSync(binary).mode & 0o777, 0o755);
  }
  assert.deepEqual(fs.readdirSync(path.join(packageRoot, "bin")).sort(), targets.map(([platform]) => platform).sort());
  assert.equal(fs.readFileSync(path.join(packageRoot, "LICENSE"), "utf8"), "fixture license");
  assert.equal(fs.readFileSync(path.join(packageRoot, "THIRD_PARTY_NOTICES"), "utf8"), "fixture notices");
});
