"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { test } = require("node:test");

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "keyspoor-action-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const workspace = path.join(directory, "workspace with spaces");
  const temporary = path.join(directory, "runner temp");
  fs.mkdirSync(workspace);
  fs.mkdirSync(temporary);
  const cli = path.join(directory, "fake cli.cjs");
  fs.writeFileSync(cli, 'process.stdout.write(JSON.stringify(process.argv.slice(2))); process.exitCode = Number(process.env.TEST_EXIT);');
  return {
    ...process.env,
    KEYSPOOR_CLI: cli,
    KEYSPOOR_SCAN_PATH: "--odd $(touch injected); 'quoted file'",
    KEYSPOOR_FORMAT: "sarif",
    RUNNER_TEMP: temporary,
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: path.join(directory, "outputs"),
  };
}

for (const exitCode of [0, 1, 2]) {
  test(`preserves scanner exit ${exitCode}, report and literal hostile path`, (t) => {
    const env = fixture(t);
    env.TEST_EXIT = String(exitCode);
    const child = spawnSync(process.execPath, [path.join(__dirname, "run.cjs")], { env, encoding: "utf8" });
    assert.equal(child.status, exitCode, child.stderr);
    const outputs = Object.fromEntries(fs.readFileSync(env.GITHUB_OUTPUT, "utf8").trimEnd().split("\n").map((line) => {
      const separator = line.indexOf("=");
      return [line.slice(0, separator), line.slice(separator + 1)];
    }));
    assert.equal(outputs["exit-code"], String(exitCode));
    assert.ok(outputs["report-path"].startsWith(env.RUNNER_TEMP + path.sep));
    assert.deepEqual(JSON.parse(fs.readFileSync(outputs["report-path"], "utf8")), [
      "scan", "--format", "sarif", "--", path.resolve(env.GITHUB_WORKSPACE, env.KEYSPOOR_SCAN_PATH),
    ]);
    assert.equal(fs.existsSync(path.join(env.GITHUB_WORKSPACE, "injected")), false);
    assert.equal(child.stdout, "");
  });
}

test("invalid format fails before scanning", (t) => {
  const env = fixture(t);
  env.KEYSPOOR_FORMAT = "sarif\n--no-ignore";
  const child = spawnSync(process.execPath, [path.join(__dirname, "run.cjs")], { env, encoding: "utf8" });
  assert.equal(child.status, 2);
  assert.equal(fs.readFileSync(env.GITHUB_OUTPUT, "utf8"), "report-path=\nexit-code=2\n");
  assert.deepEqual(fs.readdirSync(env.RUNNER_TEMP), []);
});

test("unexpected child exit maps to operational failure", (t) => {
  const env = fixture(t);
  env.TEST_EXIT = "17";
  const child = spawnSync(process.execPath, [path.join(__dirname, "run.cjs")], { env, encoding: "utf8" });
  assert.equal(child.status, 2);
  assert.match(child.stderr, /scanner did not complete normally/);
  assert.match(fs.readFileSync(env.GITHUB_OUTPUT, "utf8"), /exit-code=2\n$/);
});
