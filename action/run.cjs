"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

function run(env = process.env) {
  let reportPath = "";
  let exitCode = 2;
  try {
    const format = env.KEYSPOOR_FORMAT || "sarif";
    if (!["sarif", "json", "jsonl"].includes(format)) {
      throw new Error("format must be sarif, json, or jsonl");
    }
    const directory = fs.mkdtempSync(path.join(env.RUNNER_TEMP, "keyspoor-report-"));
    reportPath = path.join(directory, `report.${format}`);
    const target = path.resolve(env.GITHUB_WORKSPACE, env.KEYSPOOR_SCAN_PATH || ".");
    const fd = fs.openSync(reportPath, "wx", 0o600);
    let result;
    try {
      result = spawnSync(process.execPath, [env.KEYSPOOR_CLI, "scan", "--format", format, "--", target], {
        cwd: env.GITHUB_WORKSPACE,
        env,
        shell: false,
        stdio: ["ignore", fd, "inherit"],
      });
    } finally {
      fs.closeSync(fd);
    }
    if (result.error || result.signal || ![0, 1, 2].includes(result.status)) {
      throw new Error("scanner did not complete normally");
    }
    exitCode = result.status;
  } catch (error) {
    console.error(`keyspoor action: ${error.message}`);
  }
  fs.appendFileSync(env.GITHUB_OUTPUT, `report-path=${reportPath}\nexit-code=${exitCode}\n`);
  return exitCode;
}

if (require.main === module) process.exitCode = run();
module.exports = { run };
