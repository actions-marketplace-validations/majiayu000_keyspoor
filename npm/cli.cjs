#!/usr/bin/env node
"use strict";

const { spawn } = require("node:child_process");
const path = require("node:path");

function binaryPath(platform, arch) {
  const target = `${platform}-${arch}`;
  if (!["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64", "win32-x64"].includes(target)) {
    throw new Error(`Unsupported platform: ${target}`);
  }
  return path.join(__dirname, "bin", target, platform === "win32" ? "keyspoor.exe" : "keyspoor");
}

function main() {
  let executable;
  try {
    executable = binaryPath(process.platform, process.arch);
  } catch (error) {
    console.error(`keyspoor: ${error.message}`);
    process.exitCode = 2;
    return;
  }

  const child = spawn(executable, process.argv.slice(2), { stdio: "inherit" });
  const signals = process.platform === "win32" ? ["SIGINT", "SIGTERM"] : ["SIGINT", "SIGTERM", "SIGHUP"];
  const handlers = signals.map((signal) => {
    const handler = () => child.kill(signal);
    process.on(signal, handler);
    return [signal, handler];
  });
  const cleanup = () => {
    for (const [signal, handler] of handlers) process.removeListener(signal, handler);
  };

  child.on("error", (error) => {
    cleanup();
    console.error(`keyspoor: cannot start bundled scanner (${error.code || "spawn error"})`);
    process.exitCode = 2;
  });
  child.on("close", (code, signal) => {
    cleanup();
    if (signal) {
      process.kill(process.pid, signal);
    } else {
      process.exitCode = code === null || code < 0 ? 2 : code;
    }
  });
}

if (require.main === module) main();
module.exports = { binaryPath };
