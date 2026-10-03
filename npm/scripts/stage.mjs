#!/usr/bin/env node
import { access, chmod, copyFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = fileURLToPath(new URL("../", import.meta.url));
const { version } = JSON.parse(await readFile(path.join(packageRoot, "package.json"), "utf8"));
const assets = process.argv[2];
if (!assets || process.argv.length !== 3) {
  console.error("Usage: node npm/scripts/stage.mjs <release-assets-directory>");
  process.exit(2);
}

const targets = [
  ["linux-x64", "x86_64-unknown-linux-gnu"],
  ["linux-arm64", "aarch64-unknown-linux-gnu"],
  ["darwin-x64", "x86_64-apple-darwin"],
  ["darwin-arm64", "aarch64-apple-darwin"],
  ["win32-x64", "x86_64-pc-windows-msvc"],
];

try {
  const files = targets.map(([platform, target]) => {
    const extension = platform === "win32-x64" ? ".exe" : "";
    return {
      source: path.resolve(assets, `keyspoor-v${version}-${target}${extension}`),
      destination: path.join(packageRoot, "bin", platform, `keyspoor${extension}`),
    };
  });
  // Check the complete release set before replacing any packaged binary.
  await Promise.all(files.map(({ source }) => access(source)));
  for (const { source, destination } of files) {
    await mkdir(path.dirname(destination), { recursive: true });
    await copyFile(source, destination);
    await chmod(destination, 0o755);
  }
  for (const filename of ["LICENSE", "THIRD_PARTY_NOTICES"]) {
    await copyFile(path.join(packageRoot, "..", filename), path.join(packageRoot, filename));
  }
  console.log(`Staged ${files.length} native binaries for keyspoor ${version}.`);
} catch (error) {
  console.error(`Cannot stage Keyspoor release: ${error.message}`);
  process.exitCode = 2;
}
