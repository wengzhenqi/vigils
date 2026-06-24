import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const backgroundSource = readFileSync(
    resolve(repoRoot, "extensions/chrome-mv3/background.js"),
    "utf8",
);

assert.match(
    backgroundSource,
    /catch\(\(\)\s*=>\s*\{\s*sendResponse\(\{\s*action:\s*"block"/s,
    "vigil_check unexpected errors must fail closed instead of allowing page writes",
);

assert.match(
    backgroundSource,
    /func:\s*\((?:expectedOrigin|origin)\)\s*=>\s*\{\s*if\s*\(\s*location\.origin\s*!==\s*(?:expectedOrigin|origin)\s*\)\s*return;/s,
    "forceDisableGuard must check the frame origin before disabling the content script",
);

const leakedSuperpowersFiles = execFileSync(
    "git",
    ["ls-files", ".superpowers"],
    { cwd: repoRoot, encoding: "utf8" },
)
    .trim()
    .split("\n")
    .filter(Boolean);

assert.deepEqual(
    leakedSuperpowersFiles,
    [],
    "root .superpowers runtime artifacts must not be tracked",
);
