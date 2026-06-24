import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");

function read(rel) {
    return readFileSync(resolve(repoRoot, rel), "utf8");
}

test("options no longer centers native host install as default path", () => {
    const html = read("extensions/chrome-mv3/options.html");
    const js = read("extensions/chrome-mv3/options.js");
    assert.match(html, /普通模式/);
    assert.match(html, /企业模式/);
    assert.match(html, /企业连接/);
    assert.doesNotMatch(js, /vigil-native-host install --extension-id/);
});

test("options uses mode runtime messages", () => {
    const js = read("extensions/chrome-mv3/options.js");
    assert.match(js, /vigil_get_mode/);
    assert.match(js, /vigil_set_mode/);
});

test("popup displays consumer and enterprise mode labels", () => {
    const html = read("extensions/chrome-mv3/popup.html");
    const js = read("extensions/chrome-mv3/popup.js");
    assert.match(html + js, /普通保护/);
    assert.match(html + js, /企业保护/);
});
