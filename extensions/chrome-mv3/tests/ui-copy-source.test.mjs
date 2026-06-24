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
    assert.doesNotMatch(html, /注册 Native Host/);
    assert.doesNotMatch(html, /nativeMessaging<\/code>.*本机 Host/);
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

test("consumer UI does not expose native host install copy as the default path", () => {
    const manifest = read("extensions/chrome-mv3/manifest.json");
    const popup = read("extensions/chrome-mv3/popup.html");
    const options = read("extensions/chrome-mv3/options.html");
    const consumerCopy = [manifest, popup, options].join("\n");
    assert.match(manifest, /浏览器内检测/);
    assert.doesNotMatch(consumerCopy, /注册 Native Host/);
    assert.doesNotMatch(consumerCopy, /com\.vigil\.host/);
    assert.doesNotMatch(consumerCopy, /原文仅在本机 Native Host/);
    assert.doesNotMatch(consumerCopy, /nativeMessaging<\/code>.*运行期敏感权限/);
});

test("consumer UI and background do not expose page exemption bypass", () => {
    const popupHtml = read("extensions/chrome-mv3/popup.html");
    const popupJs = read("extensions/chrome-mv3/popup.js");
    const background = read("extensions/chrome-mv3/background.js");
    const source = [popupHtml, popupJs, background].join("\n");
    assert.doesNotMatch(source, /vigil_get_exempt/);
    assert.doesNotMatch(source, /vigil_set_exempt/);
    assert.doesNotMatch(source, /vigil_clear_exempt/);
    assert.doesNotMatch(source, /allow_exempt/);
    assert.doesNotMatch(source, /豁免/);
});

test("popup no longer exposes tier controls", () => {
    const html = read("extensions/chrome-mv3/popup.html");
    const js = read("extensions/chrome-mv3/popup.js");
    const css = read("extensions/chrome-mv3/popup.css");
    const popupSource = [html, js, css].join("\n");
    assert.doesNotMatch(html, /data-tier=/);
    assert.doesNotMatch(html, /保护档位/);
    assert.doesNotMatch(popupSource, /recall-first/);
    assert.doesNotMatch(popupSource, /vigil_set_tier/);
    assert.doesNotMatch(popupSource, /vigilTier/);
});
