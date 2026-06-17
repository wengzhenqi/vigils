import { normalizeCustomSiteInput } from "./custom-sites.js";

// I09b-α3 options page —— 扩展 ID 展示 + Native Host install 命令复制助手。
//
// 目标:β1 `vigil-native-host install --extension-id <ID>` 的 `<ID>` 只有用户装扩展后才
// 能拿到(chrome-extension ID 由 Chrome 基于扩展源码哈希生成),在此页面暴露出来方便复制。
//
// 安全契约:
//   - CSP `script-src 'self'`:本脚本外链,无 inline handler
//   - 所有文本插入用 textContent,含 `chrome.runtime.id` —— 虽然是 Chrome 生成的固定值,
//     但保持"backend/runtime 数据纯文本插入"不变量(与 popup.js / I08b UI 一致)
//   - Clipboard API:`navigator.clipboard.writeText` 在 extension page 无需额外权限

(() => {
    "use strict";

    const idEl = document.getElementById("extension-id");
    const copyIdBtn = document.getElementById("copy-id-btn");
    const installCmdEl = document.getElementById("install-cmd");
    const copyCmdBtn = document.getElementById("copy-cmd-btn");
    const copyCmdHint = document.getElementById("copy-cmd-hint");
    const uninstallCmdEl = document.getElementById("uninstall-cmd");
    const statusCmdEl = document.getElementById("status-cmd");
    const customSiteForm = document.getElementById("custom-site-form");
    const customSiteInput = document.getElementById("custom-site-input");
    const customSiteAddBtn = document.getElementById("custom-site-add-btn");
    const customSiteHint = document.getElementById("custom-site-hint");
    const customSiteList = document.getElementById("custom-site-list");
    const customSiteEmpty = document.getElementById("custom-site-empty");
    const TIER_STORAGE_KEY = "vigilTier";
    const TIER_DEFAULT = "balanced";
    const TIER_VALUES = ["strict", "balanced", "recall-first"];

    // Chrome 扩展 ID:`chrome.runtime.id` 返 32 chars a-p,是 Chrome 对扩展源码的哈希;
    // install/reload 后稳定,用户卸载重装会变(所以 Host manifest 注册后如果重装扩展
    // 需要重跑 install --extension-id)
    const extId = chrome.runtime.id;
    idEl.textContent = extId || "(无法获取)";

    // 构造 install 命令。用**单引号**包裹 ID 避免 shell 意外(虽然 a-p 都是安全字符,
    // 仍保持"与可执行文件路径同等保护"习惯);Windows cmd 用双引号对应。
    // 为跨平台可读,给出两份:
    const unixCmd = `vigil-native-host install --extension-id '${extId}'`;
    const winCmd = `vigil-native-host.exe install --extension-id "${extId}"`;
    installCmdEl.textContent = [
        "# Linux / macOS:",
        unixCmd,
        "",
        "# Windows (cmd / PowerShell):",
        winCmd,
    ].join("\n");

    uninstallCmdEl.textContent = "vigil-native-host uninstall";
    statusCmdEl.textContent = "vigil-native-host status";

    function flashHint(msg) {
        copyCmdHint.textContent = msg;
        copyCmdHint.classList.remove("fade");
        clearTimeout(flashHint._t);
        flashHint._t = setTimeout(() => {
            copyCmdHint.classList.add("fade");
        }, 1500);
    }

    async function copyText(text) {
        // Clipboard API 可能在某些场景(如 non-active document)失败;提供 fallback。
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch {
            // Fallback:临时 textarea + execCommand('copy')
            try {
                const ta = document.createElement("textarea");
                ta.value = text;
                ta.setAttribute("readonly", "");
                ta.style.position = "fixed";
                ta.style.left = "-9999px";
                document.body.appendChild(ta);
                ta.select();
                const ok = document.execCommand("copy");
                document.body.removeChild(ta);
                return ok;
            } catch {
                return false;
            }
        }
    }

    copyIdBtn.addEventListener("click", async () => {
        const ok = await copyText(extId);
        flashHint(ok ? "ID 已复制" : "复制失败(请手工选中)");
    });

    copyCmdBtn.addEventListener("click", async () => {
        // 复制当前 OS 对应的那份;Windows 识别:userAgent / platform 嗅探不稳,
        // 简单化:把两条都放进 clipboard(注释行作上下文 OK)
        const ok = await copyText(installCmdEl.textContent);
        flashHint(ok ? "命令已复制(含平台注释)" : "复制失败(请手工选中)");
    });

    // ─── 自定义保护网站 ───────────────────────────────────────────
    // options 页负责在用户点击手势内请求 host permission;SW 负责校验、持久化和动态注入。

    function sendRuntimeMessage(msg) {
        return new Promise((resolve) => {
            chrome.runtime.sendMessage(msg, (resp) => {
                if (chrome.runtime.lastError) {
                    resolve({ ok: false, _error: chrome.runtime.lastError.message });
                    return;
                }
                resolve(resp || {});
            });
        });
    }

    function requestOriginPermission(pattern) {
        return new Promise((resolve) => {
            chrome.permissions.request({ origins: [pattern] }, (granted) => {
                if (chrome.runtime.lastError) {
                    resolve({ granted: false, _error: chrome.runtime.lastError.message });
                    return;
                }
                resolve({ granted: Boolean(granted) });
            });
        });
    }

    function removeOriginPermission(pattern) {
        return new Promise((resolve) => {
            chrome.permissions.remove({ origins: [pattern] }, () => {
                void chrome.runtime.lastError;
                resolve();
            });
        });
    }

    const customSiteErrorLabels = {
        empty: "请输入域名",
        wildcard_not_allowed: "不支持通配符",
        userinfo_not_allowed: "不允许包含用户名或密码",
        domain_only: "只支持域名,不支持路径或查询参数",
        invalid_host: "域名格式无效",
        https_only: "仅支持 HTTPS 网站",
        permission_missing: "站点权限未授权",
    };

    function flashCustomSiteHint(msg, tone /* "ok" | "warn" */) {
        customSiteHint.textContent = msg;
        customSiteHint.style.color = tone === "warn" ? "#b45309" : "#15803d";
        customSiteHint.classList.remove("fade");
        clearTimeout(flashCustomSiteHint._t);
        flashCustomSiteHint._t = setTimeout(() => {
            customSiteHint.classList.add("fade");
        }, 2200);
    }

    function customSiteErrorMessage(code) {
        return customSiteErrorLabels[code] || String(code || "unknown");
    }

    function renderCustomSites(sites) {
        customSiteList.replaceChildren();
        const items = Array.isArray(sites) ? sites : [];
        customSiteEmpty.classList.toggle("hidden", items.length !== 0);

        for (const site of items) {
            const li = document.createElement("li");
            li.className = "custom-site-row";

            const host = document.createElement("code");
            host.className = "custom-site-host";
            host.textContent = site.host || site.pattern || "?";
            host.title = site.pattern || site.host || "";

            const status = document.createElement("span");
            status.className = "custom-site-status";
            if (site.hasPermission) {
                status.textContent = "已授权";
            } else {
                status.textContent = "缺权限";
                status.classList.add("custom-site-status-missing");
            }

            const removeBtn = document.createElement("button");
            removeBtn.type = "button";
            removeBtn.className = "custom-site-remove";
            removeBtn.textContent = "删除";
            removeBtn.addEventListener("click", async () => {
                removeBtn.disabled = true;
                const resp = await sendRuntimeMessage({
                    type: "vigil_remove_custom_site",
                    input: site.host || site.pattern,
                });
                if (!resp || !resp.ok) {
                    flashCustomSiteHint(
                        `删除失败:${customSiteErrorMessage(resp && resp._error)}`,
                        "warn",
                    );
                    removeBtn.disabled = false;
                    return;
                }
                flashCustomSiteHint("已删除并释放站点权限");
                await refreshCustomSites();
            });

            li.replaceChildren(host, status, removeBtn);
            customSiteList.appendChild(li);
        }
    }

    async function refreshCustomSites() {
        const resp = await sendRuntimeMessage({ type: "vigil_list_custom_sites" });
        renderCustomSites(resp && resp.sites);
    }

    customSiteForm.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const input = customSiteInput.value;
        customSiteAddBtn.disabled = true;
        try {
            const normalized = normalizeCustomSiteInput(input);
            if (!normalized || !normalized.ok) {
                flashCustomSiteHint(
                    `添加失败:${customSiteErrorMessage(normalized && normalized.error)}`,
                    "warn",
                );
                return;
            }

            const permission = await requestOriginPermission(normalized.pattern);
            if (!permission.granted) {
                flashCustomSiteHint(
                    permission._error
                        ? `授权失败:${permission._error}`
                        : "用户未授权该网站权限",
                    "warn",
                );
                return;
            }

            const added = await sendRuntimeMessage({
                type: "vigil_add_custom_site",
                site: normalized,
            });
            if (!added || !added.ok) {
                await removeOriginPermission(normalized.pattern);
                flashCustomSiteHint(
                    `保存失败:${customSiteErrorMessage(added && added._error)}`,
                    "warn",
                );
                return;
            }

            customSiteInput.value = "";
            flashCustomSiteHint(`已保护 ${normalized.host}`);
            await refreshCustomSites();
        } finally {
            customSiteAddBtn.disabled = false;
        }
    });

    // ─── ISS-007:3 档档位选择 ───────────────────────────────────────
    // 查 SW 当前 tier 并回填 radio;用户切换 → 发消息回 SW。
    // SW 不持久化(in-memory),每次打开 options 都重新读,避免 UI 与 SW 状态漂移。

    const tierFieldset = document.getElementById("tier-fieldset");
    const tierHint = document.getElementById("tier-hint");

    function flashTierHint(msg, tone /* "ok" | "warn" */) {
        tierHint.textContent = msg;
        tierHint.style.color = tone === "warn" ? "#b45309" : "#15803d";
        tierHint.classList.remove("fade");
        clearTimeout(flashTierHint._t);
        flashTierHint._t = setTimeout(() => {
            tierHint.classList.add("fade");
        }, 2000);
    }

    function setCheckedTier(tier) {
        const input = tierFieldset.querySelector(
            `input[name="tier"][value="${tier}"]`
        );
        if (input) input.checked = true;
    }

    function persistTier(next, callback) {
        if (!TIER_VALUES.includes(next)) {
            callback({ ok: false, _error: "invalid_tier" });
            return;
        }
        chrome.storage.local.set({ [TIER_STORAGE_KEY]: next }, () => {
            if (chrome.runtime.lastError) {
                callback({
                    ok: false,
                    _error: chrome.runtime.lastError.message || "runtime_error",
                });
                return;
            }
            chrome.runtime.sendMessage({ type: "vigil_set_tier", tier: next }, () => {
                void chrome.runtime.lastError;
            });
            callback({ ok: true, tier: next });
        });
    }

    // 初始化:从 storage 读取当前 tier;SW 也监听同一个 key。
    chrome.storage.local.get({ [TIER_STORAGE_KEY]: TIER_DEFAULT }, (got) => {
        if (chrome.runtime.lastError) {
            flashTierHint("无法读取档位", "warn");
            return;
        }
        const tier = got[TIER_STORAGE_KEY];
        setCheckedTier(TIER_VALUES.includes(tier) ? tier : TIER_DEFAULT);
    });

    // 切换事件:change 监听挂在 fieldset 上,event delegation 覆盖 3 radio
    tierFieldset.addEventListener("change", (ev) => {
        const tgt = ev.target;
        if (!tgt || tgt.name !== "tier" || !tgt.checked) return;
        const next = tgt.value;
        persistTier(next, (resp) => {
            if (!resp || !resp.ok) {
                flashTierHint(`切换失败:${(resp && resp._error) || "unknown"}`, "warn");
                return;
            }
            flashTierHint(`档位已切换为 ${resp.tier}`);
        });
    });

    refreshCustomSites();
})();
