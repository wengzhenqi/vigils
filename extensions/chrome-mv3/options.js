import { normalizeCustomSiteInput } from "./custom-sites.js";

(() => {
    "use strict";

    const idEl = document.getElementById("extension-id");
    const copyIdBtn = document.getElementById("copy-id-btn");
    const extensionIdHint = document.getElementById("extension-id-hint");
    const customSiteForm = document.getElementById("custom-site-form");
    const customSiteInput = document.getElementById("custom-site-input");
    const customSiteAddBtn = document.getElementById("custom-site-add-btn");
    const customSiteHint = document.getElementById("custom-site-hint");
    const customSiteList = document.getElementById("custom-site-list");
    const customSiteEmpty = document.getElementById("custom-site-empty");
    const modeInputs = Array.from(document.querySelectorAll("input[name='vigil-mode']"));
    const modeHint = document.getElementById("mode-hint");
    const enterpriseSection = document.getElementById("enterprise-section");
    const tierFieldset = document.getElementById("tier-fieldset");
    const tierHint = document.getElementById("tier-hint");
    const TIER_STORAGE_KEY = "vigilTier";
    const TIER_DEFAULT = "balanced";
    const TIER_VALUES = ["strict", "balanced", "recall-first"];

    const extId = chrome.runtime.id;
    idEl.textContent = extId || "(无法获取)";

    async function copyText(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch {
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

    function flashExtensionIdHint(msg, tone /* "ok" | "warn" */) {
        if (!extensionIdHint) return;
        extensionIdHint.textContent = msg;
        extensionIdHint.style.color = tone === "warn" ? "#b45309" : "#15803d";
        extensionIdHint.classList.remove("fade");
        clearTimeout(flashExtensionIdHint._t);
        flashExtensionIdHint._t = setTimeout(() => {
            extensionIdHint.classList.add("fade");
        }, 1800);
    }

    function setEnterpriseVisible(mode) {
        if (!enterpriseSection) return;
        enterpriseSection.classList.toggle("hidden", mode !== "enterprise");
    }

    async function refreshMode() {
        const resp = await sendRuntimeMessage({ type: "vigil_get_mode" });
        const mode = resp && resp.mode === "enterprise" ? "enterprise" : "consumer";
        for (const input of modeInputs) {
            input.checked = input.value === mode;
        }
        setEnterpriseVisible(mode);
        if (modeHint) {
            modeHint.textContent = mode === "enterprise"
                ? "企业模式已开启。未配置 provider 时仍使用普通保护。"
                : "普通模式保护中：检测在浏览器内完成。";
        }
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
        const input = tierFieldset.querySelector(`input[name="tier"][value="${tier}"]`);
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

    copyIdBtn.addEventListener("click", async () => {
        const ok = await copyText(extId);
        flashExtensionIdHint(ok ? "ID 已复制" : "复制失败(请手工选中)", ok ? "ok" : "warn");
    });

    for (const input of modeInputs) {
        input.addEventListener("change", async () => {
            if (!input.checked) return;
            const resp = await sendRuntimeMessage({
                type: "vigil_set_mode",
                mode: input.value,
            });
            if (!resp || !resp.ok) {
                flashCustomSiteHint(`模式切换失败:${resp && resp._error}`, "warn");
                await refreshMode();
                return;
            }
            await refreshMode();
        });
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

    chrome.storage.local.get({ [TIER_STORAGE_KEY]: TIER_DEFAULT }, (got) => {
        if (chrome.runtime.lastError) {
            flashTierHint("无法读取档位", "warn");
            return;
        }
        const tier = got[TIER_STORAGE_KEY];
        setCheckedTier(TIER_VALUES.includes(tier) ? tier : TIER_DEFAULT);
    });

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

    refreshMode();
    refreshCustomSites();
})();
