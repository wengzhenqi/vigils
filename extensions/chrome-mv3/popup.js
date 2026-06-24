// I09b-α3 popup:展示最近 findings(只读 in-memory 环形队列)+ 清空 + 跳转 options。
//
// 安全契约:
//   - §I-9.1:findings 条目不含原文;只有 origin / event_kind / action / findings enum 列表 / ts
//   - CSP `script-src 'self'`:所有 DOM 文本用 textContent(无 innerHTML / outerHTML),
//     即使 origin 字段被后端污染也只作纯文本展示(XSS 安全)
//   - popup 本身无 chrome.storage 依赖;findings 只读 SW 内存队列

(() => {
    "use strict";

    const listEl = document.getElementById("findings-list");
    const emptyHintEl = document.getElementById("empty-hint");
    const countLabel = document.getElementById("count-label");
    const refreshBtn = document.getElementById("refresh-btn");
    const clearBtn = document.getElementById("clear-btn");
    const optionsLink = document.getElementById("options-link");
    const statusPill = document.getElementById("status-pill");
    const statusLabel = document.getElementById("status-label");
    const modeLabel = document.getElementById("mode-label");

    function fmtTs(ts) {
        try {
            return new Date(ts).toLocaleTimeString();
        } catch {
            return String(ts);
        }
    }

    /**
     * 渲染 findings 列表。**全程使用 DOM API + textContent**,严禁 innerHTML —
     * origin / findings enum 值来自 Rust 端,按脱敏契约应不含恶意 HTML,但扩展 popup
     * 作为信任边界内的 UI,仍保持"所有 backend 数据纯文本插入"不变量(与 I08b UI 一致)。
     */
    function renderFindings(items) {
        // 清空 list(textContent = "" 安全清空,replaceChildren 更现代 + 清晰)
        listEl.replaceChildren();

        if (!Array.isArray(items) || items.length === 0) {
            emptyHintEl.classList.remove("hidden");
            listEl.classList.add("hidden");
            countLabel.textContent = "0 条";
            return;
        }

        emptyHintEl.classList.add("hidden");
        listEl.classList.remove("hidden");
        countLabel.textContent = `${items.length} 条`;

        for (const it of items) {
            const li = document.createElement("li");

            // 第一列:action tag
            const tag = document.createElement("span");
            tag.className = `tag tag-${it.action || "block"}`;
            tag.textContent = (it.action || "block").toUpperCase();
            li.appendChild(tag);

            // 第二列:meta + findings + ts
            const col = document.createElement("div");

            const metaLine = document.createElement("div");
            metaLine.className = "meta-line";
            const ts = document.createElement("code");
            ts.textContent = fmtTs(it.ts);
            metaLine.appendChild(ts);
            metaLine.append(" · ");
            const kind = document.createElement("span");
            kind.textContent = it.event_kind || "?";
            metaLine.appendChild(kind);
            metaLine.append(" · ");
            const origin = document.createElement("code");
            origin.textContent = it.origin || "?";
            metaLine.appendChild(origin);
            col.appendChild(metaLine);

            if (Array.isArray(it.findings) && it.findings.length > 0) {
                const fLine = document.createElement("div");
                fLine.className = "findings-inline";
                for (const f of it.findings) {
                    const c = document.createElement("code");
                    c.textContent = String(f);
                    fLine.appendChild(c);
                }
                col.appendChild(fLine);
            }

            li.appendChild(col);
            listEl.appendChild(li);
        }
    }

    function refresh() {
        chrome.runtime.sendMessage({ type: "vigil_recent_findings" }, (resp) => {
            if (chrome.runtime.lastError) {
                // SW 冷启动时偶尔会 "Could not establish connection";静默,下次 refresh 再试
                renderFindings([]);
                return;
            }
            renderFindings((resp && resp.findings) || []);
        });
    }

    function refreshMode() {
        chrome.runtime.sendMessage({ type: "vigil_get_mode" }, (resp) => {
            if (chrome.runtime.lastError) return;
            const mode = resp && resp.mode === "enterprise" ? "enterprise" : "consumer";
            if (modeLabel) {
                modeLabel.textContent = mode === "enterprise" ? "企业保护" : "普通保护";
            }
        });
    }

    // 事件绑定:addEventListener 非 inline onclick(CSP `script-src 'self'` 下 inline
    // handler 也会被拒;addEventListener 总是 self-hosted 安全)
    clearBtn.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "vigil_clear_findings" }, () => {
            // chrome.runtime.lastError 忽略,后续 refresh 自然反映空状态
            refresh();
        });
    });

    refreshBtn.addEventListener("click", () => {
        refresh();
        refreshTier();
        refreshMode();
    });

    optionsLink.addEventListener("click", (ev) => {
        ev.preventDefault();
        // MV3 正确姿势:chrome.runtime.openOptionsPage() 处理 pop-up / tab 两种场景
        if (chrome.runtime.openOptionsPage) {
            chrome.runtime.openOptionsPage();
        }
    });

    function setHeaderStatus(label, tone) {
        if (!statusPill || !statusLabel) return;
        statusLabel.textContent = label;
        statusPill.classList.toggle("status-pill-warn", tone === "warn");
        statusPill.classList.toggle("status-pill-muted", tone === "muted");
    }

    // ISS-007:tier 快速切换;复用 options 页同一 SW 消息,不新增权限 / storage。
    const tierButtons = Array.from(document.querySelectorAll(".tier-btn"));
    const tierHintEl = document.getElementById("tier-hint");
    let currentTier = null;
    let tierSwitchPending = false;
    const TIER_STORAGE_KEY = "vigilTier";
    const TIER_DEFAULT = "balanced";
    const TIER_VALUES = ["strict", "balanced", "recall-first"];

    function setTierHint(msg, tone) {
        if (!tierHintEl) return;
        tierHintEl.textContent = msg || "";
        tierHintEl.classList.toggle("tier-hint-warn", tone === "warn");
    }

    function renderTier(tier) {
        currentTier = tier || null;
        for (const btn of tierButtons) {
            const active = btn.dataset.tier === currentTier;
            btn.classList.toggle("tier-btn-active", active);
            btn.setAttribute("aria-pressed", active ? "true" : "false");
            btn.disabled = tierSwitchPending;
        }
        if (currentTier) setTierHint(currentTier, "ok");
    }

    function refreshTier() {
        if (tierSwitchPending) return;
        chrome.storage.local.get({ [TIER_STORAGE_KEY]: TIER_DEFAULT }, (got) => {
            if (chrome.runtime.lastError) {
                renderTier(null);
                setTierHint("档位未知", "warn");
                return;
            }
            const tier = got[TIER_STORAGE_KEY];
            renderTier(TIER_VALUES.includes(tier) ? tier : TIER_DEFAULT);
        });
    }

    function setTier(next, callback) {
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
            // Best-effort wake/update for an already-running service worker. Storage is
            // the source of truth, so this callback must not gate UI success.
            chrome.runtime.sendMessage({ type: "vigil_set_tier", tier: next }, () => {
                void chrome.runtime.lastError;
            });
            callback({ ok: true, tier: next });
        });
    }

    for (const btn of tierButtons) {
        btn.addEventListener("click", () => {
            const next = btn.dataset.tier;
            if (!next || next === currentTier) return;
            tierSwitchPending = true;
            for (const b of tierButtons) b.disabled = true;
            setTierHint("切换中...");
            setTier(next, (resp) => {
                tierSwitchPending = false;
                if (!resp || !resp.ok) {
                    renderTier(currentTier);
                    setTierHint(`切换失败:${(resp && resp._error) || "unknown"}`, "warn");
                    return;
                }
                renderTier(resp.tier);
                refresh();
            });
        });
    }

    // 首次渲染:最近记录 + 档位 + 模式
    (() => {
        setHeaderStatus("保护中", "ok");
        refresh();
        refreshTier();
        refreshMode();
    })();

    // popup 是短命 document,不需要 MutationObserver;但偶尔用户让 popup 开着时
    // 手动触发一次再渲染无害 —— 2s 一次轻量 refresh(同步 findings + tier)
    setInterval(() => {
        refresh();
        refreshTier();
        refreshMode();
    }, 2000);
})();
