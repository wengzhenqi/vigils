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

    // 初始化:拉取 SW 当前 tier
    chrome.runtime.sendMessage({ type: "vigil_get_tier" }, (resp) => {
        if (chrome.runtime.lastError || !resp || !resp.tier) {
            flashTierHint("无法读取档位(SW 未就绪?)", "warn");
            return;
        }
        setCheckedTier(resp.tier);
    });

    // 切换事件:change 监听挂在 fieldset 上,event delegation 覆盖 3 radio
    tierFieldset.addEventListener("change", (ev) => {
        const tgt = ev.target;
        if (!tgt || tgt.name !== "tier" || !tgt.checked) return;
        const next = tgt.value;
        chrome.runtime.sendMessage(
            { type: "vigil_set_tier", tier: next },
            (resp) => {
                if (chrome.runtime.lastError || !resp || !resp.ok) {
                    flashTierHint(
                        `切换失败:${(resp && resp._error) || "unknown"}`,
                        "warn"
                    );
                    return;
                }
                flashTierHint(`档位已切换为 ${resp.tier}`);
            }
        );
    });
})();
