/**
 * v0.15 Theme G — real-time ledger updates(前端 listener)。
 *
 * 监听后端 poller emit 的 `ledger-events-changed`(payload `{ latest_event_id }`),
 * 触发回调刷新当前页。替代**完全 event-backed 3 页**(Activity / Approval / Replay)
 * 原本各自的 5s `setInterval`。
 *
 * **语义边界**(Theme G spike § 1 / Codex Code R1):本事件**仅**代表"事件流(events 表)
 * 有新 event",不覆盖 redaction_scans/findings(PrivacyFindings)、sessions 直写表、
 * 以及 tool_descriptors first-seen(ServerRegistry pendingTools)。**PrivacyFindings 与
 * ServerRegistry 保留各自 fallback poll,不接此 composable**。
 *
 * **降级**(spike § 3.2):Tauri event API 不可用(纯浏览器 dev / SSR)时,feature
 * detect 失败 → 回退到 setInterval(intervalMs),保证不回归"无自动刷新"。
 *
 * **tab hidden 守门 + catch-up**(Codex code review R1):隐藏时跳过 `onChange`(省资源),
 * 但**记录** `missedWhileHidden`;`visibilitychange` 回到可见时补发一次。否则隐藏期间外部
 * 进程写入的变更会一直 stale 到下一个 event / 手动刷新 —— 这是相对旧 5s poll(回到可见后
 * 下一 tick 即追上)的行为回归,必须修复。
 */
import { onMounted, onUnmounted } from "vue";

interface LedgerLiveOptions {
  /** ledger 有新 event 时触发(通常 = store.refresh)*/
  onChange: () => void;
  /** 降级 setInterval 间隔(ms),默认 5000(对齐原前端 poll)*/
  fallbackIntervalMs?: number;
}

export function useLedgerLiveUpdates(opts: LedgerLiveOptions): void {
  const fallbackMs = opts.fallbackIntervalMs ?? 5000;

  // listen 的 unlisten 句柄(异步解析);fallback timer 句柄
  let unlisten: (() => void) | null = null;
  let fallbackTimer: ReturnType<typeof setInterval> | null = null;
  let disposed = false;
  // Codex R1:隐藏期间被跳过的变更标志,回到可见时补发
  let missedWhileHidden = false;

  function fireIfVisible(): void {
    if (document.hidden) {
      missedWhileHidden = true; // 标记:隐藏期间有变更被跳过
      return;
    }
    opts.onChange();
  }

  // 回到可见:若隐藏期间有遗漏,补发一次(等价旧 poll 回可见后追上的语义)
  function onVisibilityChange(): void {
    if (!document.hidden && missedWhileHidden) {
      missedWhileHidden = false;
      opts.onChange();
    }
  }

  function startFallback(): void {
    fallbackTimer = setInterval(fireIfVisible, fallbackMs);
  }

  onMounted(async () => {
    document.addEventListener("visibilitychange", onVisibilityChange);
    // feature detect:Tauri event API 在打包 webview 内可用,纯浏览器 dev 下 import 失败
    try {
      const { listen } = await import("@tauri-apps/api/event");
      const handle = await listen("ledger-events-changed", () => {
        fireIfVisible();
      });
      if (disposed) {
        // 组件在 await 期间已卸载 —— 立即解绑,防泄漏
        handle();
        return;
      }
      unlisten = handle;
    } catch {
      // Tauri event 不可用 → 降级 setInterval(不回归"无自动刷新")
      if (!disposed) startFallback();
    }
  });

  onUnmounted(() => {
    disposed = true;
    document.removeEventListener("visibilitychange", onVisibilityChange);
    if (unlisten) {
      unlisten();
      unlisten = null;
    }
    if (fallbackTimer !== null) {
      clearInterval(fallbackTimer);
      fallbackTimer = null;
    }
  });
}
