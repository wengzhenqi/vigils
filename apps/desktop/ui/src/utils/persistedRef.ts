/**
 * v0.14 Theme F — Filter persistence helper。
 *
 * 把 Vue ref 自动同步到 localStorage,reload 后恢复。
 *
 * 设计要点:
 * - **键名前缀**:统一 `vigil:filter:`,便于一次性清空(`clearPersistedFilters`)
 * - **SSR/Tauri-startup safe**:`typeof localStorage` 守门(理论上 Tauri webview 始终有)
 * - **错误吞掉**:JSON.parse 失败 / quota 超限不影响业务,回落到 initial
 * - **deep watch**:数组 / 对象的内部 mutate 也触发持久化
 * - **不暴露 raw key 给业务层**:业务层只传简短 logical key
 *
 * 不适用场景:大对象(>1MB)/ 跨 tab 同步(暂无需求)/ 加密(filter 非敏感)
 */
import { ref, watch, type Ref } from "vue";

const KEY_PREFIX = "vigil:filter:";

/** 已注册的所有 logical key — 供 `clearAllPersistedFilters` 使用 */
const registeredKeys = new Set<string>();

export function persistedRef<T>(logicalKey: string, initial: T): Ref<T> {
  registeredKeys.add(logicalKey);
  const fullKey = KEY_PREFIX + logicalKey;

  let loaded: T = initial;
  try {
    if (typeof localStorage !== "undefined") {
      const raw = localStorage.getItem(fullKey);
      if (raw !== null) {
        loaded = JSON.parse(raw) as T;
      }
    }
  } catch {
    // 损坏的 JSON 或 disabled storage:静默回退到 initial
  }

  const r = ref(loaded) as Ref<T>;
  watch(
    r,
    (v) => {
      try {
        if (typeof localStorage !== "undefined") {
          localStorage.setItem(fullKey, JSON.stringify(v));
        }
      } catch {
        // quota / disabled:忽略,内存值仍有效
      }
    },
    { deep: true },
  );
  return r;
}

/** 清除指定 logical keys 的持久化值(不重置内存中的 ref,需调用方自行重置)*/
export function clearPersistedFilters(logicalKeys: readonly string[]): void {
  if (typeof localStorage === "undefined") return;
  for (const k of logicalKeys) {
    try {
      localStorage.removeItem(KEY_PREFIX + k);
    } catch {
      // ignore
    }
  }
}

/** 列出已注册的 keys — 调试用 */
export function listRegisteredFilterKeys(): string[] {
  return [...registeredKeys];
}
