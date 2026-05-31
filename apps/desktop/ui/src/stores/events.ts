/**
 * I08b-α3 Activity Feed Pinia store。
 *
 * 职责:
 * - 维护最近事件流(list_recent_events + session/type 过滤 + limit)
 * - 管理 FTS 搜索态(query + 结果)
 * - 单条事件 detail(get_event_detail)
 * - polling 刷新(α2 相同模式:5s + hidden 暂停)
 *
 * 安全契约:payload 经 vigil-audit 写入时已脱敏,UI 只做展示不做 drill-into。
 */
import { defineStore } from "pinia";
import { ref, computed } from "vue";
import {
  listRecentEvents,
  getEventDetail,
  ftsSearch,
  type EventSummary,
  type EventDetail,
  type EventHit,
} from "@/api/ipc";
import { persistedRef, clearPersistedFilters } from "@/utils/persistedRef";

const DEFAULT_LIMIT = 100;
const FTS_LIMIT = 50;

// v0.14 Theme F:持久化 filter keys(也用于 reset)
const EVENTS_FILTER_KEYS = [
  "events:sessionFilter",
  "events:typeFilters",
  "events:limit",
] as const;

export const useEventsStore = defineStore("events", () => {
  // --- Feed state ---
  const events = ref<EventSummary[]>([]);
  // v0.14 Theme F:三个 filter 持久化到 localStorage(reload 后恢复)
  const sessionFilter = persistedRef<string | null>("events:sessionFilter", null);
  const typeFilters = persistedRef<string[]>("events:typeFilters", []);
  const limit = persistedRef<number>("events:limit", DEFAULT_LIMIT);
  const loading = ref(false);
  const error = ref<string | null>(null);
  const lastRefreshedAt = ref<number | null>(null);

  // --- Detail state ---
  const detail = ref<EventDetail | null>(null);
  const detailLoading = ref(false);

  // --- Search state ---
  const searchQuery = ref<string>("");
  const searchHits = ref<EventHit[]>([]);
  const searchLoading = ref(false);
  const searchError = ref<string | null>(null);
  const searchActive = computed(() => searchQuery.value.trim().length > 0);

  // --- Getters ---
  const count = computed(() => events.value.length);

  // --- Actions ---

  async function refresh(): Promise<void> {
    loading.value = true;
    error.value = null;
    try {
      events.value = await listRecentEvents({
        session_id: sessionFilter.value,
        event_type_filter: typeFilters.value.length > 0 ? typeFilters.value : null,
        limit: limit.value,
      });
      lastRefreshedAt.value = Date.now();
    } catch (e) {
      error.value = String(e);
    } finally {
      loading.value = false;
    }
  }

  async function loadDetail(event_id: number): Promise<void> {
    detailLoading.value = true;
    error.value = null;
    try {
      detail.value = await getEventDetail({ event_id });
    } catch (e) {
      error.value = String(e);
      detail.value = null;
    } finally {
      detailLoading.value = false;
    }
  }

  function clearDetail(): void {
    detail.value = null;
  }

  /**
   * FTS5 搜索。`query` 传给 SQLite MATCH 语法 — 前端**不转义**(让用户用 AND / OR / * 前缀)。
   * 空字符串视为清空搜索。
   *
   * R1 MUST-FIX 3 修复:FTS 错误不再透传后端原文,而是包装为用户可理解的提示 +
   * 附原文作为附注(便于排错)。SQLite 常见错误:
   *   - 裸符号作 token(`:` / `&` / `-` 等)→ "syntax error" / "no such table"
   *   - 未配对引号 / 括号 → "fts5: ..."
   */
  async function search(query: string): Promise<void> {
    const trimmed = query.trim();
    searchQuery.value = trimmed;
    if (trimmed === "") {
      searchHits.value = [];
      searchError.value = null;
      return;
    }
    searchLoading.value = true;
    searchError.value = null;
    try {
      searchHits.value = await ftsSearch({ query: trimmed, limit: FTS_LIMIT });
    } catch (e) {
      searchError.value = friendlyFtsError(String(e));
      searchHits.value = [];
    } finally {
      searchLoading.value = false;
    }
  }

  /**
   * 把 SQLite FTS5 原始错误信息包装为用户可读提示。
   *
   * 保留原文放 `[详情]` 段,便于开发排错;首行是用户友好提示。
   */
  function friendlyFtsError(raw: string): string {
    const hints: string[] = [];
    const lower = raw.toLowerCase();
    if (lower.includes("syntax") || lower.includes("fts5")) {
      hints.push(
        "查询语法无效 — 建议:① 整词用双引号包住(如 `\"access token\"`);② 用 AND / OR 连接多个词;③ 前缀匹配加 `*`(如 `auth*`);④ 避免裸符号 `:` `-` `&`。",
      );
    } else if (lower.includes("no such table")) {
      hints.push("FTS 索引尚未就绪 — 若刚启动 ledger,请稍后重试或先触发 1 条事件。");
    } else if (hints.length === 0) {
      hints.push("搜索失败 — 请检查查询语法或联系管理员。");
    }
    return `${hints.join(" ")}  [详情] ${raw}`;
  }

  function clearSearch(): void {
    searchQuery.value = "";
    searchHits.value = [];
    searchError.value = null;
  }

  // --- Filters mutators(保留显式 API,避免组件直接 mutate ref)---
  function setSessionFilter(v: string | null): void {
    sessionFilter.value = v && v.trim() !== "" ? v.trim() : null;
  }
  function setTypeFilters(v: string[]): void {
    typeFilters.value = v;
  }
  function setLimit(v: number): void {
    limit.value = v > 0 ? v : DEFAULT_LIMIT;
  }

  /** v0.14 Theme F:reset 三个 filter 到默认 + 清空 localStorage 持久化值 */
  function resetFilters(): void {
    sessionFilter.value = null;
    typeFilters.value = [];
    limit.value = DEFAULT_LIMIT;
    clearPersistedFilters(EVENTS_FILTER_KEYS);
  }

  return {
    // Feed
    events,
    sessionFilter,
    typeFilters,
    limit,
    loading,
    error,
    lastRefreshedAt,
    count,
    // Detail
    detail,
    detailLoading,
    // Search
    searchQuery,
    searchHits,
    searchLoading,
    searchError,
    searchActive,
    // Actions
    refresh,
    loadDetail,
    clearDetail,
    search,
    clearSearch,
    setSessionFilter,
    setTypeFilters,
    setLimit,
    resetFilters,
  };
});
