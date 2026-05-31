<script setup lang="ts">
/**
 * I08b-α3 Activity Feed 页面(方案 §9.4 / §14 "看见 agent 做了什么")。
 *
 * - 最近事件流(NTimeline 时间轴)
 * - session / event_type 多选筛选
 * - FTS 搜索切换(searchActive 时显示 hits,否则显示 feed)
 * - 5s polling(tab hidden 暂停,复用 α2 pattern)
 * - 点击 item → 弹 EventDetailModal
 *
 * 安全契约:所有 text 经 `{{ }}` 插值,payload 走 EventDetailModal 的 `<pre>{{ }}`。
 */
import { computed, onMounted, ref } from "vue";
import {
  NButton,
  NCard,
  NSpace,
  NInput,
  NSelect,
  NAlert,
  NTimeline,
  NTimelineItem,
  NEmpty,
  type SelectOption,
} from "naive-ui";
import { useI18n } from "vue-i18n";
import { useEventsStore } from "@/stores/events";
import { useLedgerLiveUpdates } from "@/composables/useLedgerLiveUpdates";
import type { EventSummary } from "@/api/ipc";
import EventDetailModal from "@/components/EventDetailModal.vue";

const { t } = useI18n();
const store = useEventsStore();
const modalOpen = ref(false);

// ─────────────────────── v0.15 Theme G:real-time(替代 5s poll)───────────────────────
// events 表写入即 event-backed → ledger-events-changed listener。搜索模式不刷 feed
// (searchActive 时跳过,延续原 poll 守门);Tauri event 不可用降级 setInterval。
useLedgerLiveUpdates({
  onChange: () => {
    if (!store.searchActive) store.refresh();
  },
});

onMounted(() => {
  store.refresh();
});

// ─────────────────────── Filter options ───────────────────────

/**
 * R1 BLOCKER 修复 + R2 MUST-FIX 修复:白名单严格对齐 workspace Rust 真实
 * `append_event(...)` 写入点的字面量(grep 确认存在且有实际写入处)。来源:
 * - `crates/vigil-audit/src/span.rs`:tool_call.{opened,decided,executed,execute_failed,abandoned}
 * - `crates/vigil-audit/src/approvals.rs`:decision.recorded / approval.{created,resolved,note}
 *   / lease.{minted,revoked}
 * - `crates/vigil-audit/src/registry.rs`:tool_approval.{first_approved,re_approved,drift_rejected}
 *   / server.{command_re_approved,command_drift_rejected}
 * - `crates/vigil-mcp/src/hub.rs`:server.command_drifted
 *
 * **R2 移除**:`runner.rejected` / `runner.killed_by_timeout` / `runner.io_error`
 * 在 workspace 仅作为 `vigil-runner` 错误注释/plan 注释存在,未找到实际
 * `append_event("runner.*")` 写入点。若未来 Hub 接入 runner 事件写入,再补回
 * 这三条(同步本文件 + typeTagType errorExact)。
 *
 * 用户可能有自定义类型(session 里 `append_event` 传任意字符串);UI 筛选仅列常用。
 */
const EVENT_TYPE_OPTIONS: SelectOption[] = [
  // tool_call.* (vigil-audit/src/span.rs)
  { label: "tool_call.opened", value: "tool_call.opened" },
  { label: "tool_call.decided", value: "tool_call.decided" },
  { label: "tool_call.executed", value: "tool_call.executed" },
  { label: "tool_call.execute_failed", value: "tool_call.execute_failed" },
  { label: "tool_call.abandoned", value: "tool_call.abandoned" },
  // decision / approval / lease (vigil-audit/src/approvals.rs)
  { label: "decision.recorded", value: "decision.recorded" },
  { label: "approval.created", value: "approval.created" },
  { label: "approval.resolved", value: "approval.resolved" },
  { label: "approval.note", value: "approval.note" },
  { label: "lease.minted", value: "lease.minted" },
  { label: "lease.revoked", value: "lease.revoked" },
  // tool_approval / server (vigil-audit/src/registry.rs + vigil-mcp/src/hub.rs)
  { label: "tool_approval.first_approved", value: "tool_approval.first_approved" },
  { label: "tool_approval.re_approved", value: "tool_approval.re_approved" },
  { label: "tool_approval.drift_rejected", value: "tool_approval.drift_rejected" },
  { label: "server.command_drifted", value: "server.command_drifted" },
  { label: "server.command_re_approved", value: "server.command_re_approved" },
  { label: "server.command_drift_rejected", value: "server.command_drift_rejected" },
];

// ─────────────────────── Formatters ───────────────────────

function fmtTs(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("zh-CN");
}

/**
 * 事件类型 tag 颜色启发式。
 *
 * R1 MUST-FIX 2 修复 + R2 移除 runner.*:扩展 error 类型命中清单 —— 失败/拒绝/漂移事件
 * 是用户最需醒目看到的风险信号,不能默认色稀释。命中集合(与 Rust 真实事件名对齐):
 *   - tool_call.execute_failed
 *   - tool_call.abandoned
 *   - server.command_drifted / command_drift_rejected
 *   - tool_approval.drift_rejected
 *   - 任何 `*.denied` / `*.failed` / `*.timeout` / `*.drift_rejected` 后缀(含 runner
 *     若未来接入时通过 `.io_error` / `.rejected` 后缀兜底命中)
 */
function typeTagType(
  eventType: string,
): "default" | "info" | "success" | "warning" | "error" {
  // 高优先级 — error(失败 / 拒绝 / 超时 / 漂移拒绝)
  const errorExact = [
    "tool_call.execute_failed",
    "tool_call.abandoned",
    "server.command_drifted",
    "server.command_drift_rejected",
    "tool_approval.drift_rejected",
  ];
  if (errorExact.includes(eventType)) return "error";
  if (
    eventType.endsWith(".denied") ||
    eventType.endsWith(".failed") ||
    eventType.endsWith(".timeout") ||
    eventType.endsWith(".drift_rejected") ||
    eventType.endsWith(".execute_failed") ||
    eventType.endsWith(".io_error") ||
    eventType.endsWith(".rejected") ||
    eventType.endsWith(".killed_by_timeout")
  ) {
    return "error";
  }
  // warning — approval / re-approved / command drift(非 rejected)
  if (eventType.startsWith("approval.")) return "warning";
  if (eventType === "tool_approval.re_approved") return "warning";
  if (eventType === "server.command_re_approved") return "warning";
  // info — lease / decision(中性记录)
  if (eventType.startsWith("lease.")) return "info";
  if (eventType === "decision.recorded") return "info";
  // success — 正常完成 / 首次批准
  if (eventType === "tool_call.executed") return "success";
  if (eventType === "tool_approval.first_approved") return "success";
  return "default";
}

// ─────────────────────── Feed view ───────────────────────

/** 当前展示的事件列表:searchActive 时是搜索结果,否则是 feed */
const currentList = computed<EventSummary[]>(() =>
  store.searchActive ? store.searchHits : store.events,
);

function handleItemClick(row: EventSummary): void {
  store.loadDetail(row.event_id);
  modalOpen.value = true;
}

// ─────────────────────── Search ───────────────────────
const searchInput = ref<string>("");

async function onSearchSubmit(): Promise<void> {
  await store.search(searchInput.value);
}

function onSearchClear(): void {
  searchInput.value = "";
  store.clearSearch();
  store.refresh(); // 回到 feed
}

// ─────────────────────── Filter handlers ───────────────────────
function onSessionFilterBlur(): void {
  // N-input onBlur 时触发 refresh
  store.refresh();
}
function onTypeFilterUpdate(v: string[]): void {
  store.setTypeFilters(v);
  store.refresh();
}

// v0.14 Theme F:计算是否有非默认 filter,用于显示 reset 按钮
const hasActiveFilter = computed(() =>
  store.sessionFilter !== null || store.typeFilters.length > 0,
);

function onResetFilters(): void {
  store.resetFilters();
  store.refresh();
}
</script>

<template>
  <div class="p-6 space-y-4">
    <NSpace justify="space-between" align="center">
      <h2 class="text-xl font-semibold text-vigil-text">
        {{ t("activity.page_title") }}
        <span class="text-sm font-normal opacity-60 ml-2">
          ({{ store.searchActive
            ? t("activity.count_search", { count: store.count })
            : t("activity.count_live", { count: store.count }) }})
        </span>
      </h2>
      <NButton
        :loading="store.loading"
        size="small"
        data-testid="refresh-feed"
        @click="store.refresh()"
      >
        {{ t("common.refresh") }}
      </NButton>
    </NSpace>

    <!-- Search bar -->
    <NCard size="small" class="bg-vigil-panel border-vigil-border">
      <NSpace align="center">
        <!-- v0.14 Theme B:data-shortcut="search" 让 `/` 全局快捷键 focus 本框
             外层 div 标记(NInput input-props 类型受限,wrapper 更稳)-->
        <div data-shortcut-wrapper="search">
          <NInput
            v-model:value="searchInput"
            :placeholder="t('activity.search_placeholder')"
            clearable
            style="width: 420px;"
            data-testid="fts-input"
            @keydown.enter="onSearchSubmit"
          />
        </div>
        <NButton
          :loading="store.searchLoading"
          type="primary"
          data-testid="fts-search-btn"
          @click="onSearchSubmit"
        >
          {{ t("activity.search_button") }}
        </NButton>
        <NButton
          v-if="store.searchActive"
          size="small"
          data-testid="fts-clear-btn"
          @click="onSearchClear"
        >
          {{ t("activity.back_to_feed") }}
        </NButton>
      </NSpace>
      <div v-if="store.searchError" class="text-red-400 mt-2 text-sm" data-testid="fts-error">
        {{ t("activity.search_error", { msg: store.searchError }) }}
      </div>
    </NCard>

    <!-- Filters(仅 feed 模式)-->
    <NCard v-if="!store.searchActive" size="small" class="bg-vigil-panel border-vigil-border">
      <NSpace>
        <NInput
          :value="store.sessionFilter ?? ''"
          :placeholder="t('activity.session_filter_placeholder')"
          clearable
          style="width: 320px;"
          data-testid="session-filter"
          @update:value="(v: string) => store.setSessionFilter(v)"
          @blur="onSessionFilterBlur"
        />
        <NSelect
          :value="store.typeFilters"
          multiple
          clearable
          :options="EVENT_TYPE_OPTIONS"
          :placeholder="t('activity.type_filter_placeholder')"
          style="width: 420px;"
          data-testid="type-filter"
          @update:value="onTypeFilterUpdate"
        />
        <!-- v0.14 Theme F:显式 reset(只显示在有非默认 filter 时,减少视觉噪声)-->
        <NButton
          v-if="hasActiveFilter"
          size="small"
          quaternary
          data-testid="reset-feed-filters"
          @click="onResetFilters"
        >
          {{ t("activity.reset_filters") }}
        </NButton>
      </NSpace>
    </NCard>

    <NAlert
      v-if="store.error"
      type="error"
      :title="t('common.ipc_error')"
      closable
      @close="store.error = null"
    >
      {{ store.error }}
    </NAlert>

    <!-- Timeline -->
    <NCard class="bg-vigil-panel border-vigil-border" :bordered="true">
      <!-- v0.14 Theme A:升级 empty state 用 NEmpty + contextual CTA copy -->
      <NEmpty
        v-if="currentList.length === 0 && !store.loading"
        :description="store.searchActive
          ? t('activity.empty_no_hits')
          : t('activity.empty_no_events')"
        data-testid="activity-empty"
        class="py-8"
      >
        <template #extra>
          <div class="text-xs opacity-60 text-center">
            {{
              store.searchActive
                ? t("activity.empty_hits_extra")
                : t("activity.empty_events_extra")
            }}
          </div>
        </template>
      </NEmpty>
      <NTimeline v-else>
        <NTimelineItem
          v-for="ev in currentList"
          :key="ev.event_id"
          :type="typeTagType(ev.event_type)"
          :title="ev.event_type"
          :time="fmtTs(ev.created_at)"
          data-testid="event-item"
          style="cursor: pointer;"
          @click="handleItemClick(ev)"
        >
          <div class="text-sm opacity-70">
            <span class="font-mono">{{ ev.session_id }}</span>
            <span class="mx-2">·</span>
            <span class="font-mono">event_id={{ ev.event_id }}</span>
          </div>
          <div
            v-if="ev.redacted_text"
            class="text-sm mt-1 text-vigil-text whitespace-pre-wrap break-all"
          >
            {{ ev.redacted_text }}
          </div>
        </NTimelineItem>
      </NTimeline>
    </NCard>

    <EventDetailModal
      v-model:show="modalOpen"
      :detail="store.detail"
      :loading="store.detailLoading"
    />
  </div>
</template>
