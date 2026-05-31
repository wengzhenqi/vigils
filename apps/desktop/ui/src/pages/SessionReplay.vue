<script setup lang="ts">
/**
 * I08b-α5 Session Replay 页面(方案 §9 / ADR 0002 hash chain)。
 *
 * 布局:
 *   左:session 列表(risk_score 排序 + 过滤)
 *   右:选中 session 的完整事件流(时间顺序 + 每条 payload 可展开)+ chain verify badge
 *
 * 安全契约:
 * - replay events payload 走 `<pre>{{ JSON.stringify }}`(Vue 插值转义 XSS)
 * - ChainVerifyReport.message 经后端脱敏,可直接插值
 * - **hash chain 是 ledger 级语义**:UI 明示 "ledger-wide chain verify"
 *
 * 不做:
 * - verify_chain 失败后的自动修复(设计上 ledger 不变,仅提示 `chain_broken_at`)
 * - 多 session 对比(仅单 session 重放 MVP)
 */
import { computed, h, onMounted, ref } from "vue";
import {
  NButton,
  NCard,
  NSpace,
  NInput,
  NAlert,
  NTag,
  NTimeline,
  NTimelineItem,
  NDataTable,
  NEmpty,
  NCheckbox,
  NDescriptions,
  NDescriptionsItem,
  type DataTableColumns,
} from "naive-ui";
import { useI18n } from "vue-i18n";
import { useSessionsStore } from "@/stores/sessions";
import { persistedRef, clearPersistedFilters } from "@/utils/persistedRef";
import { useLedgerLiveUpdates } from "@/composables/useLedgerLiveUpdates";
import {
  exportSessionReplay,
  type EventDetail,
  type ExportFormat,
  type SessionView,
} from "@/api/ipc";

const { t } = useI18n();
const store = useSessionsStore();

// ─────────────────────────── UI state ───────────────────────────

// v0.14 Theme F:filter 持久化(reload 后恢复)
const sourceFilter = persistedRef<string>("sessions:sourceFilter", "");
const verifyOnReplay = ref<boolean>(true);

/** v0.14 Theme F:reset source filter + 重新拉列表 */
function resetSessionFilters(): void {
  sourceFilter.value = "";
  clearPersistedFilters(["sessions:sourceFilter"]);
  store.refreshList({ source: null, limit: 100 });
}

// 展开的事件 id(同时只展开一条,减少 DOM 压力)
const expandedEventId = ref<number | null>(null);

// ─────────────────────────── ISS-018 Safe Export 状态 ───────────────────────────

const exportingFormat = ref<ExportFormat | null>(null);
const exportError = ref<string | null>(null);

/** ISS-018 — 把 SessionExportDto 触发浏览器下载。
 *  Tauri 进程不直接写文件(避免提权 FS write);走 Blob + `<a download>`,
 *  保留浏览器原生 OS 保存对话框。 */
async function safeExport(format: ExportFormat) {
  if (!store.selectedSessionId) return;
  exportingFormat.value = format;
  exportError.value = null;
  try {
    const dto = await exportSessionReplay({
      session_id: store.selectedSessionId,
      format,
    });
    const blob = new Blob([dto.content], {
      type: format === "md" ? "text/markdown;charset=utf-8" : "text/html;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    try {
      const a = document.createElement("a");
      // 文件名同时含 session 与时戳,便于用户区分多次导出
      a.href = url;
      a.download = `vigil-${dto.session_id}-${dto.generated_at}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } finally {
      URL.revokeObjectURL(url);
    }
  } catch (e) {
    exportError.value = String(e);
  } finally {
    exportingFormat.value = null;
  }
}

// ─────────────────── v0.15 Theme G:real-time 列表刷新(替代 5s poll)───────────────────
// 新 session 的首条 event 即 event-backed → ledger-events-changed listener 刷列表。
// replay 加载中不刷(避免列表抖动);Tauri event 不可用降级 setInterval。
// 注(spike § 3.2.1):零事件 session 在首 event 前不会触发刷新,可接受(无重放价值)。
useLedgerLiveUpdates({
  onChange: () => {
    if (!store.replayLoading) {
      store.refreshList({ source: sourceFilter.value || null, limit: 100 });
    }
  },
});

onMounted(() => {
  store.refreshList({ source: sourceFilter.value || null, limit: 100 });
});

// ─────────────────────────── Handlers ───────────────────────────

async function onPickSession(s: SessionView): Promise<void> {
  expandedEventId.value = null;
  await store.loadReplay({ session_id: s.session_id, verify: verifyOnReplay.value });
}

function onSourceFilterBlur(): void {
  store.refreshList({ source: sourceFilter.value || null, limit: 100 });
}

function toggleEvent(ev: EventDetail): void {
  expandedEventId.value = expandedEventId.value === ev.event_id ? null : ev.event_id;
}

function payloadPretty(ev: EventDetail): string {
  if (ev.payload === null || ev.payload === undefined) return "";
  try {
    return JSON.stringify(ev.payload, null, 2);
  } catch {
    return String(ev.payload);
  }
}

// ─────────────────────────── Formatters ───────────────────────────

function fmtTs(ts: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("zh-CN");
}

function riskTagType(score: number): "default" | "warning" | "error" {
  if (score >= 70) return "error";
  if (score >= 30) return "warning";
  return "default";
}

// ─────────────────────────── Session table ───────────────────────────

const sessionsColumns: DataTableColumns<SessionView> = [
  {
    title: "Session",
    key: "session_id",
    render: (row) => h("code", { class: "text-xs font-mono" }, row.session_id),
  },
  {
    title: "Source",
    key: "source",
    render: (row) => h(NTag, { size: "small" }, { default: () => row.source }),
  },
  {
    title: "App",
    key: "app_name",
    render: (row) => row.app_name ?? "—",
  },
  {
    title: "Started",
    key: "started_at",
    render: (row) => fmtTs(row.started_at),
  },
  {
    title: "Ended",
    key: "ended_at",
    render: (row) => (row.ended_at ? fmtTs(row.ended_at) : h(NTag, { size: "tiny", type: "info" }, { default: () => "live" })),
  },
  {
    title: "Risk",
    key: "risk_score",
    render: (row) =>
      h(NTag, { size: "small", type: riskTagType(row.risk_score) }, { default: () => String(row.risk_score) }),
  },
  {
    title: "Action",
    key: "__actions",
    render: (row) =>
      h(
        NButton,
        {
          size: "tiny",
          type: "primary",
          "data-testid": `replay-${row.session_id}`,
          loading: store.replayLoading && store.selectedSessionId === row.session_id,
          onClick: () => onPickSession(row),
        },
        { default: () => "Replay" },
      ),
  },
];

// ─────────────────────────── Chain verify badge ───────────────────────────

/**
 * Chain verify badge 文案计算。
 *
 * R1 MUST-FIX(Codex):**所有状态都必须明示 "ledger-wide"** —— 不能仅在 OK 分支
 * 出现 "ledger-wide"、broken 分支只显示 `chain_broken_at=N`。否则用户会误读为
 * "本 session 子链坏"而不是"整个 ledger 全局链坏"。
 */
const chainBadge = computed<{
  text: string;
  type: "success" | "error" | "default";
  detail: string;
}>(() => {
  const v = store.replay?.chain_verified;
  if (!v) {
    return {
      text: "chain not verified",
      type: "default",
      detail: "replay invoked with verify=false — ledger-wide chain not checked",
    };
  }
  if (v.ok) {
    return {
      text: "ledger-wide chain OK",
      type: "success",
      detail: "ledger-wide hash chain verified",
    };
  }
  const reason = v.message ?? "chain_verify_failed";
  return {
    text: "ledger-wide chain BROKEN",
    type: "error",
    detail: `ledger-wide hash chain broken — ${reason}`,
  };
});

async function onStandaloneVerify(): Promise<void> {
  await store.runStandaloneVerify();
}
</script>

<template>
  <div class="p-6 space-y-4">
    <NSpace justify="space-between" align="center">
      <h2 class="text-xl font-semibold text-vigil-text">
        {{ t("session.page_title") }}
        <span class="text-sm font-normal opacity-60 ml-2">
          ({{ store.sessions.length }} sessions)
        </span>
      </h2>
      <NSpace>
        <NButton
          :loading="store.verifyLoading"
          size="small"
          data-testid="verify-chain-standalone"
          @click="onStandaloneVerify"
        >
          {{ t("session.verify_chain_button") }}
        </NButton>
        <NButton
          :loading="store.listLoading"
          size="small"
          data-testid="refresh-sessions"
          @click="store.refreshList({ source: sourceFilter || null, limit: 100 })"
        >
          {{ t("common.refresh") }}
        </NButton>
      </NSpace>
    </NSpace>

    <NAlert
      v-if="store.error"
      type="error"
      :title="t('common.ipc_error')"
      closable
      @close="store.error = null"
    >
      {{ store.error }}
    </NAlert>

    <!-- standalone verify 结果(按钮触发时展示) -->
    <NAlert
      v-if="store.standaloneVerify"
      :type="store.standaloneVerify.ok ? 'success' : 'error'"
      :title="store.standaloneVerify.ok ? t('session.chain_ok') : t('session.chain_broken')"
      closable
      @close="store.standaloneVerify = null"
    >
      <template v-if="!store.standaloneVerify.ok">
        <div>{{ store.standaloneVerify.message ?? t("session.chain_verify_failed") }}</div>
        <div v-if="store.standaloneVerify.broken_at_event_id" class="text-xs mt-1">
          {{ t("session.first_broken_event", { id: store.standaloneVerify.broken_at_event_id }) }}
        </div>
      </template>
    </NAlert>

    <!-- 过滤 + verify 开关 -->
    <NCard size="small" class="bg-vigil-panel border-vigil-border">
      <NSpace align="center">
        <NInput
          v-model:value="sourceFilter"
          :placeholder="t('session.source_filter_placeholder')"
          clearable
          style="width: 320px;"
          data-testid="source-filter"
          @blur="onSourceFilterBlur"
        />
        <NCheckbox v-model:checked="verifyOnReplay" data-testid="verify-on-replay">
          {{ t("session.verify_on_replay") }}
        </NCheckbox>
        <!-- v0.14 Theme F:显式 reset(只显示在有 filter 时,减少视觉噪声)-->
        <NButton
          v-if="sourceFilter"
          size="small"
          quaternary
          data-testid="reset-session-filters"
          @click="resetSessionFilters"
        >
          {{ t("session.reset_filters") }}
        </NButton>
      </NSpace>
    </NCard>

    <!-- Sessions 列表 -->
    <NCard :title="t('session.sessions_card_title')" size="small" class="bg-vigil-panel border-vigil-border">
      <NDataTable
        :columns="sessionsColumns"
        :data="store.sessions"
        :bordered="false"
        :pagination="{ pageSize: 15 }"
        data-testid="sessions-table"
      >
        <template #empty>
          <NEmpty :description="t('session.empty_no_sessions')" data-testid="sessions-empty">
            <template #extra>
              <div class="text-xs opacity-60 text-center">
                {{ t("session.empty_sessions_extra") }}
              </div>
            </template>
          </NEmpty>
        </template>
      </NDataTable>
    </NCard>

    <!-- Replay 结果 -->
    <NCard
      v-if="store.selectedSessionId || store.replayLoading"
      size="small"
      class="bg-vigil-panel border-vigil-border"
    >
      <template #header>
        <NSpace align="center">
          <span>Replay: <code class="text-xs font-mono">{{ store.selectedSessionId }}</code></span>
          <NTag :type="chainBadge.type" size="small" data-testid="chain-badge">
            {{ chainBadge.text }}
          </NTag>
          <span class="text-xs opacity-60">{{ chainBadge.detail }}</span>
        </NSpace>
      </template>
      <template #header-extra>
        <NSpace size="small">
          <!-- ISS-018 Safe Export buttons:payload 已脱敏 + Blob download(无 FS write 提权) -->
          <NButton
            size="tiny"
            :loading="exportingFormat === 'md'"
            :disabled="exportingFormat !== null"
            data-testid="safe-export-md"
            :title="t('session.export_md')"
            @click="safeExport('md')"
          >
            {{ t("session.export_md") }}
          </NButton>
          <NButton
            size="tiny"
            :loading="exportingFormat === 'html'"
            :disabled="exportingFormat !== null"
            data-testid="safe-export-html"
            :title="t('session.export_html')"
            @click="safeExport('html')"
          >
            {{ t("session.export_html") }}
          </NButton>
          <NButton size="tiny" @click="store.clearReplay()">{{ t("common.close") }}</NButton>
        </NSpace>
      </template>

      <NAlert
        v-if="exportError"
        type="error"
        class="mb-3"
        closable
        :title="t('session.export_error', { msg: exportError })"
        @close="exportError = null"
      />
      <div v-if="store.replayLoading" class="text-gray-500 p-4">{{ t("session.replay_loading") }}</div>
      <div
        v-else-if="!store.replay || store.replay.events.length === 0"
        class="text-gray-500 p-4 text-center"
      >
        {{ t("session.replay_no_events") }}
      </div>
      <template v-else>
        <NDescriptions label-placement="left" :column="3" size="small" class="mb-3">
          <NDescriptionsItem label="Event count">
            {{ store.replay.event_count }}
          </NDescriptionsItem>
          <NDescriptionsItem label="Ledger-wide chain">
            <!-- R1 MUST-FIX:broken 态文案也明示 "ledger-wide",避免被读作本 session 子链 -->
            <template v-if="!store.replay.chain_verified">
              — (verify=false, ledger chain not checked)
            </template>
            <template v-else-if="store.replay.chain_verified.ok">
              ✓ ledger-wide OK
            </template>
            <template v-else>
              ✗ ledger-wide BROKEN
            </template>
          </NDescriptionsItem>
          <NDescriptionsItem v-if="store.replay.chain_verified?.broken_at_event_id" label="Broken at (ledger-wide)">
            event_id = {{ store.replay.chain_verified.broken_at_event_id }}
          </NDescriptionsItem>
        </NDescriptions>

        <NTimeline>
          <NTimelineItem
            v-for="ev in store.replay.events"
            :key="ev.event_id"
            :title="ev.event_type"
            :time="fmtTs(ev.created_at)"
            data-testid="replay-event"
          >
            <div class="text-sm">
              <div class="opacity-70">
                <span class="font-mono">event_id={{ ev.event_id }}</span>
                <span class="mx-2">·</span>
                <span class="font-mono break-all">event_hash={{ ev.event_hash.slice(0, 12) }}…</span>
              </div>
              <div
                v-if="ev.redacted_text"
                class="mt-1 text-vigil-text whitespace-pre-wrap break-all"
              >
                {{ ev.redacted_text }}
              </div>
              <NButton
                size="tiny"
                text
                class="mt-1"
                :data-testid="`toggle-${ev.event_id}`"
                @click="toggleEvent(ev)"
              >
                {{ expandedEventId === ev.event_id ? "Hide payload" : "Show payload" }}
              </NButton>
              <div v-if="expandedEventId === ev.event_id" class="mt-2">
                <div class="text-xs opacity-60 mb-1">
                  prev_hash: <code class="break-all">{{ ev.prev_hash }}</code>
                </div>
                <pre
                  class="text-xs whitespace-pre-wrap break-all max-h-[20rem] overflow-auto font-mono bg-vigil-bg p-3 rounded border border-vigil-border"
                  :data-testid="`payload-${ev.event_id}`"
                >{{ payloadPretty(ev) }}</pre>
              </div>
            </div>
          </NTimelineItem>
        </NTimeline>
      </template>
    </NCard>
  </div>
</template>
