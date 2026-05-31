<script setup lang="ts">
/**
 * I08b-α4 Server Registry 页面(方案 §9 / ADR 0005 / 0008)。
 *
 * 3 Tab:
 *   1. Servers      —— 已审批 servers(StoredServerProfile)
 *   2. Pending tools —— 首次 pin 的 tool approval 卡片(approved_at == null)
 *   3. Drift        —— Drifted tools + Drifted servers(pending_command_hash 非空)
 *
 * 点击任何 server 行 → 弹 ServerOnboardingCard(argv / env keys / drift diff)。
 *
 * 安全契约:
 * - argv 逐元素渲染(ServerOnboardingCard 已守)
 * - 所有写操作走 store action(capability=Write 在 Rust 层显式);UI 侧 dialog 二次确认
 * - 轮询 5s + hidden/modal 暂停(复用 α2/α3)
 */
import { onMounted, onUnmounted, ref, computed, h } from "vue";
import {
  NButton,
  NTabs,
  NTabPane,
  NDataTable,
  NEmpty,
  NTag,
  NSpace,
  NAlert,
  NCard,
  NModal,
  NBadge,
  useDialog,
  type DataTableColumns,
} from "naive-ui";
import { useI18n } from "vue-i18n";
import { useServersStore } from "@/stores/servers";
import type { StoredServerProfile, ToolApprovalCard, ServerOnboardingData } from "@/api/ipc";
import ServerOnboardingCard from "@/components/ServerOnboardingCard.vue";

const { t } = useI18n();
const store = useServersStore();
const dialog = useDialog();
const activeTab = ref<"servers" | "pending" | "drift">("servers");

// Modal
const detailOpen = ref(false);
const detailShowDriftActions = ref(false);

// ─────────────────────────── Polling(保留;非完全 event-backed)───────────────────────────
// Codex code review R1:Server Registry **不接** ledger-events-changed 实时刷新 —— pendingTools
// 来自 listPendingToolApprovals,而 first-seen tool descriptor(registry.rs PinOutcome::FirstSeen)
// 直写 tool_descriptors **不 append event**(且生产 auto_approve_first_seen_tools=false),
// MAX(event_id) 锚点不覆盖"新待审工具"。故保留 5s fallback poll(同 PrivacyFindings 决策)。
const POLL_INTERVAL_MS = 5000;
let pollTimer: ReturnType<typeof setInterval> | null = null;

onMounted(() => {
  store.refresh();
  pollTimer = setInterval(() => {
    // modal 打开时暂停 polling,避免用户看卡片时被刷新抢走 detail
    if (!document.hidden && !detailOpen.value) {
      store.refresh();
    }
  }, POLL_INTERVAL_MS);
});
onUnmounted(() => {
  if (pollTimer !== null) clearInterval(pollTimer);
  pollTimer = null;
});

// ─────────────────────────── Formatters ───────────────────────────
function fmtTs(ts: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("zh-CN");
}
function trustTagType(t: StoredServerProfile["trust_level"]): "success" | "default" | "warning" {
  if (t === "Trusted") return "success";
  if (t === "Limited") return "default";
  return "warning"; // Untrusted
}

// ─────────────────────────── Row click → open detail ───────────────────────────

async function openServerDetail(server_id: string, withDriftActions: boolean): Promise<void> {
  detailShowDriftActions.value = withDriftActions;
  detailOpen.value = true;
  await store.loadDetail(server_id);
}

function closeDetail(): void {
  detailOpen.value = false;
  store.clearDetail();
}

// ─────────────────────────── Write action handlers ───────────────────────────

function confirmApproveTool(card: ToolApprovalCard): void {
  dialog.info({
    title: "Approve tool?",
    content: `批准 tool \`${card.tool_name}\`(server \`${card.server_id}\`)。descriptor_hash=${card.current_hash}`,
    positiveText: "Approve",
    negativeText: "Cancel",
    onPositiveClick: async () => {
      await store.approveToolAction({ server_id: card.server_id, tool_name: card.tool_name });
    },
  });
}
function confirmApproveDriftTool(card: ToolApprovalCard): void {
  if (!card.proposed_hash) return;
  const newHash = card.proposed_hash;
  dialog.warning({
    title: "Approve tool drift?",
    content: `认可 tool \`${card.tool_name}\` 的新 descriptor_hash=${newHash}(旧 ${card.current_hash})。`,
    positiveText: "Approve drift",
    negativeText: "Cancel",
    onPositiveClick: async () => {
      await store.approveToolDriftAction({
        server_id: card.server_id,
        tool_name: card.tool_name,
        new_hash: newHash,
      });
    },
  });
}
function confirmRejectDriftTool(card: ToolApprovalCard): void {
  dialog.error({
    title: "Reject tool drift?",
    content: `拒绝 tool \`${card.tool_name}\` 的新 descriptor,恢复为旧 hash=${card.current_hash}。`,
    positiveText: "Reject",
    negativeText: "Cancel",
    onPositiveClick: async () => {
      await store.rejectToolDriftAction({
        server_id: card.server_id,
        tool_name: card.tool_name,
      });
    },
  });
}

async function onApproveServerDrift(server_id: string): Promise<void> {
  await store.approveServerCommandDriftAction({ server_id });
}
async function onRejectServerDrift(server_id: string): Promise<void> {
  await store.rejectServerCommandDriftAction({ server_id });
}

// ─────────────────────────── Table columns ───────────────────────────

const serversColumns: DataTableColumns<StoredServerProfile> = [
  {
    title: "Server",
    key: "server_id",
    render: (row) =>
      h("code", { class: "text-xs font-mono" }, row.server_id),
  },
  {
    title: "Transport",
    key: "transport",
    render: (row) =>
      h(
        NTag,
        { size: "small", type: row.transport === "Stdio" ? "info" : "success" },
        { default: () => row.transport },
      ),
  },
  {
    title: "Trust",
    key: "trust_level",
    render: (row) =>
      h(NTag, { size: "small", type: trustTagType(row.trust_level) }, {
        default: () => row.trust_level,
      }),
  },
  {
    title: "First seen",
    key: "first_seen_at",
    render: (row) => fmtTs(row.first_seen_at),
  },
  {
    title: "Drift",
    key: "pending_command_hash",
    render: (row) =>
      row.pending_command_hash
        ? h(NTag, { size: "small", type: "warning" }, { default: () => "pending" })
        : h("span", { class: "text-gray-500" }, "—"),
  },
  {
    title: "Actions",
    key: "__actions",
    render: (row) =>
      h(
        NButton,
        {
          size: "tiny",
          "data-testid": `server-detail-${row.server_id}`,
          onClick: () => openServerDetail(row.server_id, false),
        },
        { default: () => "Detail" },
      ),
  },
];

// Pending tools 表(approved_at === null 的 ToolApprovalCard)
const pendingColumns: DataTableColumns<ToolApprovalCard> = [
  {
    title: "Server",
    key: "server_id",
    render: (row) => h("code", { class: "text-xs font-mono" }, row.server_id),
  },
  {
    title: "Tool",
    key: "tool_name",
    render: (row) =>
      h("code", { class: "text-xs font-mono font-semibold" }, row.tool_name),
  },
  {
    title: "descriptor_hash",
    key: "current_hash",
    render: (row) =>
      h("code", { class: "text-xs font-mono break-all" }, row.current_hash),
  },
  {
    title: "First seen",
    key: "first_seen_at",
    render: (row) => fmtTs(row.first_seen_at),
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
          "data-testid": `approve-tool-${row.tool_name}`,
          onClick: () => confirmApproveTool(row),
        },
        { default: () => "Approve" },
      ),
  },
];

// Drifted tools 表(proposed_hash 非 null)
const driftedToolsColumns: DataTableColumns<ToolApprovalCard> = [
  {
    title: "Server",
    key: "server_id",
    render: (row) => h("code", { class: "text-xs font-mono" }, row.server_id),
  },
  {
    title: "Tool",
    key: "tool_name",
    render: (row) =>
      h("code", { class: "text-xs font-mono font-semibold" }, row.tool_name),
  },
  {
    title: "Current hash",
    key: "current_hash",
    render: (row) => h("code", { class: "text-xs break-all" }, row.current_hash),
  },
  {
    title: "Proposed hash",
    key: "proposed_hash",
    render: (row) =>
      h(
        "code",
        { class: "text-xs break-all text-yellow-400" },
        row.proposed_hash ?? "—",
      ),
  },
  {
    title: "Last drift",
    key: "last_drift_at",
    render: (row) => fmtTs(row.last_drift_at),
  },
  {
    title: "Actions",
    key: "__actions",
    render: (row) =>
      h(NSpace, { size: "small" }, () => [
        h(
          NButton,
          {
            size: "tiny",
            type: "warning",
            "data-testid": `approve-drift-${row.tool_name}`,
            onClick: () => confirmApproveDriftTool(row),
          },
          { default: () => "Approve" },
        ),
        h(
          NButton,
          {
            size: "tiny",
            type: "error",
            "data-testid": `reject-drift-${row.tool_name}`,
            onClick: () => confirmRejectDriftTool(row),
          },
          { default: () => "Reject" },
        ),
      ]),
  },
];

// Drifted servers 表(ServerOnboardingData,pending_command_hash 非 null)
const driftedServersColumns: DataTableColumns<ServerOnboardingData> = [
  {
    title: "Server",
    key: "server_id",
    render: (row) => h("code", { class: "text-xs font-mono" }, row.server_id),
  },
  {
    title: "Old hash",
    key: "command_hash",
    render: (row) => h("code", { class: "text-xs break-all" }, row.command_hash ?? "—"),
  },
  {
    title: "Pending hash",
    key: "pending_command_hash",
    render: (row) =>
      h(
        "code",
        { class: "text-xs break-all text-yellow-400" },
        row.pending_command_hash ?? "—",
      ),
  },
  {
    title: "First seen",
    key: "first_seen_at",
    render: (row) => fmtTs(row.first_seen_at),
  },
  {
    title: "Actions",
    key: "__actions",
    render: (row) =>
      h(
        NButton,
        {
          size: "tiny",
          "data-testid": `server-drift-detail-${row.server_id}`,
          onClick: () => openServerDetail(row.server_id, true),
        },
        { default: () => "Detail + drift actions" },
      ),
  },
];

const driftCount = computed(() => store.driftedCount);
</script>

<template>
  <div class="p-6 space-y-4">
    <NSpace justify="space-between" align="center">
      <h2 class="text-xl font-semibold text-vigil-text">
        {{ t("server.page_title") }}
        <span class="text-sm font-normal opacity-60 ml-2">
          ({{ t("server.count_summary", {
            approved: store.servers.length,
            pending: store.pendingCount,
            drifted: driftCount,
          }) }})
        </span>
      </h2>
      <NButton
        :loading="store.loading"
        size="small"
        data-testid="refresh-servers"
        @click="store.refresh()"
      >
        {{ t("common.refresh") }}
      </NButton>
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

    <NCard class="bg-vigil-panel border-vigil-border" :bordered="true">
      <NTabs v-model:value="activeTab" type="line" animated>
        <NTabPane name="servers" :tab="t('server.tab_servers')">
          <NDataTable
            :columns="serversColumns"
            :data="store.servers"
            :bordered="false"
            :pagination="{ pageSize: 20 }"
            data-testid="servers-table"
          >
            <template #empty>
              <NEmpty :description="t('server.empty_no_servers')" data-testid="servers-empty">
                <template #extra>
                  <div class="text-xs opacity-60 text-center">
                    {{ t("server.servers_register_cta") }}
                  </div>
                </template>
              </NEmpty>
            </template>
          </NDataTable>
        </NTabPane>

        <NTabPane name="pending">
          <template #tab>
            <NBadge :value="store.pendingCount" :max="99" :show="store.pendingCount > 0">
              {{ t("server.pending_tools_tab") }}
            </NBadge>
          </template>
          <NDataTable
            :columns="pendingColumns"
            :data="store.pendingTools"
            :bordered="false"
            :pagination="{ pageSize: 20 }"
            data-testid="pending-tools-table"
          />
        </NTabPane>

        <NTabPane name="drift">
          <template #tab>
            <NBadge :value="driftCount" :max="99" :show="driftCount > 0" type="warning">
              {{ t("server.tab_drift") }}
            </NBadge>
          </template>
          <NSpace vertical :size="24">
            <div>
              <div class="text-sm opacity-70 mb-2">{{ t("server.drifted_tools_label") }}</div>
              <NDataTable
                :columns="driftedToolsColumns"
                :data="store.driftedTools"
                :bordered="false"
                :pagination="{ pageSize: 10 }"
                data-testid="drifted-tools-table"
              />
            </div>
            <div>
              <div class="text-sm opacity-70 mb-2">{{ t("server.drifted_servers_label") }}</div>
              <NDataTable
                :columns="driftedServersColumns"
                :data="store.driftedServers"
                :bordered="false"
                :pagination="{ pageSize: 10 }"
                data-testid="drifted-servers-table"
              />
            </div>
          </NSpace>
        </NTabPane>
      </NTabs>
    </NCard>

    <NModal
      :show="detailOpen"
      preset="card"
      :title="t('server.onboarding_title')"
      :bordered="false"
      size="huge"
      style="max-width: 800px;"
      @update:show="(v: boolean) => { if (!v) closeDetail(); }"
    >
      <div v-if="store.detailLoading" class="text-gray-500">{{ t("server.onboarding_loading") }}</div>
      <div v-else-if="!store.onboardingDetail" class="text-gray-500">
        {{ t("server.onboarding_no_data") }}
      </div>
      <ServerOnboardingCard
        v-else
        :data="store.onboardingDetail"
        :show-drift-actions="detailShowDriftActions"
        @approve-drift="onApproveServerDrift"
        @reject-drift="onRejectServerDrift"
      />
    </NModal>
  </div>
</template>
