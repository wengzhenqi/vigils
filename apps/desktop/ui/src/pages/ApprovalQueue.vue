<script setup lang="ts">
/**
 * I08b-α2 Approval Queue 页面(R1 BLOCKER 修订版)。
 *
 * **R1 修订关键**:
 * - Approve 路径必须带 `scope` (Once / ThisSession);UI 打开 ApproveScopeDialog 让用户选
 * - status 对比严格 PascalCase("Pending" / ...)
 * - action 参数 lowercase("approve" / "deny" / "cancel",与 Rust serde 对齐)
 */
import { computed, h, onMounted, onUnmounted, ref, watch } from "vue";
import {
  NButton,
  NCard,
  NDataTable,
  NSpace,
  NTag,
  NAlert,
  NEmpty,
  NModal,
  NRadio,
  NRadioGroup,
  useDialog,
  type DataTableColumns,
  type DataTableRowKey,
} from "naive-ui";
import { useI18n } from "vue-i18n";
import { useApprovalsStore } from "@/stores/approvals";
import type { ApprovalSummary, ApprovalAction, ApprovalScope } from "@/api/ipc";
import ApprovalDetailDrawer from "@/components/ApprovalDetailDrawer.vue";
import { isEditingTarget } from "@/composables/useGlobalShortcuts";
import { useLedgerLiveUpdates } from "@/composables/useLedgerLiveUpdates";

const { t } = useI18n();
const store = useApprovalsStore();
const dialog = useDialog();

const drawerOpen = ref(false);

// ─────────────────────── v0.14 Theme B+:page-level row navigation ───────────────────────
//
// selectedIndex 指向 store.approvals 内的 index(-1 = 未选)。
// j/k 移动,Enter 打开 drawer,a/d/c 触发 approve/deny/cancel(对选中行)。
// 当 modal 或 dialog 打开时,这些快捷键不应再触发(避免重叠 confirm flow)。
const selectedIndex = ref<number>(-1);

const selectedApproval = computed<ApprovalSummary | null>(() => {
  const idx = selectedIndex.value;
  if (idx < 0 || idx >= store.approvals.length) return null;
  return store.approvals[idx];
});

// 列表变化(refresh 后)若 selectedIndex 越界,clamp 到 0(若有数据)或 -1
function clampSelectedIndex(): void {
  const n = store.approvals.length;
  if (n === 0) selectedIndex.value = -1;
  else if (selectedIndex.value >= n) selectedIndex.value = n - 1;
  else if (selectedIndex.value < 0) selectedIndex.value = 0;
}

function moveSelection(delta: number): void {
  const n = store.approvals.length;
  if (n === 0) {
    selectedIndex.value = -1;
    return;
  }
  if (selectedIndex.value < 0) {
    selectedIndex.value = delta > 0 ? 0 : n - 1;
    return;
  }
  // 边界不 wrap(避免 power user 误以为按 j 到底会跳头)
  const next = selectedIndex.value + delta;
  selectedIndex.value = Math.max(0, Math.min(n - 1, next));
}

// ─────────────────────── Approve scope modal(单条 + 批量复用)───────────────────────
//
// v0.14 Theme E:同一 modal 同时承载单条 approve 和 bulk approve;
// `approveModalMode` 区分两种路径,bulk 模式忽略 approvalId 改用 checkedRowKeys。
type ApproveMode = "single" | "bulk";
const approveModalOpen = ref(false);
const approveModalMode = ref<ApproveMode>("single");
const approveModalApprovalId = ref<string | null>(null);
const approveScope = ref<ApprovalScope>("Once");

function openApproveModal(approval_id: string): void {
  approveModalMode.value = "single";
  approveModalApprovalId.value = approval_id;
  approveScope.value = "Once";
  approveModalOpen.value = true;
}

async function confirmApproveWithScope(): Promise<void> {
  approveModalOpen.value = false;
  if (approveModalMode.value === "bulk") {
    confirmBulkApprove();
    return;
  }
  const id = approveModalApprovalId.value;
  if (!id) return;
  // 二次确认(scope 已由 modal 收集)
  dialog.warning({
    title: t("approval.confirm_approve_title"),
    content: t("approval.confirm_approve_content", { id, scope: approveScope.value }),
    positiveText: t("common.approve"),
    negativeText: t("common.rethink"),
    onPositiveClick: async () => {
      await store.resolve(id, "approve", { scope: approveScope.value });
      if (!store.hasError) {
        drawerOpen.value = false;
      }
    },
  });
}

// ─────────────────────── Deny / Cancel 二次确认 ───────────────────────
function confirmDenyOrCancel(approvalId: string, action: Exclude<ApprovalAction, "approve">): void {
  const title = action === "deny"
    ? t("approval.confirm_deny_title")
    : t("approval.confirm_cancel_title");
  const positiveText = action === "deny" ? t("common.deny") : t("common.cancel");
  dialog.warning({
    title,
    content: t("approval.confirm_deny_content", { id: approvalId }),
    positiveText,
    negativeText: t("common.rethink"),
    onPositiveClick: async () => {
      await store.resolve(approvalId, action);
      if (!store.hasError) {
        drawerOpen.value = false;
      }
    },
  });
}

// ─────────────────────── v0.15 Theme G:real-time(替代 α2 5s poll)───────────────────────
// approval.created / approval.resolved 均 event-backed → 走 ledger-events-changed listener。
// Tauri event 不可用时 composable 内自动降级 setInterval(5s)。
useLedgerLiveUpdates({ onChange: () => store.refresh() });

onMounted(() => {
  store.refresh();
  window.addEventListener("keydown", onPageKeyDown);
});

onUnmounted(() => {
  window.removeEventListener("keydown", onPageKeyDown);
});

// v0.14 Theme B+:页面级 keydown handler。
// 守门:input/textarea/contenteditable 内禁用 + modifier 不接管 + modal 打开时禁用。
function onPageKeyDown(ev: KeyboardEvent): void {
  // Esc:优先关闭 drawer / approveModal(覆盖默认行为)
  if (ev.key === "Escape") {
    if (approveModalOpen.value) {
      approveModalOpen.value = false;
      ev.preventDefault();
      return;
    }
    if (drawerOpen.value) {
      drawerOpen.value = false;
      ev.preventDefault();
      return;
    }
    return;
  }
  if (isEditingTarget(ev.target)) return;
  if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
  // approveModal / scope-select 时不接管行操作(避免双重 confirm)
  if (approveModalOpen.value) return;

  switch (ev.key) {
    case "j":
    case "ArrowDown":
      moveSelection(1);
      ev.preventDefault();
      break;
    case "k":
    case "ArrowUp":
      moveSelection(-1);
      ev.preventDefault();
      break;
    case "Enter": {
      const row = selectedApproval.value;
      if (row && !drawerOpen.value) {
        store.loadDetail(row.approval_id);
        drawerOpen.value = true;
        ev.preventDefault();
      }
      break;
    }
    case "a": {
      const row = selectedApproval.value;
      if (row) {
        openApproveModal(row.approval_id);
        ev.preventDefault();
      }
      break;
    }
    case "d": {
      const row = selectedApproval.value;
      if (row) {
        confirmDenyOrCancel(row.approval_id, "deny");
        ev.preventDefault();
      }
      break;
    }
    case "c": {
      const row = selectedApproval.value;
      if (row) {
        confirmDenyOrCancel(row.approval_id, "cancel");
        ev.preventDefault();
      }
      break;
    }
  }
}

// ─────────────────────── Columns ───────────────────────

function fmtTs(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("zh-CN");
}

const columns = computed<DataTableColumns<ApprovalSummary>>(() => [
  // v0.14 Theme E:多选列(NDataTable type:'selection' 内置 checkbox)
  { type: "selection" },
  {
    title: t("approval.col_approval_id"),
    key: "approval_id",
    width: 160,
    ellipsis: { tooltip: true },
    render: (row) => row.approval_id,
  },
  {
    title: t("approval.col_title"),
    key: "title",
    render: (row) => row.title,
  },
  {
    title: t("approval.col_summary"),
    key: "summary",
    ellipsis: { tooltip: true },
    render: (row) => row.summary,
  },
  {
    title: t("approval.col_status"),
    key: "status",
    width: 100,
    render: (row) => {
      const expired = store.isExpired(row);
      return h(NTag, { type: expired ? "error" : "warning" }, () =>
        expired ? t("approval.status_expired") : row.status,
      );
    },
  },
  {
    title: t("approval.col_expires"),
    key: "expires_at",
    width: 160,
    render: (row) => fmtTs(row.expires_at),
  },
]);

function handleRowClick(row: ApprovalSummary, index: number, ev: MouseEvent): void {
  // v0.14 Theme E:点击 selection 列(checkbox)不进 drawer
  const target = ev.target as HTMLElement | null;
  if (target?.closest(".n-data-table-td--selection")) return;
  selectedIndex.value = index;
  store.loadDetail(row.approval_id);
  drawerOpen.value = true;
}

// NDataTable rowProps 仅传 row;index 用 closure 复用 store.approvals.indexOf
const rowProps = (row: ApprovalSummary) => ({
  style: "cursor: pointer;",
  onClick: (ev: MouseEvent) =>
    handleRowClick(row, store.approvals.indexOf(row), ev),
});

function rowKey(row: ApprovalSummary): DataTableRowKey {
  return row.approval_id;
}

// v0.14 Theme B+:选中行高亮 class(配合 :deep CSS)
function rowClassName(_row: ApprovalSummary, index: number): string {
  return index === selectedIndex.value ? "row-selected" : "";
}

// ─────────────────────── v0.14 Theme E:Bulk actions ───────────────────────
const checkedRowKeys = ref<DataTableRowKey[]>([]);
const selectedCount = computed(() => checkedRowKeys.value.length);
const selectedIds = computed(() => checkedRowKeys.value.map((k) => String(k)));

function clearSelection(): void {
  checkedRowKeys.value = [];
}

// 当列表 refresh 后,把已不在 pending 的 id 从 selection 里剔除(防止 stale 选中)
function pruneStaleSelection(): void {
  if (checkedRowKeys.value.length === 0) return;
  const alive = new Set(store.approvals.map((a) => a.approval_id));
  checkedRowKeys.value = checkedRowKeys.value.filter((k) => alive.has(String(k)));
}

function openBulkApproveModal(): void {
  if (selectedCount.value === 0) return;
  approveModalMode.value = "bulk";
  approveModalApprovalId.value = null;
  approveScope.value = "Once";
  approveModalOpen.value = true;
}

function confirmBulkApprove(): void {
  const ids = [...selectedIds.value];
  const scope = approveScope.value;
  dialog.warning({
    title: t("approval.bulk_approve_confirm_title", { count: ids.length }),
    content: t("approval.bulk_approve_confirm_content", { scope }),
    positiveText: t("approval.bulk_approve_button", { count: ids.length }),
    negativeText: t("common.rethink"),
    onPositiveClick: async () => {
      const result = await store.resolveBulk(ids, "approve", { scope });
      // 成功的从 selection 移除;失败的保留以便重试
      const failedSet = new Set(result.failed.map((f) => f.approval_id));
      checkedRowKeys.value = checkedRowKeys.value.filter((k) => failedSet.has(String(k)));
      pruneStaleSelection();
    },
  });
}

function confirmBulkDeny(): void {
  const ids = [...selectedIds.value];
  if (ids.length === 0) return;
  dialog.warning({
    title: t("approval.bulk_deny_confirm_title", { count: ids.length }),
    content: t("approval.bulk_deny_confirm_content"),
    positiveText: t("approval.bulk_deny_button", { count: ids.length }),
    negativeText: t("common.rethink"),
    onPositiveClick: async () => {
      const result = await store.resolveBulk(ids, "deny");
      const failedSet = new Set(result.failed.map((f) => f.approval_id));
      checkedRowKeys.value = checkedRowKeys.value.filter((k) => failedSet.has(String(k)));
      pruneStaleSelection();
    },
  });
}

// Drawer emit → 分派
function handleApprove(approvalId: string): void {
  openApproveModal(approvalId);
}
function handleDeny(approvalId: string): void {
  confirmDenyOrCancel(approvalId, "deny");
}
function handleCancel(approvalId: string): void {
  confirmDenyOrCancel(approvalId, "cancel");
}

// v0.14 Theme B+:approvals 列表更新后 clamp selectedIndex
//   (approve/deny 成功后 row 消失,索引可能越界)
watch(() => store.approvals.length, clampSelectedIndex);
</script>

<template>
  <div class="p-6 space-y-4">
    <NSpace justify="space-between" align="center">
      <h2 class="text-xl font-semibold text-vigil-text">
        {{ t("approval.page_title") }}
        <span class="text-sm font-normal opacity-60 ml-2">
          ({{ t("approval.pending_count", { count: store.count }) }})
        </span>
      </h2>
      <NButton
        :loading="store.loading"
        size="small"
        data-testid="refresh-approvals"
        @click="store.refresh()"
      >
        {{ t("common.refresh") }}
      </NButton>
    </NSpace>

    <!-- v0.14 Theme E:bulk action bar(仅当有选中时显示)-->
    <NAlert
      v-if="selectedCount > 0"
      type="info"
      :show-icon="false"
      data-testid="bulk-action-bar"
    >
      <NSpace justify="space-between" align="center">
        <span class="text-sm">
          {{ t("approval.bulk_selected", { count: selectedCount }) }}
        </span>
        <NSpace :size="8">
          <NButton
            size="small"
            type="primary"
            :loading="store.resolving"
            data-testid="bulk-approve"
            @click="openBulkApproveModal"
          >
            {{ t("approval.bulk_approve") }}
          </NButton>
          <NButton
            size="small"
            type="error"
            :loading="store.resolving"
            data-testid="bulk-deny"
            @click="confirmBulkDeny"
          >
            {{ t("approval.bulk_deny") }}
          </NButton>
          <NButton size="small" quaternary @click="clearSelection">
            {{ t("approval.bulk_clear") }}
          </NButton>
        </NSpace>
      </NSpace>
    </NAlert>

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
      <NDataTable
        v-model:checked-row-keys="checkedRowKeys"
        :columns="columns"
        :data="store.approvals"
        :loading="store.loading"
        :row-props="rowProps"
        :row-key="rowKey"
        :row-class-name="rowClassName"
        :pagination="{ pageSize: 20 }"
        :bordered="false"
        size="small"
        data-testid="approvals-table"
      >
        <!-- v0.14 Theme A:contextual empty state(per ADR 0008 user-facing copy)-->
        <template #empty>
          <NEmpty
            :description="t('approval.empty_description')"
            data-testid="approvals-empty"
          >
            <template #extra>
              <div class="text-xs opacity-60 text-center">
                {{ t("approval.empty_extra") }}
              </div>
            </template>
          </NEmpty>
        </template>
      </NDataTable>
    </NCard>

    <ApprovalDetailDrawer
      v-model:show="drawerOpen"
      :detail="store.detail"
      :resolving="store.resolving"
      @approve="handleApprove"
      @deny="handleDeny"
      @cancel="handleCancel"
    />

    <!-- Approve scope 选择 modal — R1 BLOCKER 3 修复;v0.14 Theme E 复用于 bulk -->
    <NModal
      v-model:show="approveModalOpen"
      preset="card"
      :title="approveModalMode === 'bulk'
        ? t('approval.scope_modal_title_bulk', { count: selectedCount })
        : t('approval.scope_modal_title')"
      :bordered="false"
      size="small"
      style="width: 480px;"
    >
      <NSpace vertical :size="16">
        <div class="text-sm opacity-70">
          {{ approveModalMode === "bulk"
            ? t("approval.scope_modal_hint_bulk", { count: selectedCount })
            : t("approval.scope_modal_hint_single") }}
        </div>
        <NRadioGroup v-model:value="approveScope">
          <NSpace vertical :size="8">
            <NRadio value="Once">
              <strong>{{ t("approval.scope_once") }}</strong> —
              <span class="text-sm opacity-70">{{ t("approval.scope_once_desc") }}</span>
            </NRadio>
            <NRadio value="ThisSession">
              <strong>{{ t("approval.scope_this_session") }}</strong> —
              <span class="text-sm opacity-70">
                {{ t("approval.scope_this_session_desc") }}
              </span>
            </NRadio>
          </NSpace>
        </NRadioGroup>
        <NSpace justify="end">
          <NButton @click="approveModalOpen = false">{{ t("common.cancel") }}</NButton>
          <NButton
            type="primary"
            data-testid="confirm-approve-scope"
            @click="confirmApproveWithScope"
          >
            {{ t("common.next_step") }}({{ t("common.second_confirm") }})
          </NButton>
        </NSpace>
      </NSpace>
    </NModal>
  </div>
</template>

<style scoped>
/* v0.14 Theme B+:键盘选中行高亮(`:deep` 穿透到 NDataTable 内部 tr) */
:deep(.n-data-table-tr.row-selected) {
  background-color: rgba(64, 158, 255, 0.12);
}
:deep(.n-data-table-tr.row-selected .n-data-table-td) {
  background-color: rgba(64, 158, 255, 0.12);
}
</style>
