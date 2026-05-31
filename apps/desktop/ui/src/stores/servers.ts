/**
 * I08b-α4 Server Registry Pinia store。
 *
 * 职责:
 * - 维护 4 个列表:approved servers / pending tool approvals / drifted tools / drifted servers
 * - 单个 server 的 onboarding detail(展开 argv + env keys + pending hash)
 * - 审批写操作(approveTool / approveToolDrift / rejectToolDrift /
 *   approveServerCommandDrift / rejectServerCommandDrift)
 * - polling 刷新(复用 α2/α3 pattern:5s + `document.hidden` 暂停)
 *
 * 安全契约:
 * - argv 展示由页面层逐元素渲染,store 只传 string[],不在此 join
 * - env keys 值永远不出现;store 只存 key 数组
 * - 写操作返回 void(Ack),UI 侧在成功后显式 refresh() 拉新状态
 */
import { defineStore } from "pinia";
import { computed, ref } from "vue";
import {
  approveServerCommandDrift,
  approveTool,
  approveToolDrift,
  getServerOnboarding,
  listDriftedServers,
  listDriftedTools,
  listPendingToolApprovals,
  listServers,
  rejectServerCommandDrift,
  rejectToolDrift,
  type ApproveServerCommandDriftReq,
  type ApproveToolDriftReq,
  type ApproveToolReq,
  type RejectServerCommandDriftReq,
  type RejectToolDriftReq,
  type ServerOnboardingData,
  type StoredServerProfile,
  type ToolApprovalCard,
} from "@/api/ipc";

export const useServersStore = defineStore("servers", () => {
  // --- List states ---
  const servers = ref<StoredServerProfile[]>([]);
  const pendingTools = ref<ToolApprovalCard[]>([]);
  const driftedTools = ref<ToolApprovalCard[]>([]);
  const driftedServers = ref<ServerOnboardingData[]>([]);

  // --- Detail state(点击卡片后填充)---
  const onboardingDetail = ref<ServerOnboardingData | null>(null);
  const detailLoading = ref(false);

  // --- Loading / error ---
  const loading = ref(false);
  const error = ref<string | null>(null);
  const lastRefreshedAt = ref<number | null>(null);

  // --- Counts(UI 徽章)---
  const pendingCount = computed(() => pendingTools.value.length);
  const driftedCount = computed(
    () => driftedTools.value.length + driftedServers.value.length,
  );

  // --- Actions ---

  /** 一键并行刷新 4 个列表(尽量减少状态不一致窗口)。 */
  async function refresh(): Promise<void> {
    loading.value = true;
    error.value = null;
    try {
      const [a, b, c, d] = await Promise.all([
        listServers(),
        listPendingToolApprovals(),
        listDriftedTools(),
        listDriftedServers(),
      ]);
      servers.value = a;
      pendingTools.value = b;
      driftedTools.value = c;
      driftedServers.value = d;
      lastRefreshedAt.value = Date.now();
    } catch (e) {
      error.value = String(e);
    } finally {
      loading.value = false;
    }
  }

  async function loadDetail(server_id: string): Promise<void> {
    detailLoading.value = true;
    error.value = null;
    try {
      onboardingDetail.value = await getServerOnboarding({ server_id });
    } catch (e) {
      error.value = String(e);
      onboardingDetail.value = null;
    } finally {
      detailLoading.value = false;
    }
  }

  function clearDetail(): void {
    onboardingDetail.value = null;
  }

  // --- Write actions(成功后统一 refresh 列表 & detail)---

  async function approveToolAction(req: ApproveToolReq): Promise<void> {
    await approveTool(req);
    await refresh();
  }

  async function approveToolDriftAction(req: ApproveToolDriftReq): Promise<void> {
    await approveToolDrift(req);
    await refresh();
  }

  async function rejectToolDriftAction(req: RejectToolDriftReq): Promise<void> {
    await rejectToolDrift(req);
    await refresh();
  }

  async function approveServerCommandDriftAction(
    req: ApproveServerCommandDriftReq,
  ): Promise<void> {
    await approveServerCommandDrift(req);
    // 漂移批准后 onboardingDetail 的 pending_command_hash 应清空 —— 若当前 detail 是该 server 则同步
    if (onboardingDetail.value?.server_id === req.server_id) {
      await loadDetail(req.server_id);
    }
    await refresh();
  }

  async function rejectServerCommandDriftAction(
    req: RejectServerCommandDriftReq,
  ): Promise<void> {
    await rejectServerCommandDrift(req);
    if (onboardingDetail.value?.server_id === req.server_id) {
      await loadDetail(req.server_id);
    }
    await refresh();
  }

  return {
    // state
    servers,
    pendingTools,
    driftedTools,
    driftedServers,
    onboardingDetail,
    detailLoading,
    loading,
    error,
    lastRefreshedAt,
    // getters
    pendingCount,
    driftedCount,
    // actions
    refresh,
    loadDetail,
    clearDetail,
    approveToolAction,
    approveToolDriftAction,
    rejectToolDriftAction,
    approveServerCommandDriftAction,
    rejectServerCommandDriftAction,
  };
});
