/**
 * I08b-α5 Session Replay Pinia store。
 *
 * 职责:
 * - 维护 session 列表(复用 α1 listSessions + SessionView DTO)
 * - 加载选中 session 的完整 replay(SessionReplay + 可选 chain verify)
 * - 支持独立触发 ledger 级 verify_chain(Activity Feed 也可调)
 *
 * 安全契约:
 * - ChainVerifyReport.message 经后端脱敏(chain_broken_at=N 或固定字符串)
 * - replay 返回的 events 每条 payload 已 JCS + 脱敏,UI 仅 stringify 展示
 */
import { defineStore } from "pinia";
import { ref } from "vue";
import {
  listSessions,
  replaySession,
  verifyChain,
  type ChainVerifyReport,
  type ListSessionsReq,
  type ReplaySessionReq,
  type SessionReplay,
  type SessionView,
} from "@/api/ipc";

export const useSessionsStore = defineStore("sessions", () => {
  // --- List ---
  const sessions = ref<SessionView[]>([]);
  const listLoading = ref(false);

  // --- Replay ---
  const replay = ref<SessionReplay | null>(null);
  const replayLoading = ref(false);
  const selectedSessionId = ref<string | null>(null);

  // --- Standalone chain verify(Activity Feed 或 SessionReplay 页侧) ---
  const standaloneVerify = ref<ChainVerifyReport | null>(null);
  const verifyLoading = ref(false);

  const error = ref<string | null>(null);
  const lastRefreshedAt = ref<number | null>(null);

  async function refreshList(req: ListSessionsReq = { limit: 100 }): Promise<void> {
    listLoading.value = true;
    error.value = null;
    try {
      sessions.value = await listSessions(req);
      lastRefreshedAt.value = Date.now();
    } catch (e) {
      error.value = String(e);
    } finally {
      listLoading.value = false;
    }
  }

  async function loadReplay(req: ReplaySessionReq): Promise<void> {
    replayLoading.value = true;
    error.value = null;
    try {
      replay.value = await replaySession(req);
      selectedSessionId.value = req.session_id;
    } catch (e) {
      error.value = String(e);
      replay.value = null;
    } finally {
      replayLoading.value = false;
    }
  }

  function clearReplay(): void {
    replay.value = null;
    selectedSessionId.value = null;
  }

  async function runStandaloneVerify(): Promise<void> {
    verifyLoading.value = true;
    error.value = null;
    try {
      standaloneVerify.value = await verifyChain();
    } catch (e) {
      error.value = String(e);
      standaloneVerify.value = null;
    } finally {
      verifyLoading.value = false;
    }
  }

  return {
    // state
    sessions,
    listLoading,
    replay,
    replayLoading,
    selectedSessionId,
    standaloneVerify,
    verifyLoading,
    error,
    lastRefreshedAt,
    // actions
    refreshList,
    loadReplay,
    clearReplay,
    runStandaloneVerify,
  };
});
