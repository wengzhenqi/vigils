/**
 * I08b-α2 Approval Queue Pinia store。
 *
 * **R1 修订点**:
 * - `resolve()` 对 Approve 动作强制要求 `scope`(dispatcher 会拒绝无 scope 的 approve)
 * - enum 字符串大小写严格与 `@/api/ipc` 声明一致
 */
import { defineStore } from "pinia";
import { ref, computed } from "vue";
import {
  listPendingApprovals,
  getApprovalDetail,
  resolveApproval,
  type ApprovalSummary,
  type ApprovalDetailDto,
  type ApprovalAction,
  type ApprovalScope,
} from "@/api/ipc";

export const useApprovalsStore = defineStore("approvals", () => {
  // --- State ---
  const approvals = ref<ApprovalSummary[]>([]);
  const detail = ref<ApprovalDetailDto | null>(null);
  const loading = ref(false);
  const resolving = ref(false);
  const error = ref<string | null>(null);
  const lastRefreshedAt = ref<number | null>(null);

  // --- Getters ---
  const count = computed(() => approvals.value.length);
  const hasError = computed(() => error.value !== null);

  // --- Actions ---

  async function refresh(): Promise<void> {
    loading.value = true;
    error.value = null;
    try {
      approvals.value = await listPendingApprovals({});
      lastRefreshedAt.value = Date.now();
    } catch (e) {
      error.value = String(e);
    } finally {
      loading.value = false;
    }
  }

  async function loadDetail(approval_id: string): Promise<void> {
    error.value = null;
    try {
      detail.value = await getApprovalDetail({ approval_id });
    } catch (e) {
      error.value = String(e);
      detail.value = null;
    }
  }

  function clearDetail(): void {
    detail.value = null;
  }

  /**
   * 解析 approval。
   *
   * **契约**(来自 Rust dispatcher):
   * - `action === "approve"` **必须**带 `scope`;否则后端返 Invalid("approve action
   *   requires scope (Once / ThisSession)")
   * - `action === "deny" | "cancel"` 时 `scope` 应为 null,后端忽略
   * - `resolved_by` 必填(默认 "desktop-ui")
   *
   * 错误恢复:如果 approve 调用失败,UI 列表**不回滚**(approval 仍在 pending),
   * 用户可重试。error.value 被设置供 UI 提示。
   */
  async function resolve(
    approval_id: string,
    action: ApprovalAction,
    options: { scope?: ApprovalScope | null; resolved_by?: string; reason?: string } = {},
  ): Promise<void> {
    // 前端契约守门:approve 必传 scope(提前失败,避免无效 IPC)
    if (action === "approve" && !options.scope) {
      error.value = "approve action requires scope (Once / ThisSession)";
      return;
    }
    resolving.value = true;
    error.value = null;
    try {
      await resolveApproval({
        approval_id,
        action,
        scope: action === "approve" ? (options.scope ?? null) : null,
        resolved_by: options.resolved_by ?? "desktop-ui",
        reason: options.reason ?? null,
      });
      await refresh();
      if (detail.value && detail.value.request.approval_id === approval_id) {
        clearDetail();
      }
    } catch (e) {
      error.value = String(e);
    } finally {
      resolving.value = false;
    }
  }

  /**
   * v0.14 Theme E:批量 resolve(approve / deny / cancel)。
   *
   * **审计契约**(ADR 0001 hash chain per-event):
   * - 后端无 batch endpoint;此处**逐个**调用 `resolveApproval` IPC
   * - 每次 IPC 对应账本一条事件,保留 per-event hash 链粒度
   * - 任一失败不阻塞后续(用户视角:已批的留批,失败的列表可重试)
   * - 全部完成后**只 refresh 一次**,避免 N 次列表抓取
   *
   * Approve 路径必须传 `scope`(与单个 `resolve()` 同契约)。
   */
  async function resolveBulk(
    approval_ids: readonly string[],
    action: ApprovalAction,
    options: { scope?: ApprovalScope | null; resolved_by?: string; reason?: string } = {},
  ): Promise<{ succeeded: string[]; failed: Array<{ approval_id: string; error: string }> }> {
    if (action === "approve" && !options.scope) {
      error.value = "approve action requires scope (Once / ThisSession)";
      return { succeeded: [], failed: approval_ids.map((id) => ({ approval_id: id, error: "missing scope" })) };
    }
    resolving.value = true;
    error.value = null;
    const succeeded: string[] = [];
    const failed: Array<{ approval_id: string; error: string }> = [];
    for (const approval_id of approval_ids) {
      try {
        await resolveApproval({
          approval_id,
          action,
          scope: action === "approve" ? (options.scope ?? null) : null,
          resolved_by: options.resolved_by ?? "desktop-ui",
          reason: options.reason ?? null,
        });
        succeeded.push(approval_id);
      } catch (e) {
        failed.push({ approval_id, error: String(e) });
      }
    }
    if (failed.length > 0) {
      error.value = `${failed.length} of ${approval_ids.length} failed; first: ${failed[0].error}`;
    }
    await refresh();
    if (
      detail.value &&
      succeeded.includes(detail.value.request.approval_id)
    ) {
      clearDetail();
    }
    resolving.value = false;
    return { succeeded, failed };
  }

  /** 判定 approval 是否过期(UI hint;对比 PascalCase ApprovalStatus)*/
  function isExpired(summary: ApprovalSummary, nowSec: number = Math.floor(Date.now() / 1000)): boolean {
    // 已是 Expired 状态或 TTL 到期
    return summary.status === "Expired" || (summary.expires_at > 0 && nowSec >= summary.expires_at);
  }

  return {
    approvals,
    detail,
    loading,
    resolving,
    error,
    lastRefreshedAt,
    count,
    hasError,
    refresh,
    loadDetail,
    clearDetail,
    resolve,
    resolveBulk,
    isExpired,
  };
});
