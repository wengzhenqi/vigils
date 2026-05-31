<script setup lang="ts">
/**
 * ISS-017 — Privacy Findings 聚合面板。
 *
 * 视图布局:
 *   1) 顶部:全局 label × count 标签徽章("一眼看到今天拦了哪些 PII")
 *   2) 下方:最近 N 条 scans 表格(ts / source / scan_id 缩短 / fingerprint 缩短 / finding 数)
 *      - 行点击预留(phase 2 加溯源 drawer)
 *
 * **绝不展原文**:DTO 仅含 metadata 类字段。fingerprint 显示 8 字符前缀(可识别但
 * 不可逆),session_id / scan_id 缩短到首 8 字符 + 末 4 字符。
 *
 * 安全契约(延续 ApprovalDetailDrawer α3):
 *   - 所有字符串 `{{ }}` 插值,Vue 默认转义,XSS 安全
 *   - 不引入 v-html / innerHTML
 *   - 后端 ipc.listPrivacyFindings 失败 → 显示 error 提示,不崩页
 */
import { computed, onMounted, onUnmounted, ref } from "vue";
import {
  NCard,
  NDataTable,
  NEmpty,
  NSpace,
  NTag,
  NText,
  NSpin,
  NAlert,
  type DataTableColumns,
} from "naive-ui";
import { h } from "vue";
import { useI18n } from "vue-i18n";
import {
  listPrivacyFindings,
  type PrivacyFindingDto,
  type PrivacyFindingsDto,
  type RedactionScanSummaryDto,
} from "@/api/ipc";

const { t } = useI18n();
const data = ref<PrivacyFindingsDto | null>(null);
const loading = ref(true);
const errorMsg = ref<string | null>(null);

async function refresh() {
  loading.value = true;
  errorMsg.value = null;
  try {
    data.value = await listPrivacyFindings({ limit_recent_scans: 100 });
  } catch (e) {
    errorMsg.value = String(e);
  } finally {
    loading.value = false;
  }
}

onMounted(refresh);

// 30s 自动刷新(轻量轮询;UI 长时间打开仍跟踪新 scan)。
const refreshTimer = setInterval(refresh, 30_000);
onUnmounted(() => clearInterval(refreshTimer));

/** Label 徽章颜色映射 — 与 ApprovalDetailDrawer.privacyTagType 同源(ISS-014)。
 *  字面量与 vigil_redaction::PrivacyLabel::as_str() 对齐(无 `private_` 前缀)。 */
function privacyTagType(
  label: string,
): "default" | "warning" | "success" | "error" | "info" {
  switch (label) {
    case "secret":
    case "account_number":
      return "error";
    case "email":
    case "phone":
    case "person":
    case "address":
    case "url":
    case "date":
      return "warning";
    default:
      return "default";
  }
}

/** Source 标签:tool_arg(firewall preflight) / paste(扩展粘贴) / tool_output(回吐) / export */
function sourceTagType(
  source: string,
): "default" | "warning" | "success" | "error" | "info" {
  switch (source) {
    case "tool_arg":
      return "info";
    case "paste":
      return "default";
    case "tool_output":
      return "warning";
    case "export":
      return "success";
    default:
      return "default";
  }
}

/** UUID/Hex 缩短显示:首 8 + … + 末 4(总 14 字符,适合表格列宽)。 */
function shortId(id: string): string {
  if (id.length <= 14) return id;
  return `${id.slice(0, 8)}…${id.slice(-4)}`;
}

/** Unix 秒 → 本地时间字符串 */
function formatTs(ts: number): string {
  if (!ts || ts <= 0) return "—";
  return new Date(ts * 1000).toLocaleString("zh-CN");
}

const columns = computed<DataTableColumns<RedactionScanSummaryDto>>(() => [
  {
    title: t("privacy.col_time"),
    key: "ts",
    width: 170,
    render: (row) => formatTs(row.ts),
  },
  {
    title: t("privacy.col_source"),
    key: "source",
    width: 110,
    render: (row) =>
      h(
        NTag,
        { size: "small", type: sourceTagType(row.source), bordered: false },
        () => row.source,
      ),
  },
  {
    title: t("privacy.col_findings"),
    key: "finding_count",
    width: 100,
    render: (row) => `${row.finding_count}`,
  },
  {
    title: t("privacy.col_scan_id"),
    key: "scan_id",
    width: 160,
    render: (row) =>
      h(
        "code",
        { class: "text-xs", title: row.scan_id },
        shortId(row.scan_id),
      ),
  },
  {
    title: t("privacy.col_session"),
    key: "session_id",
    width: 160,
    render: (row) =>
      h(
        "code",
        { class: "text-xs opacity-70", title: row.session_id },
        shortId(row.session_id),
      ),
  },
  {
    title: t("privacy.col_fingerprint"),
    key: "fingerprint",
    render: (row) =>
      h(
        "code",
        { class: "text-xs opacity-50", title: row.fingerprint },
        row.fingerprint.slice(0, 8),
      ),
  },
]);
</script>

<template>
  <div class="p-6 overflow-auto h-full">
    <header class="mb-6">
      <h1 class="text-xl font-semibold mb-1">{{ t("privacy.page_title") }}</h1>
      <NText depth="3" class="text-sm">
        {{ t("privacy.page_subtitle_1") }}
        <strong>{{ t("privacy.page_subtitle_strong") }}</strong> {{ t("privacy.page_subtitle_2") }}
      </NText>
    </header>

    <NAlert
      v-if="errorMsg"
      type="error"
      class="mb-4"
      :title="t('privacy.load_error', { msg: errorMsg })"
      closable
    />

    <NSpin :show="loading">
      <!-- 顶部:全局 label 聚合 -->
      <NCard
        :title="t('privacy.by_label_title')"
        size="small"
        class="mb-4"
        data-testid="privacy-findings-by-label"
      >
        <NEmpty
          v-if="!data || data.by_label_total.length === 0"
          :description="t('privacy.by_label_empty')"
          size="small"
        />
        <NSpace v-else>
          <NTag
            v-for="f in (data.by_label_total as PrivacyFindingDto[])"
            :key="f.label"
            size="medium"
            :type="privacyTagType(f.label)"
            :bordered="false"
            :data-testid="`privacy-by-label-${f.label}`"
          >
            {{ f.label }} × {{ f.count }}
          </NTag>
        </NSpace>
      </NCard>

      <!-- 下方:最近 N 条 scans -->
      <NCard
        :title="t('privacy.recent_scans_title')"
        size="small"
        data-testid="privacy-findings-recent-scans"
      >
        <NDataTable
          :columns="columns"
          :data="data?.recent_scans ?? []"
          :bordered="false"
          size="small"
          :max-height="600"
          virtual-scroll
        />
      </NCard>
    </NSpin>
  </div>
</template>
