<script setup lang="ts">
/**
 * D19 Protection Overview —— 桌面 GUI 的"Vigil 拦下了什么"保护成效落地页。
 * = CLI `vigil-hub inspect protection`(D11)的 GUI 等价物,面向非 CLI 受众的 audit 控制台。
 *
 * 只读:调 `protection_summary()` → 展示计数 + 哈希链完整性 + 最近脱敏事件。
 * **fail-closed**:`chain_intact=false`(账本被篡改)时 Rust 端已强制 `recent=[]`(绝不回显
 * 可能被注入 secret 的明细),计数仍保留。
 * 安全契约:所有 text 经 `{{ }}` 插值(含 redacted_text);i18n 仅纯 `{named}`(CSP-safe 编译器)。
 */
import { onMounted, ref } from "vue";
import { NCard, NSpace, NButton, NAlert, NEmpty, NTimeline, NTimelineItem } from "naive-ui";
import { useI18n } from "vue-i18n";
import { useLedgerLiveUpdates } from "@/composables/useLedgerLiveUpdates";
import { protectionSummary, type ProtectionSummary } from "@/api/ipc";

const { t } = useI18n();
const summary = ref<ProtectionSummary | null>(null);
const loading = ref(false);
const error = ref<string | null>(null);

async function refresh(): Promise<void> {
  loading.value = true;
  error.value = null;
  try {
    summary.value = await protectionSummary();
  } catch (e) {
    error.value = String(e);
  } finally {
    loading.value = false;
  }
}

// 账本写入即刷新(复用 Activity/Approval 等页同款 live-update 锚点);不可用降级一次性加载。
useLedgerLiveUpdates({ onChange: () => refresh() });
onMounted(() => refresh());

function fmtTs(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("zh-CN");
}
</script>

<template>
  <div class="p-6 space-y-4">
    <NSpace justify="space-between" align="center">
      <h2 class="text-xl font-semibold text-vigil-text">{{ t("protection.page_title") }}</h2>
      <NButton
        :loading="loading"
        size="small"
        data-testid="refresh-protection"
        @click="refresh()"
      >
        {{ t("common.refresh") }}
      </NButton>
    </NSpace>

    <p class="text-sm opacity-70 text-vigil-text">{{ t("protection.subtitle") }}</p>

    <NAlert
      v-if="error"
      type="error"
      :title="t('common.ipc_error')"
      closable
      @close="error = null"
    >
      {{ error }}
    </NAlert>

    <template v-if="summary">
      <!-- 计数 tiles(每块 = 一类已发生的保护动作)-->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
        <NCard size="small" class="bg-vigil-panel border-vigil-border" data-testid="stat-secrets-blocked">
          <div class="text-2xl font-semibold text-vigil-text">{{ summary.raw_secrets_blocked }}</div>
          <div class="text-sm text-vigil-text mt-1">{{ t("protection.secrets_blocked") }}</div>
          <div class="text-xs opacity-60 mt-1">{{ t("protection.secrets_blocked_hint") }}</div>
        </NCard>
        <NCard size="small" class="bg-vigil-panel border-vigil-border" data-testid="stat-leaks-detected">
          <div class="text-2xl font-semibold text-vigil-text">{{ summary.tool_result_leaks_detected }}</div>
          <div class="text-sm text-vigil-text mt-1">{{ t("protection.leaks_detected") }}</div>
          <div class="text-xs opacity-60 mt-1">{{ t("protection.leaks_detected_hint") }}</div>
        </NCard>
        <NCard size="small" class="bg-vigil-panel border-vigil-border" data-testid="stat-aliases-withheld">
          <div class="text-2xl font-semibold text-vigil-text">{{ summary.secret_aliases_unresolved }}</div>
          <div class="text-sm text-vigil-text mt-1">{{ t("protection.aliases_withheld") }}</div>
          <div class="text-xs opacity-60 mt-1">{{ t("protection.aliases_withheld_hint") }}</div>
        </NCard>
        <NCard size="small" class="bg-vigil-panel border-vigil-border" data-testid="stat-events-audited">
          <div class="text-2xl font-semibold text-vigil-text">{{ summary.total_events_audited }}</div>
          <div class="text-sm text-vigil-text mt-1">{{ t("protection.events_audited") }}</div>
          <div class="text-xs opacity-60 mt-1">
            {{ t("protection.events_audited_hint", { sessions: summary.sessions_covered }) }}
          </div>
        </NCard>
      </div>

      <!-- 哈希链完整性 = 防篡改审计的信任锚 -->
      <NAlert
        :type="summary.chain_intact ? 'success' : 'error'"
        :title="summary.chain_intact ? t('protection.chain_ok_title') : t('protection.chain_bad_title')"
        data-testid="chain-status"
      >
        {{ summary.chain_intact ? t("protection.chain_ok_body") : t("protection.chain_bad_body") }}
      </NAlert>

      <!-- 最近保护事件(只读脱敏摘要;链坏时 Rust 端已强制为空)-->
      <NCard class="bg-vigil-panel border-vigil-border" :bordered="true">
        <h3 class="text-base font-semibold text-vigil-text mb-2">{{ t("protection.recent_title") }}</h3>
        <NEmpty
          v-if="summary.recent.length === 0"
          :description="summary.chain_intact
            ? t('protection.recent_empty')
            : t('protection.recent_suppressed')"
          data-testid="protection-recent-empty"
          class="py-6"
        />
        <NTimeline v-else>
          <NTimelineItem
            v-for="ev in summary.recent"
            :key="ev.event_id"
            type="warning"
            :title="ev.event_type"
            :time="fmtTs(ev.created_at)"
            data-testid="protection-event-item"
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
    </template>

    <NEmpty
      v-else-if="!loading"
      :description="t('protection.loading_failed')"
      data-testid="protection-load-failed"
      class="py-8"
    />
  </div>
</template>
