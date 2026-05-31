<script setup lang="ts">
/**
 * I08b-α4 Server onboarding detail card。
 *
 * 展示 ServerOnboardingData 的所有字段(§9 核心面板)。
 *
 * 安全契约:
 * - **argv 逐元素渲染**(禁 `.join(' ')`),防 shell 误读 / 注入错觉
 * - env_keys 只展示 key,绝不展示值(由后端保证 value 不在 DTO 里)
 * - pending_command_hash 非空 → 展示 drift diff(旧 hash vs 新 hash)
 */
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import {
  NCard,
  NDescriptions,
  NDescriptionsItem,
  NTag,
  NSpace,
  NAlert,
  NButton,
  useDialog,
} from "naive-ui";
import type { ServerOnboardingData } from "@/api/ipc";

const { t } = useI18n();

interface Props {
  data: ServerOnboardingData;
  /** 是否显示 command drift 审批按钮(Tab 3 drifted servers 下开启)*/
  showDriftActions?: boolean;
}
const props = withDefaults(defineProps<Props>(), { showDriftActions: false });

const emit = defineEmits<{
  (e: "approve-drift", server_id: string): void;
  (e: "reject-drift", server_id: string): void;
}>();

const dialog = useDialog();

const firstSeenDisplay = computed(() =>
  props.data.first_seen_at ? new Date(props.data.first_seen_at * 1000).toLocaleString("zh-CN") : "—",
);

const hasDrift = computed(() => props.data.pending_command_hash !== null);

const trustTagType = computed<"default" | "warning" | "success" | "error">(() => {
  switch (props.data.trust_level) {
    case "Trusted":
      return "success";
    case "Limited":
      return "default";
    case "Untrusted":
      return "warning";
    default:
      return "default";
  }
});

// 双层确认:approve / reject command drift 是高危操作
function confirmApproveDrift(): void {
  dialog.warning({
    title: t("onboardingCard.confirm_approve_title"),
    content: t("onboardingCard.confirm_approve_content", {
      serverId: props.data.server_id,
      hash: props.data.pending_command_hash,
    }),
    positiveText: t("common.approve"),
    negativeText: t("common.cancel"),
    onPositiveClick: () => {
      emit("approve-drift", props.data.server_id);
    },
  });
}
function confirmRejectDrift(): void {
  dialog.error({
    title: t("onboardingCard.confirm_reject_title"),
    content: t("onboardingCard.confirm_reject_content", { hash: props.data.command_hash }),
    positiveText: t("common.reject"),
    negativeText: t("common.cancel"),
    onPositiveClick: () => {
      emit("reject-drift", props.data.server_id);
    },
  });
}
</script>

<template>
  <NSpace vertical :size="16">
    <NAlert v-if="hasDrift" type="warning" :show-icon="true" :title="t('onboardingCard.drift_alert_title')">
      {{ t("onboardingCard.drift_alert_body") }}
    </NAlert>

    <NDescriptions label-placement="left" :column="1" bordered>
      <NDescriptionsItem :label="t('onboardingCard.label_server_id')">
        <code class="text-xs">{{ data.server_id }}</code>
      </NDescriptionsItem>
      <NDescriptionsItem :label="t('onboardingCard.label_transport')">
        <NTag size="small" :type="data.transport === 'Stdio' ? 'info' : 'success'">
          {{ data.transport }}
        </NTag>
      </NDescriptionsItem>
      <NDescriptionsItem :label="t('onboardingCard.label_trust_level')">
        <NTag size="small" :type="trustTagType">{{ data.trust_level }}</NTag>
      </NDescriptionsItem>
      <NDescriptionsItem :label="t('onboardingCard.label_first_seen')">
        {{ firstSeenDisplay }}
      </NDescriptionsItem>
      <NDescriptionsItem v-if="data.url" :label="t('onboardingCard.label_url')">
        <code class="text-xs break-all">{{ data.url }}</code>
      </NDescriptionsItem>
      <NDescriptionsItem :label="t('onboardingCard.label_command_hash')">
        <code class="text-xs break-all">{{ data.command_hash ?? "—" }}</code>
      </NDescriptionsItem>
      <NDescriptionsItem v-if="hasDrift" :label="t('onboardingCard.label_pending_hash')">
        <code class="text-xs break-all text-yellow-400">{{ data.pending_command_hash }}</code>
      </NDescriptionsItem>
      <NDescriptionsItem :label="t('onboardingCard.label_sandbox_profile')">
        <code v-if="data.sandbox_profile_id" class="text-xs">{{ data.sandbox_profile_id }}</code>
        <span v-else class="text-gray-500">{{ t("onboardingCard.sandbox_inherit_default") }}</span>
      </NDescriptionsItem>
    </NDescriptions>

    <!-- Exact argv — 逐元素渲染(§ADR 0005:禁 shell 拼接) -->
    <NCard :title="t('onboardingCard.argv_title')" size="small">
      <div v-if="data.command && data.command.length > 0" class="font-mono text-xs space-y-1">
        <div
          v-for="(arg, idx) in data.command"
          :key="idx"
          class="flex items-start gap-2"
        >
          <span class="text-gray-500 w-8 text-right select-none">{{ idx }}</span>
          <code class="break-all">{{ arg }}</code>
        </div>
      </div>
      <div v-else class="text-gray-500">{{ t("onboardingCard.argv_non_stdio") }}</div>
    </NCard>

    <!-- Env keys — 仅展示 key,值永远不暴露 -->
    <NCard :title="t('onboardingCard.env_keys_title')" size="small">
      <div v-if="data.requested_env_keys === null" class="text-gray-500">
        {{ t("onboardingCard.env_keys_pending") }}
      </div>
      <div v-else-if="data.requested_env_keys.length === 0" class="text-gray-500">
        {{ t("onboardingCard.env_keys_none") }}
      </div>
      <NSpace v-else>
        <NTag
          v-for="k in data.requested_env_keys"
          :key="k"
          size="small"
          type="info"
          :bordered="false"
        >
          {{ k }}
        </NTag>
      </NSpace>
    </NCard>

    <!-- Drift actions(仅 Tab 3) -->
    <NSpace v-if="showDriftActions && hasDrift">
      <NButton
        type="warning"
        size="small"
        data-testid="approve-command-drift"
        @click="confirmApproveDrift"
      >
        {{ t("onboardingCard.approve_drift") }}
      </NButton>
      <NButton
        type="error"
        size="small"
        data-testid="reject-command-drift"
        @click="confirmRejectDrift"
      >
        {{ t("onboardingCard.reject_drift") }}
      </NButton>
    </NSpace>
  </NSpace>
</template>
