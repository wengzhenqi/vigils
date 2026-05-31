<script setup lang="ts">
/**
 * v0.14 Theme B — Keyboard shortcut help modal。
 *
 * `?` 切换显示;Esc 关闭(由全局 keydown 处理)。按 group 分组渲染。
 */
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { NModal, NSpace } from "naive-ui";
import { SHORTCUT_REFERENCE } from "@/composables/useGlobalShortcuts";

const { t } = useI18n();

defineProps<{ show: boolean }>();
defineEmits<{ "update:show": [value: boolean] }>();

// 按 groupKey 聚合,保持原始顺序;group 标题 + desc 走 i18n
const groupedShortcuts = computed(() => {
  const order: string[] = [];
  const map = new Map<string, Array<{ keys: string; desc: string }>>();
  for (const entry of SHORTCUT_REFERENCE) {
    if (!map.has(entry.groupKey)) {
      map.set(entry.groupKey, []);
      order.push(entry.groupKey);
    }
    map.get(entry.groupKey)!.push({ keys: entry.keys, desc: t(entry.descKey) });
  }
  return order.map((gk) => ({ group: t(gk), items: map.get(gk)! }));
});
</script>

<template>
  <NModal
    :show="show"
    preset="card"
    :title="t('shortcuts.modal_title')"
    :bordered="false"
    size="small"
    style="width: 520px;"
    @update:show="(v) => $emit('update:show', v)"
  >
    <NSpace vertical :size="14" data-testid="shortcut-help">
      <div v-for="block in groupedShortcuts" :key="block.group">
        <div class="shortcut-group-title">{{ block.group }}</div>
        <div
          v-for="entry in block.items"
          :key="entry.keys"
          class="shortcut-row"
        >
          <code class="shortcut-keys">{{ entry.keys }}</code>
          <span class="shortcut-desc">{{ entry.desc }}</span>
        </div>
      </div>
      <div class="shortcut-footnote">
        {{ t("shortcuts.footnote") }}
      </div>
    </NSpace>
  </NModal>
</template>

<style scoped>
.shortcut-group-title {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  opacity: 0.55;
  margin-bottom: 6px;
}
.shortcut-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 3px 0;
}
.shortcut-keys {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  padding: 2px 8px;
  border-radius: 4px;
  background: var(--vigil-input-bg, rgba(255, 255, 255, 0.06));
  border: 1px solid var(--vigil-border, rgba(255, 255, 255, 0.12));
  min-width: 64px;
  text-align: center;
}
.shortcut-desc {
  font-size: 13px;
  opacity: 0.85;
}
.shortcut-footnote {
  margin-top: 8px;
  font-size: 11px;
  opacity: 0.55;
  line-height: 1.6;
}
</style>
