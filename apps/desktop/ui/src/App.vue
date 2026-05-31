<script setup lang="ts">
/**
 * I08b-α2 App shell — 侧边栏 + router-view。
 *
 * 安全契约(AGENTS.md + ADR 0008):
 * - 全局 NConfigProvider 使用 darkTheme(用户需求默认深色模式)
 * - NDialogProvider + NMessageProvider 供子组件 useDialog / useMessage
 * - 禁 v-html / innerHTML(ESLint rule 守门)
 *
 * v0.14 GUI Theme C(2026-05-16):theme toggle 启用 dark / light / system(prefers)
 * 三模式,localStorage 持久化。default = "dark"(原行为保留)。
 */
import { NConfigProvider, NLayout, NLayoutSider, NMenu, NDialogProvider, NMessageProvider, NButton, darkTheme, lightTheme } from "naive-ui";
import { RouterLink, RouterView, useRoute, useRouter } from "vue-router";
import { computed, h, ref, onMounted, onUnmounted } from "vue";
import { useI18n } from "vue-i18n";
import { useGlobalShortcuts } from "@/composables/useGlobalShortcuts";
import ShortcutHelpModal from "@/components/ShortcutHelpModal.vue";
import { setLocale, SUPPORTED_LOCALES, type SupportedLocale } from "@/i18n";

const route = useRoute();
const router = useRouter();
const { t, locale } = useI18n();

// v0.14 Theme D:语言切换(zh-CN ↔ en-US 二态循环)
function cycleLocale(): void {
  const idx = SUPPORTED_LOCALES.findIndex((l) => l.code === locale.value);
  const next = SUPPORTED_LOCALES[(idx + 1) % SUPPORTED_LOCALES.length];
  setLocale(next.code as SupportedLocale);
}
const currentLocaleShort = computed(() => {
  const entry = SUPPORTED_LOCALES.find((l) => l.code === locale.value);
  return entry?.short ?? "EN";
});
const currentLocaleLabel = computed(() => {
  const entry = SUPPORTED_LOCALES.find((l) => l.code === locale.value);
  return entry?.label ?? "English";
});

// v0.14 Theme B:全局快捷键(g-chord 导航 / `/` 搜索 / `?` 帮助)
const shortcutHelpOpen = ref(false);
useGlobalShortcuts({ router, helpOpen: shortcutHelpOpen });

// ─────────────────────── v0.14 Theme C:三模式 toggle ───────────────────────
type ThemeMode = "dark" | "light" | "system";
const THEME_STORAGE_KEY = "vigil-theme-mode";

const themeMode = ref<ThemeMode>(loadTheme());

function loadTheme(): ThemeMode {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === "dark" || stored === "light" || stored === "system") return stored;
  } catch {
    // localStorage 不可用(privacy mode / sandbox 等),fallback 默认
  }
  return "dark";
}

function persistTheme(mode: ThemeMode): void {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, mode);
  } catch {
    // 同上 ignore
  }
}

const prefersDark = ref(
  typeof window !== "undefined" && typeof window.matchMedia === "function"
    ? window.matchMedia("(prefers-color-scheme: dark)").matches
    : true,
);

// reactive Naive UI theme(dark = darkTheme,light = lightTheme,system = follow prefers)
const activeTheme = computed(() => {
  if (themeMode.value === "dark") return darkTheme;
  if (themeMode.value === "light") return lightTheme;
  // system
  return prefersDark.value ? darkTheme : lightTheme;
});

function cycleTheme(): void {
  // 三态循环:dark → light → system → dark ...
  const order: ThemeMode[] = ["dark", "light", "system"];
  const idx = order.indexOf(themeMode.value);
  themeMode.value = order[(idx + 1) % order.length];
  persistTheme(themeMode.value);
}

const themeIcon = computed(() => {
  if (themeMode.value === "dark") return "🌙";
  if (themeMode.value === "light") return "☀️";
  return "🖥️"; // system
});

const themeLabel = computed(() => {
  if (themeMode.value === "dark") return t("sidebar.theme_dark");
  if (themeMode.value === "light") return t("sidebar.theme_light");
  return t("sidebar.theme_system");
});

// 监听 system color scheme 改变(仅 themeMode = "system" 时影响 activeTheme)
let mediaQueryList: MediaQueryList | null = null;
const onSystemThemeChange = (e: MediaQueryListEvent): void => {
  prefersDark.value = e.matches;
};
onMounted(() => {
  if (typeof window !== "undefined" && typeof window.matchMedia === "function") {
    mediaQueryList = window.matchMedia("(prefers-color-scheme: dark)");
    mediaQueryList.addEventListener("change", onSystemThemeChange);
  }
});
onUnmounted(() => {
  if (mediaQueryList) {
    mediaQueryList.removeEventListener("change", onSystemThemeChange);
    mediaQueryList = null;
  }
});

// 菜单与 router 4 条路由一一对应(R2 NICE 修复:同步占位项)。
// 未实装路由指向 NotImplemented,菜单显示为 disabled 以让用户知晓存在但暂不可点。
// v0.14 Theme D:菜单 label 走 i18n,locale 变化时 computed 重渲染
const menuOptions = computed(() => [
  {
    label: () => h(RouterLink, { to: "/approvals" }, () => t("nav.approvals")),
    key: "approvals",
  },
  {
    label: () => h(RouterLink, { to: "/activity" }, () => t("nav.activity")),
    key: "activity",
  },
  {
    label: () => h(RouterLink, { to: "/servers" }, () => t("nav.servers")),
    key: "servers",
  },
  {
    label: () => h(RouterLink, { to: "/sessions" }, () => t("nav.sessions")),
    key: "sessions",
  },
  {
    label: () => h(RouterLink, { to: "/privacy" }, () => t("nav.privacy")),
    key: "privacy",
  },
]);

const selectedKey = computed(() => {
  const name = (route.name as string | undefined) ?? "approvals";
  return name;
});
</script>

<template>
  <NConfigProvider :theme="activeTheme">
    <NMessageProvider>
      <NDialogProvider>
        <NLayout has-sider class="h-screen">
          <NLayoutSider
            bordered
            :width="180"
            :collapsed-width="56"
            :collapse-mode="'width'"
            class="bg-vigil-panel"
          >
            <div class="p-4 border-b border-vigil-border">
              <div class="text-sm font-semibold text-vigil-text">{{ t("sidebar.app_title") }}</div>
              <div class="text-xs opacity-60">{{ t("sidebar.app_subtitle") }}</div>
            </div>
            <NMenu :options="menuOptions" :value="selectedKey" />
            <!-- v0.14 Theme C + B + D:sidebar 底部 toggle 区 -->
            <div class="sidebar-footer">
              <NButton
                size="small"
                quaternary
                block
                data-testid="shortcut-help-toggle"
                title="Keyboard shortcuts (press ?)"
                @click="shortcutHelpOpen = true"
              >
                <span class="theme-toggle-content">{{ t("sidebar.shortcuts_button") }}</span>
              </NButton>
              <NButton
                size="small"
                quaternary
                block
                data-testid="locale-toggle"
                :title="t('sidebar.language_tooltip', { label: currentLocaleLabel })"
                @click="cycleLocale"
              >
                <span class="theme-toggle-content">🌐 {{ currentLocaleShort }}</span>
              </NButton>
              <NButton
                size="small"
                quaternary
                block
                data-testid="theme-toggle"
                :title="t('sidebar.theme_tooltip', { label: themeLabel })"
                @click="cycleTheme"
              >
                <span class="theme-toggle-content">{{ themeIcon }} {{ themeLabel }}</span>
              </NButton>
            </div>
          </NLayoutSider>
          <NLayout>
            <RouterView />
          </NLayout>
        </NLayout>
        <!-- v0.14 Theme B:全局快捷键 help modal -->
        <ShortcutHelpModal v-model:show="shortcutHelpOpen" />
      </NDialogProvider>
    </NMessageProvider>
  </NConfigProvider>
</template>

<style scoped>
.sidebar-footer {
  position: absolute;
  bottom: 12px;
  left: 8px;
  right: 8px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.theme-toggle-content {
  font-size: 12px;
}
</style>
