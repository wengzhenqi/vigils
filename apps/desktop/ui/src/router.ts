import { createRouter, createWebHashHistory, type RouteRecordRaw } from "vue-router";

/**
 * I08b-α2 Router 骨架。
 *
 * - α2 实装:ApprovalQueue(`/approvals`)
 * - α3/α4/α5 占位:显式指向 `NotImplemented.vue` 而非虚假指向 ApprovalQueue
 *   (R1 NICE 修复:避免"功能已存在"错觉)
 *
 * 用 hash history(Tauri 打包 SPA 本地路径友好,避免 file:// 协议冲突)。
 */
const routes: RouteRecordRaw[] = [
  {
    // D19:默认落地 = Protection Overview(首屏即见"Vigil 拦下了什么",面向采用)。
    path: "/",
    redirect: "/protection",
  },
  // D19 — Protection Overview(= CLI inspect protection 的 GUI 等价物)
  {
    path: "/protection",
    name: "protection",
    component: () => import("@/pages/ProtectionOverview.vue"),
    meta: { title: "Protection Overview" },
  },
  {
    path: "/approvals",
    name: "approvals",
    component: () => import("@/pages/ApprovalQueue.vue"),
    meta: { title: "Approval Queue" },
  },
  {
    path: "/activity",
    name: "activity",
    component: () => import("@/pages/ActivityFeed.vue"),
    meta: { title: "Activity Feed" },
  },
  {
    path: "/servers",
    name: "servers",
    component: () => import("@/pages/ServerRegistry.vue"),
    meta: { title: "Server Registry" },
  },
  {
    path: "/sessions",
    name: "sessions",
    component: () => import("@/pages/SessionReplay.vue"),
    meta: { title: "Session Replay" },
  },
  // ISS-017 — Privacy Findings 聚合面板
  {
    path: "/privacy",
    name: "privacy",
    component: () => import("@/pages/PrivacyFindings.vue"),
    meta: { title: "Privacy Findings" },
  },
];

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
});
