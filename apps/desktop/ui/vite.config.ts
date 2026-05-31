import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import path from "node:path";

// Tauri 2 + Vite 集成:
//   - 固定端口 1420(tauri.conf.json devUrl 同步)
//   - strictPort 避免端口漂移 → Tauri 找不到
//   - clearScreen false 保留 rustc / tauri 日志
//   - HMR host 0.0.0.0 供远程调试
//
// **安全契约**(AGENTS.md + ADR 0008):
//   - 不启任何跨域转发(dev server 仅本机)
//   - 严禁加 proxy 把 UI 流量代理到外网
export default defineConfig({
  plugins: [vue()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: process.env.TAURI_DEV_HOST || "localhost",
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  envPrefix: ["VITE_", "TAURI_ENV_*"],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  build: {
    target: "es2021",
    minify: "esbuild",
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    globals: true,
  },
});
