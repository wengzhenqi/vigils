/** @type {import('tailwindcss').Config} */
export default {
  // Tailwind 与 Naive UI 共存:Tailwind 作 utility 层,Naive UI 管组件内部样式。
  // **不启** Tailwind preflight 的强制 base reset,避免覆盖 Naive UI 默认样式。
  content: [
    "./index.html",
    "./src/**/*.{vue,ts,tsx}",
  ],
  // 禁 base preflight,留给 Naive UI 的 `n-global-style`
  corePlugins: {
    preflight: false,
  },
  theme: {
    extend: {
      // Vigil 品牌色(极简 — 深灰 + 警示橙,本地工具风格)
      colors: {
        vigil: {
          bg: "#0f1116",
          panel: "#1a1d24",
          border: "#2a2e38",
          text: "#e6e9ef",
          accent: "#e87818",
        },
      },
    },
  },
  plugins: [],
};
