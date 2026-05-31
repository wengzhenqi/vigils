/* I08b-α1 ESLint 严格规则 — UI 安全不变量第一道守门(AGENTS.md + ADR 0008)。
 *
 * 关键规则:
 * - `vue/no-v-html: error` —— 禁 v-html,杜绝 XSS 注入面
 * - `security/detect-object-injection: warn` —— 对象字面量索引提醒
 * - `@typescript-eslint/no-explicit-any: warn` —— 逼近 type safety
 *
 * 原则:**禁止把用户数据当 HTML 渲染**;所有 payload 只能通过 `{{ }}` / `<pre>` / v-text。
 */
module.exports = {
  root: true,
  env: {
    browser: true,
    es2022: true,
    node: true,
  },
  extends: [
    "eslint:recommended",
    "plugin:vue/vue3-recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:security/recommended-legacy",
  ],
  parser: "vue-eslint-parser",
  parserOptions: {
    parser: "@typescript-eslint/parser",
    ecmaVersion: 2022,
    sourceType: "module",
  },
  plugins: ["@typescript-eslint", "vue", "security"],
  rules: {
    // XSS 防线 — 非绿意
    "vue/no-v-html": "error",
    "vue/no-v-text-v-html-on-component": "error",
    // TS 严格化
    "@typescript-eslint/no-explicit-any": "warn",
    "@typescript-eslint/no-unused-vars": [
      "warn",
      { argsIgnorePattern: "^_" },
    ],
    // Vue 代码风格
    "vue/multi-word-component-names": "off", // 允许 App.vue 这种单词
  },
  overrides: [
    {
      files: ["*.test.ts", "tests/**/*.ts"],
      rules: {
        "@typescript-eslint/no-explicit-any": "off",
      },
    },
  ],
};
