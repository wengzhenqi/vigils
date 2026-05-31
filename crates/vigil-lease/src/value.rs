//! `SecretValue`:真实 secret 值的零化包装。
//!
//! 不变量(ADR 0006 §I-6.2):`SecretValue::expose()` 是**唯一**真实值暴露点。
//! 本类型**不**派生 `Debug` / `Display`,防止 `println!("{v:?}")` 或 `{}` 插值泄漏。
//! `Drop` 通过 `Zeroizing<String>` 自动清零。

use zeroize::Zeroizing;

/// 真实 secret 值的零化容器。
///
/// 构造来源只能是 `SecretStore::get`(keychain)或测试代码。
/// 除了 [`SecretValue::expose`] 之外,没有其他访问裸值的途径。
///
/// **Debug**:只打印长度,**不**打印真实值(AGENTS.md §4)。手写以防派生宏被意外恢复。
pub struct SecretValue(Zeroizing<String>);

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretValue")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl SecretValue {
    /// 从字符串构造。仅供 store 实现和测试使用。
    ///
    /// 生产路径下,caller 应通过 `SecretStore::get` 取值,
    /// 避免手动持有真实 secret 字面量。
    pub fn new(s: impl Into<String>) -> Self {
        Self(Zeroizing::new(s.into()))
    }

    /// **唯一**的裸值访问点,命名故意显眼以提醒 caller 此操作敏感。
    ///
    /// 调用点应:
    /// 1. 紧邻注入目的地(如 `env.insert(k, v.expose())`)
    /// 2. 不要把返回的 `&str` 再 `.to_string()` 到外部作用域(会失去零化保证)
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// 返回字节长度(用于 redaction / audit 打印条件判断时不暴露内容)。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Clone for SecretValue {
    fn clone(&self) -> Self {
        // Zeroizing 没实现 Clone;手工 clone 内部 String 并重新包一层
        Self(Zeroizing::new(self.0.as_str().to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expose_returns_original_bytes() {
        let v = SecretValue::new("gh_pat_xxxxx");
        assert_eq!(v.expose(), "gh_pat_xxxxx");
        assert_eq!(v.len(), 12);
        assert!(!v.is_empty());
    }

    #[test]
    fn clone_preserves_value() {
        let v = SecretValue::new("abc");
        let v2 = v.clone();
        assert_eq!(v.expose(), v2.expose());
    }

    #[test]
    fn debug_does_not_leak_value() {
        let v = SecretValue::new("gh_pat_SUPERSECRET");
        let s = format!("{v:?}");
        assert!(
            !s.contains("SUPERSECRET"),
            "Debug 实现不得暴露真实值,实际 = {s}"
        );
        // 长度应出现(便于 diagnostic)
        assert!(s.contains("len"));
    }
}
