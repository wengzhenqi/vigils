//! `SecretStore` trait + `InMemorySecretStore` + 可选 `KeyringSecretStore`。
//!
//! ADR 0006 §D1:trait 边界**只**管真实值读写,**不**含 lease / bound / 审批语义。

use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::SecretStoreError;
use crate::value::SecretValue;

/// 真实 secret 值的存储后端抽象。
pub trait SecretStore: Send + Sync {
    /// 写入(或覆盖)一个 secret。
    fn put(&self, secret_ref: &str, value: SecretValue) -> Result<(), SecretStoreError>;
    /// 读取一个 secret 的真实值。
    fn get(&self, secret_ref: &str) -> Result<SecretValue, SecretStoreError>;
    /// 删除一个 secret。
    fn delete(&self, secret_ref: &str) -> Result<(), SecretStoreError>;
    /// 后端标识(审计 / diagnostics 用,非敏感)。
    fn backend_kind(&self) -> &'static str;
}

/// 进程内 HashMap store —— I06 默认测试用。
///
/// 真实 secret 存在内存中,进程退出时 `Zeroizing` 自动清零。
#[derive(Default)]
pub struct InMemorySecretStore {
    inner: Mutex<HashMap<String, SecretValue>>,
}

impl std::fmt::Debug for InMemorySecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 不暴露 SecretValue(未派生 Debug),只打印容量 hint
        let len = self.inner.lock().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("InMemorySecretStore")
            .field("entries", &len)
            .finish_non_exhaustive()
    }
}

impl InMemorySecretStore {
    /// 新建空 store。
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for InMemorySecretStore {
    fn put(&self, secret_ref: &str, value: SecretValue) -> Result<(), SecretStoreError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| SecretStoreError::LockPoisoned)?;
        g.insert(secret_ref.to_string(), value);
        Ok(())
    }

    fn get(&self, secret_ref: &str) -> Result<SecretValue, SecretStoreError> {
        let g = self
            .inner
            .lock()
            .map_err(|_| SecretStoreError::LockPoisoned)?;
        g.get(secret_ref).cloned().ok_or(SecretStoreError::NotFound)
    }

    fn delete(&self, secret_ref: &str) -> Result<(), SecretStoreError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| SecretStoreError::LockPoisoned)?;
        g.remove(secret_ref)
            .map(|_| ())
            .ok_or(SecretStoreError::NotFound)
    }

    fn backend_kind(&self) -> &'static str {
        "memory"
    }
}

/// 基于 [`keyring`] crate 的 OS Keychain 适配。
///
/// 仅在 feature `os-keychain` 启用时编译。默认关,原因见 ADR 0006 §D1。
///
/// `service` 参数对应 keyring 的 service 标识(一般固定为 `"vigil"`);
/// `secret_ref` 作为 user 标识传入 keyring entry。
#[cfg(feature = "os-keychain")]
#[derive(Debug)]
pub struct KeyringSecretStore {
    service: String,
}

#[cfg(feature = "os-keychain")]
impl KeyringSecretStore {
    /// 新建 keyring-backed store。
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, secret_ref: &str) -> Result<keyring::Entry, SecretStoreError> {
        // Codex R1 BLOCKER-2:不把 keyring 错误原文传出,统一映射为 BackendUnavailable。
        keyring::Entry::new(&self.service, secret_ref)
            .map_err(|_| SecretStoreError::BackendUnavailable)
    }
}

#[cfg(feature = "os-keychain")]
fn map_keyring_err(err: keyring::Error) -> SecretStoreError {
    // 结构化映射;不落任何 `Display` 字符串到 caller / audit。
    match err {
        keyring::Error::NoEntry => SecretStoreError::NotFound,
        keyring::Error::PlatformFailure(_) | keyring::Error::NoStorageAccess(_) => {
            SecretStoreError::BackendUnavailable
        }
        keyring::Error::Ambiguous(_)
        | keyring::Error::BadEncoding(_)
        | keyring::Error::TooLong(_, _)
        | keyring::Error::Invalid(_, _) => SecretStoreError::BackendOther,
        _ => SecretStoreError::BackendOther,
    }
}

#[cfg(feature = "os-keychain")]
impl SecretStore for KeyringSecretStore {
    fn put(&self, secret_ref: &str, value: SecretValue) -> Result<(), SecretStoreError> {
        self.entry(secret_ref)?
            .set_password(value.expose())
            .map_err(map_keyring_err)
    }

    fn get(&self, secret_ref: &str) -> Result<SecretValue, SecretStoreError> {
        self.entry(secret_ref)?
            .get_password()
            .map(SecretValue::new)
            .map_err(map_keyring_err)
    }

    fn delete(&self, secret_ref: &str) -> Result<(), SecretStoreError> {
        self.entry(secret_ref)?
            .delete_credential()
            .map_err(map_keyring_err)
    }

    fn backend_kind(&self) -> &'static str {
        "keyring"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_put_get_delete_roundtrip() {
        let s = InMemorySecretStore::new();
        s.put("secret://gh/rw", SecretValue::new("tok_xxx"))
            .unwrap();
        assert_eq!(s.get("secret://gh/rw").unwrap().expose(), "tok_xxx");
        s.delete("secret://gh/rw").unwrap();
        assert!(matches!(
            s.get("secret://gh/rw"),
            Err(SecretStoreError::NotFound)
        ));
    }

    #[test]
    fn in_memory_delete_missing_returns_not_found() {
        let s = InMemorySecretStore::new();
        assert!(matches!(
            s.delete("secret://nope"),
            Err(SecretStoreError::NotFound)
        ));
    }

    #[test]
    fn in_memory_backend_kind_is_memory() {
        assert_eq!(InMemorySecretStore::new().backend_kind(), "memory");
    }
}
