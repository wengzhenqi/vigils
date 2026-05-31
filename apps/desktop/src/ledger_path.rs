//! I08b-β5 Ledger 磁盘持久化路径解析。
//!
//! 本模块在 **默认 feature**(非 gui)下也参与编译 + 测试,专门让 `cargo test --workspace`
//! 能守门 "GUI 持久化路径 + fail-closed" 的安全不变量 —— 避免 β1 R1 教训重演
//! ("关键安全变更却落在默认测试矩阵之外")。
//!
//! # 依赖注入(DI)理由
//!
//! `dirs::data_local_dir()` 是 OS 特定查询,仅 gui feature 下拉取(tauri transitive)。
//! 为让默认 feature 也能跑测试,把 OS 路径查询**结果**(而非查询函数)作参数传入:
//! ```ignore
//! use vigil_desktop::ledger_path::{resolve_ledger_path, LEDGER_ENV_VAR};
//!
//! // gui.rs 生产代码:
//! let env_value = std::env::var(LEDGER_ENV_VAR).ok();
//! let local_data = dirs::data_local_dir();
//! let path = resolve_ledger_path(env_value.as_deref(), local_data.as_deref())?;
//! ```
//! 测试传 `None` / `Some(tempdir)` 模拟 OS 分支,无需 dirs / gui feature。
//!
//! # 安全契约(ADR 0002 §I-2.1 审计不变量)
//!
//! - **Fail-closed**:任一步失败立即返 `LedgerPathError`,caller 应 `exit(1)` 不 fallback
//!   `open_in_memory`(审计链静默丢失等同失守)
//! - **错误脱敏**:`LedgerPathError` 不含 `std::io::Error` / 文件路径以外的环境细节
//!   (仅 `parent: PathBuf` 便于用户核对目标位置)

use std::path::{Path, PathBuf};

/// 环境变量名 —— `VIGIL_LEDGER_PATH`(非空即覆盖 OS 默认位置)。
///
/// **trust boundary**:启动进程与本进程同信任域,不作外部不可信输入;仅做"非空去空白"
/// 的最小格式化,不拒绝相对路径 / `..` 等(开发/测试/CI 可能需要)。
pub const LEDGER_ENV_VAR: &str = "VIGIL_LEDGER_PATH";

/// 默认目录名 —— `<local_data_dir>/<VIGIL_SUBDIR>/<LEDGER_FILENAME>`。
pub const VIGIL_SUBDIR: &str = "Vigil";
/// 默认文件名。
pub const LEDGER_FILENAME: &str = "ledger.sqlite3";

/// 路径解析 / 父目录创建失败的 fail-closed 错误。
#[derive(Debug)]
pub enum LedgerPathError {
    /// `local_data_dir` 参数为 `None`(生产侧 `dirs::data_local_dir()` 返 None,某些
    /// 最小化容器 / headless Linux 无 XDG_DATA_HOME 时可能发生)。
    MissingLocalDataDir,
    /// 父目录递归创建失败(权限 / 磁盘 / 路径非法)。
    /// 不透传 `io::Error` 原文避免环境细节泄漏。
    ParentDirCreateFailed {
        /// 实际尝试创建的父目录,给用户核对位置。
        parent: PathBuf,
    },
}

impl std::fmt::Display for LedgerPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingLocalDataDir => write!(
                f,
                "failed to locate OS local data directory (dirs::data_local_dir() 返 None;\
                 可设置 {LEDGER_ENV_VAR} 覆盖)"
            ),
            Self::ParentDirCreateFailed { parent } => write!(
                f,
                "failed to create parent directory for ledger at {} \
                 (权限 / 磁盘 / 路径非法)",
                parent.display()
            ),
        }
    }
}

impl std::error::Error for LedgerPathError {}

/// 解析 ledger 磁盘持久化路径。
///
/// 优先级:
/// 1. `env_override` 非 `None` 且 `trim()` 非空 → 用其 `trim()` 后值
/// 2. Fallback: `local_data_dir` 下 `Vigil/ledger.sqlite3`
///
/// 返回路径前,**保证父目录已存在**(失败返 `ParentDirCreateFailed`)。
///
/// # 参数
///
/// - `env_override`:`Some(raw_value)` 对应 `env::var(LEDGER_ENV_VAR).ok()` 的结果;
///   空串 / 纯空白视为"未设置",走 fallback
/// - `local_data_dir`:`Some(path)` 对应 `dirs::data_local_dir()`;
///   `None` 触发 `MissingLocalDataDir` fail-closed
pub fn resolve_ledger_path(
    env_override: Option<&str>,
    local_data_dir: Option<&Path>,
) -> Result<PathBuf, LedgerPathError> {
    // 1) env 覆盖(开发/测试/CI)
    if let Some(raw) = env_override {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            ensure_parent_dir(&path)?;
            return Ok(path);
        }
    }

    // 2) OS 默认
    let base = local_data_dir.ok_or(LedgerPathError::MissingLocalDataDir)?;
    let path = base.join(VIGIL_SUBDIR).join(LEDGER_FILENAME);
    ensure_parent_dir(&path)?;
    Ok(path)
}

/// 确保 `path` 的父目录存在(递归创建);失败仅返回"父目录创建失败"错误,不透传 io 文本。
fn ensure_parent_dir(path: &Path) -> Result<(), LedgerPathError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|_| {
                LedgerPathError::ParentDirCreateFailed {
                    parent: parent.to_path_buf(),
                }
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn env_override_takes_precedence_over_fallback() {
        let td = TempDir::new().unwrap();
        let base = td.path();
        let env_path = base.join("custom").join("my.db");

        // 环境变量胜出;fallback data_local 应被忽略
        let fallback_base = base.join("ignored");
        let resolved =
            resolve_ledger_path(Some(env_path.to_str().unwrap()), Some(&fallback_base)).unwrap();

        assert_eq!(resolved, env_path);
        assert!(base.join("custom").exists(), "env 路径的父目录必须已被创建");
        assert!(
            !base.join("ignored").exists(),
            "fallback 基目录不应被 env 路径触发创建"
        );
    }

    #[test]
    fn env_override_empty_or_whitespace_falls_back() {
        let td = TempDir::new().unwrap();
        let base = td.path();

        for empty in ["", "   ", "\t\n  "] {
            let resolved = resolve_ledger_path(Some(empty), Some(base)).unwrap();
            let expected = base.join(VIGIL_SUBDIR).join(LEDGER_FILENAME);
            assert_eq!(resolved, expected, "空/空白 env 必须走 fallback({empty:?})");
        }
    }

    #[test]
    fn env_override_trims_whitespace() {
        let td = TempDir::new().unwrap();
        let base = td.path();
        let env_path = base.join("custom.db");
        let padded = format!("   {}   ", env_path.to_str().unwrap());

        let resolved = resolve_ledger_path(Some(&padded), Some(base)).unwrap();
        assert_eq!(resolved, env_path, "前后空白应被 trim");
    }

    #[test]
    fn fallback_builds_vigil_subdir_under_local_data() {
        let td = TempDir::new().unwrap();
        let base = td.path();

        let resolved = resolve_ledger_path(None, Some(base)).unwrap();
        assert_eq!(resolved, base.join(VIGIL_SUBDIR).join(LEDGER_FILENAME));
        assert!(base.join(VIGIL_SUBDIR).is_dir(), "Vigil 子目录必须被创建");
    }

    #[test]
    fn missing_local_data_dir_without_env_fails_closed() {
        // env 未设 + data_local_dir None → MissingLocalDataDir
        match resolve_ledger_path(None, None) {
            Err(LedgerPathError::MissingLocalDataDir) => {}
            other => panic!("expected MissingLocalDataDir, got {other:?}"),
        }
    }

    #[test]
    fn empty_env_with_missing_data_dir_fails_closed() {
        // 空 env 视为未设,再 + data_local None → 同上 fail-closed
        match resolve_ledger_path(Some("   "), None) {
            Err(LedgerPathError::MissingLocalDataDir) => {}
            other => panic!("expected MissingLocalDataDir, got {other:?}"),
        }
    }

    #[test]
    fn parent_dir_create_failure_reports_parent_path() {
        // 在一个**文件**(非目录)下尝试建子路径的父目录,create_dir_all 必失败
        let td = TempDir::new().unwrap();
        let file_as_obstacle = td.path().join("blocker.txt");
        fs::write(&file_as_obstacle, b"blocking file").unwrap();

        let target = file_as_obstacle.join("sub").join("ledger.sqlite3");
        let err = resolve_ledger_path(Some(target.to_str().unwrap()), Some(td.path()))
            .expect_err("路径父目录不可建,应 fail-closed");

        match err {
            LedgerPathError::ParentDirCreateFailed { parent } => {
                assert_eq!(parent, target.parent().unwrap());
            }
            other => panic!("expected ParentDirCreateFailed, got {other:?}"),
        }
    }

    #[test]
    fn display_messages_redact_io_details() {
        // 错误 Display 不含 io::Error 原文,仅含稳定文案 + 路径
        let err = LedgerPathError::MissingLocalDataDir;
        let msg = format!("{err}");
        assert!(msg.contains(LEDGER_ENV_VAR), "提示应指引 env 覆盖");
        assert!(!msg.contains("os error"), "不应暴露 os error 原文");

        let err2 = LedgerPathError::ParentDirCreateFailed {
            parent: PathBuf::from("/tmp/xyz"),
        };
        let msg2 = format!("{err2}");
        assert!(msg2.contains("/tmp/xyz"), "提示应含目标父目录供排错");
        assert!(!msg2.contains("Permission denied"), "不透传 io 文本");
    }
}
