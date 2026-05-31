//! Native spawn backend(ADR 0007 §D4):统一 env_clear + cwd + capture + timeout。
//!
//! I04 `StdioUpstream::spawn` 和 I07 一次性 runner 都应走这里,避免双份安全边界漂移。
//!
//! 安全不变量:
//! - §I-7.1:Native spawn 必须走这个 backend
//! - §I-7.3:`take_env()` 与 `Command::envs()` 之间**不得**插入 log/Debug/audit
//! - §I-7.4:stdout/stderr 读到一行立即 `scrub` 再 append;原始 bytes 不持久化

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use vigil_lease::PreparedChildEnv;

use vigil_runner_types::{
    apply_native_env_policy, ExecutionPlan, ExecutionResult, RejectField, RunnerAuditSink,
    RunnerError, RunnerEvent, RunnerKind, ScrubCallback,
};

// ADR 0018 v0.13 split:`ScrubCallback` / `RESERVED_SYSTEM_ENV_KEYS` /
// `is_reserved_env_key` / `apply_native_env_policy` 已移至 `vigil-runner-types`。
// 本 crate 通过 `pub use vigil_runner_types::*`(见 lib.rs)继续 re-export 给
// downstream consumer 用,backward compat 保持。
//
// `default_scrub` 留本 crate(依赖 `vigil_redaction::scrub_text`,types crate 不引
// vigil-redaction)。

/// 返回默认 scrub callback(vigil-redaction 硬指纹脱敏)。
pub fn default_scrub() -> ScrubCallback {
    Arc::new(vigil_redaction::scrub_text)
}

/// Native spawn 的入口。此函数是 `async`,需在 tokio runtime 内调用。
///
/// **消费语义**:`prepared` 在函数内被 `take_env()`,值的暴露面限定在
/// 紧邻 `Command::envs()` 调用的几行内(§I-7.3)。函数返回后 `prepared`
/// 被 drop,自动 revoke lease(§I-7.6 / I06 契约)。
///
/// 失败语义:
/// - 预检失败 → caller 应先调 `plan.validate()`(本函数不重复做)
/// - 已配 binary 无法 spawn → `RunnerError::Io { phase: "spawn" }`
/// - wall_ms 耗尽 → `RunnerError::Timeout`,子进程被 kill
/// - stdout/stderr pipe 故障 → `RunnerError::Io { phase: "stdout_read" / "stderr_read" }`
pub async fn spawn_native(
    plan: &ExecutionPlan,
    argv: &[String],
    mut prepared: PreparedChildEnv,
    scrub: &ScrubCallback,
    audit: &dyn RunnerAuditSink,
) -> Result<ExecutionResult, RunnerError> {
    // 预检:写 rejected 事件
    if plan.runner_kind != RunnerKind::Native {
        let e = RunnerError::Rejected {
            field: RejectField::Runner,
            reason_code: "plan_runner_kind_not_native",
        };
        emit_rejected(audit, &e);
        return Err(e);
    }
    if argv.is_empty() {
        let e = RunnerError::Rejected {
            field: RejectField::Argv,
            reason_code: "argv_empty",
        };
        emit_rejected(audit, &e);
        return Err(e);
    }

    let mut cmd = Command::new(&argv[0]);
    for a in &argv[1..] {
        cmd.arg(a);
    }
    cmd.current_dir(&plan.cwd);

    // I07.5+ (ADR 0007 §I-7.1):env 政策通过共享 helper `apply_native_env_policy` 统一
    // 应用 —— env_clear + Windows SystemRoot 注入 + user env。StdioUpstream::spawn 走
    // 同一 helper,消除历史漂移。§I-7.3 合规:take_env() 调用与 helper 之间无其他语句。
    let user_env = prepared.take_env().unwrap_or_default();
    apply_native_env_policy(cmd.as_std_mut(), user_env);

    // I07.5(ADR 0007 §8.6):Linux Landlock 注入 —— 把 SandboxProfile 的
    // read_dirs/write_dirs 编译成 kernel-enforced 白名单,子进程 exec 前自我限制。
    //
    // **决策边界**:
    // - 仅 Linux 目标生效(cfg gate);其他 OS 沿用 env_clear + cwd + timeout 原线。
    // - 内核不支持 Landlock(< 5.13 或未启 LSM)→ `LandlockError::NotSupported`,
    //   本 runner **fail-closed 拒绝 spawn**(不降级为"无 Landlock 照常 spawn")。
    // - `SandboxProfile.write_dirs` 同时授权读写;`read_dirs` 只授权读。
    // - 路径 canonicalize 由 `plan.validate()` 在本函数外保证(预检);这里只信任输入。
    //
    // Windows / macOS 构建:`vigil-sandbox-linux` 是 target-gated dep,不编译,
    // `#[cfg(target_os = "linux")]` 整块代码被优化掉,零运行时开销。
    #[cfg(target_os = "linux")]
    {
        use vigil_sandbox_linux::{LandlockError, LandlockPolicy};

        let policy = LandlockPolicy::from_dirs(
            plan.read_dirs.iter().cloned(),
            plan.write_dirs.iter().cloned(),
        );
        if let Err(err) = policy.install_into(cmd.as_std_mut()) {
            // I07.5 R2 BLOCKER 3 修复:`LandlockError` 是 `#[non_exhaustive]`,
            // fail-closed `_` 分支保证未来新增变体不破坏审计契约
            let reason_code = match err {
                LandlockError::NotSupported => "landlock_kernel_unsupported",
                LandlockError::PathOpenFailed(_) => "landlock_path_open_failed",
                LandlockError::RulesetBuildFailed { .. } => "landlock_ruleset_build_failed",
                _ => "landlock_unknown_install_error",
            };
            let e = RunnerError::Rejected {
                field: RejectField::Sandbox,
                reason_code,
            };
            emit_rejected(audit, &e);
            return Err(e);
        }
    }
    if plan.capture_stdout {
        cmd.stdout(Stdio::piped());
    } else {
        cmd.stdout(Stdio::null());
    }
    if plan.capture_stderr {
        cmd.stderr(Stdio::piped());
    } else {
        cmd.stderr(Stdio::null());
    }
    cmd.stdin(Stdio::null());
    cmd.kill_on_drop(true);

    let start = Instant::now();
    let env_keys: Vec<String> = cmd
        .as_std()
        .get_envs()
        .filter_map(|(k, _)| k.to_str().map(String::from))
        .collect();
    let cwd_str = plan.cwd.to_string_lossy().to_string();

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(err) => {
            // I07.5 R2 BLOCKER 1 修复:区分 landlock pre_exec 失败 vs 通用 spawn 失败。
            // landlock 的 restrict_self 失败通过 pre_exec 返回 `io::Error(EPROTO)`,
            // `Command::spawn` 透传此 errno。若匹配,映射到 `Rejected { Sandbox }` 以符合
            // fail-closed 审计契约;其他原因走原有 `command_spawn_failed` IO 路径。
            #[cfg(target_os = "linux")]
            if err.raw_os_error() == Some(vigil_sandbox_linux::LANDLOCK_PRE_EXEC_ERRNO) {
                let e = RunnerError::Rejected {
                    field: RejectField::Sandbox,
                    reason_code: "landlock_restrict_self_failed",
                };
                emit_rejected(audit, &e);
                return Err(e);
            }
            let _ = err; // 非 Linux 或非 EPROTO:忽略具体原因,走通用 IO 失败
            let e = RunnerError::Io {
                phase: "spawn",
                reason_code: "command_spawn_failed",
            };
            audit.emit(RunnerEvent::IoError {
                phase: "spawn",
                reason_code: "command_spawn_failed",
            });
            return Err(e);
        }
    };

    // spawn 成功 → started 事件
    audit.emit(RunnerEvent::Started {
        runner_kind: "Native",
        server_id: None,
        wall_ms: plan.wall_ms,
        env_keys: &env_keys,
        cwd: &cwd_str,
    });

    // 启动 capture 任务
    let stdout_task = child.stdout.take().map(|s| {
        let scrub = scrub.clone();
        tokio::spawn(async move { capture_stream(s, scrub).await })
    });
    let stderr_task = child.stderr.take().map(|s| {
        let scrub = scrub.clone();
        tokio::spawn(async move { capture_stream(s, scrub).await })
    });

    // wall timeout + wait
    let wait_fut = child.wait();
    let status = match tokio::time::timeout(
        std::time::Duration::from_millis(plan.wall_ms),
        wait_fut,
    )
    .await
    {
        Ok(Ok(status)) => Some(status),
        Ok(Err(_)) => {
            audit.emit(RunnerEvent::IoError {
                phase: "wait",
                reason_code: "child_wait_failed",
            });
            return Err(RunnerError::Io {
                phase: "wait",
                reason_code: "child_wait_failed",
            });
        }
        Err(_elapsed) => {
            // timeout:kill_on_drop 在 child drop 时会 SIGKILL;这里显式 kill 更快。
            // capture task 在 pipe 关闭时可能返 Io 错误,但 Timeout 是主错误,忽略 capture 的 IO 失败。
            let _ = child.start_kill();
            let _ = child.wait().await;
            if let Some(t) = stdout_task {
                let _ = t.await;
            }
            if let Some(t) = stderr_task {
                let _ = t.await;
            }
            audit.emit(RunnerEvent::KilledByTimeout {
                wall_ms: plan.wall_ms,
            });
            return Err(RunnerError::Timeout {
                wall_ms: plan.wall_ms,
            });
        }
    };

    // 收集 capture(R2 MUST-FIX 2:Err(Io) 路径也要 audit.emit)
    let stdout = match stdout_task {
        Some(t) => match t.await {
            Ok(Ok(b)) => b,
            Ok(Err(RunnerError::Io { phase, reason_code })) => {
                audit.emit(RunnerEvent::IoError { phase, reason_code });
                return Err(RunnerError::Io { phase, reason_code });
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(RunnerError::Internal("stdout_task_join_failed")),
        },
        None => Vec::new(),
    };
    let stderr = match stderr_task {
        Some(t) => match t.await {
            Ok(Ok(b)) => b,
            Ok(Err(RunnerError::Io { phase, reason_code })) => {
                audit.emit(RunnerEvent::IoError { phase, reason_code });
                return Err(RunnerError::Io { phase, reason_code });
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(RunnerError::Internal("stderr_task_join_failed")),
        },
        None => Vec::new(),
    };
    let wall_elapsed_ms = start.elapsed().as_millis() as u64;
    let exit_code = status.and_then(|s| s.code());

    // ISS-020:post-exec leak hook —— 在已脱敏 stdout/stderr 上二次扫硬指纹,
    // 命中则标 quarantined + emit LeakDetected(分源)。out-of-band,不改字节。
    let (quarantined, leak_findings) =
        crate::leak_scan::post_exec_leak_scan(&stdout, &stderr, audit);

    audit.emit(RunnerEvent::Completed {
        exit_code,
        wall_elapsed_ms,
        stdout_bytes: stdout.len(),
        stderr_bytes: stderr.len(),
    });

    Ok(ExecutionResult {
        exit_code,
        wall_elapsed_ms,
        stdout,
        stderr,
        quarantined,
        leak_findings,
    })
}

fn emit_rejected(audit: &dyn RunnerAuditSink, err: &RunnerError) {
    if let RunnerError::Rejected { field, reason_code } = err {
        audit.emit(RunnerEvent::Rejected {
            field: *field,
            reason_code,
        });
    }
}

/// Line-by-line capture + 最早处 scrub。
///
/// **语义**(Codex R1 NICE-TO-HAVE 修正):
/// - `Ok(None)` = 正常 EOF(pipe 关闭) → 返回已累积 bytes
/// - `Err(BrokenPipe / ConnectionAborted / UnexpectedEof)` = 子进程结束/被 kill
///   触发的 pipe 断开,这**不是** runner 错误 → 尽力返回已累积,main flow 的 wait
///   结果决定 final error(正常退出 / timeout / crash)
/// - `Err(其他 io::ErrorKind)` = 真正的读错 → 上抛 `RunnerError::Io`,由 main flow
///   决定是否覆盖 wait 的 status(当前实现:main flow 在正常 exit 分支会返回这个 Io;
///   timeout 分支仍以 Timeout 为主错误,吞掉 capture 的 Io)
///
/// 这避免了"把子进程结束的 pipe 关闭误报成 IO 错误"(R1 NICE-TO-HAVE 问题),
/// 同时保留了真正 read 故障的可见性。
async fn capture_stream<R>(reader: R, scrub: ScrubCallback) -> Result<Vec<u8>, RunnerError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut lines = BufReader::new(reader).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                // §I-7.4:read → scrub → buffer(不写 trace,不写 audit raw)
                let cleaned = scrub(&line);
                buf.extend_from_slice(cleaned.as_bytes());
                buf.push(b'\n');
            }
            Ok(None) => break, // 正常 EOF
            Err(e) => {
                use std::io::ErrorKind::*;
                match e.kind() {
                    BrokenPipe | ConnectionAborted | UnexpectedEof => break, // 子进程结束
                    _ => {
                        return Err(RunnerError::Io {
                            phase: "read_line",
                            reason_code: "stream_read_failed",
                        })
                    }
                }
            }
        }
    }
    Ok(buf)
}

/// 可选:为 `ExecutionPlan` + argv 做 plan-level 预检(路径已经 validate;这里只校验 argv)。
pub fn prescreen_native(plan: &ExecutionPlan, argv: &[String]) -> Result<(), RunnerError> {
    if plan.runner_kind != RunnerKind::Native {
        return Err(RunnerError::Rejected {
            field: RejectField::Runner,
            reason_code: "plan_runner_kind_not_native",
        });
    }
    if argv.is_empty() {
        return Err(RunnerError::Rejected {
            field: RejectField::Argv,
            reason_code: "argv_empty",
        });
    }
    // 禁止 binary 位于 write_dirs(简单启发:防止 download-then-execute)
    if let Some(bin) = argv.first() {
        let bin_path = PathBuf::from(bin);
        if plan.write_dirs.iter().any(|d| bin_path.starts_with(d)) {
            return Err(RunnerError::Rejected {
                field: RejectField::Argv,
                reason_code: "binary_inside_write_dir",
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I07.5+ helper 烟雾测试:`apply_native_env_policy` 正确注入 user env,
    /// 且 env_clear 先于 envs(user 注入在最后)。
    #[test]
    fn apply_native_env_policy_injects_user_env_after_clear() {
        let mut cmd = std::process::Command::new("dummy");
        // 预置一个 env 看是否会被 clear
        cmd.env("PRE_EXISTING_KEY", "preexisting_value");

        let user_env = vec![
            ("USER_KEY_A".to_string(), "val_a".to_string()),
            ("USER_KEY_B".to_string(), "val_b".to_string()),
        ];
        apply_native_env_policy(&mut cmd, user_env);

        let envs: std::collections::HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
            .collect();

        // env_clear 清掉预置键
        assert!(
            !envs.contains_key("PRE_EXISTING_KEY"),
            "env_clear 应清除预置 env",
        );
        // user env 存在
        assert_eq!(envs.get("USER_KEY_A").map(|s| s.as_str()), Some("val_a"));
        assert_eq!(envs.get("USER_KEY_B").map(|s| s.as_str()), Some("val_b"));
    }

    /// I07.5+ helper Windows 专有:`RESERVED_SYSTEM_ENV_KEYS` 在 env_clear 后被注入,
    /// 允许 cmd.exe / System32 DLL 正常解析。
    #[cfg(windows)]
    #[test]
    fn apply_native_env_policy_injects_windows_system_root() {
        // 若系统无 SystemRoot(极罕见),跳过(Windows 正常环境一定有)
        if std::env::var("SystemRoot").is_err() {
            return;
        }
        let mut cmd = std::process::Command::new("dummy");
        apply_native_env_policy(&mut cmd, std::iter::empty::<(String, String)>());
        let envs: std::collections::HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
            .collect();
        // `RESERVED_SYSTEM_ENV_KEYS` 包含 SystemRoot 及其大小写变体 —— 至少其中一个被注入
        // (`std::env::var` 在 Windows 上大小写不敏感,但 cmd.env 是精确 key,所以只注入
        // 真实存在于父进程 env 的那个变体)
        let has_any_systemroot = envs
            .keys()
            .any(|k| k.eq_ignore_ascii_case("SystemRoot") || k.eq_ignore_ascii_case("windir"));
        assert!(
            has_any_systemroot,
            "Windows 下应注入至少一个 SystemRoot 变体,实际 keys={:?}",
            envs.keys().collect::<Vec<_>>()
        );
    }

    /// I07.5+ helper 用户 env 优先级最高:即使与 `RESERVED_SYSTEM_ENV_KEYS` 同名,
    /// user env 后注入,覆盖 system 值。(registry 层已拒绝此类 binding,这是
    /// defense-in-depth 测试)
    #[cfg(windows)]
    #[test]
    fn apply_native_env_policy_user_env_overrides_system_keys() {
        if std::env::var("SystemRoot").is_err() {
            return;
        }
        let mut cmd = std::process::Command::new("dummy");
        // 用户故意用 SystemRoot 作为 key(registry 正常应拒绝,此处模拟 registry 漏检)
        let user_env = vec![("SystemRoot".to_string(), "C:\\USER_OVERRIDE".to_string())];
        apply_native_env_policy(&mut cmd, user_env);
        let envs: std::collections::HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
            .collect();
        assert_eq!(
            envs.get("SystemRoot").map(|s| s.as_str()),
            Some("C:\\USER_OVERRIDE"),
            "user env 必须压倒 system 保留键(defense-in-depth)"
        );
    }
}
