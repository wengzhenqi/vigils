//! ExecutionPlan / SandboxProfile / RunnerKind(ADR 0007 §D3)。
//!
//! 预检规则(ADR 0007 §I-7.2):`ExecutionPlan::validate` 必须在任何 spawn 前调用,
//! 对 cwd / read_dirs / write_dirs 做 canonicalize + allowlist 检查。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{RejectField, RunnerError};

/// Wasm 或 Native。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RunnerKind {
    /// WebAssembly + WASI preopen(强隔离,全平台一致)。
    Wasm,
    /// 原生子进程(env_clear + cwd + timeout + capture;Linux Landlock 延 I07.5)。
    Native,
}

/// Wasm / Native 专属字段。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RunnerSpecific {
    /// Wasm 专属限制。
    Wasm {
        /// wasmtime fuel 预算(大致对应 wasm 指令数)
        fuel_units: u64,
        /// epoch 硬截止(毫秒);0 表示不启用
        epoch_deadline_ms: u64,
    },
    /// Native 专属(I07 为占位;I07.5 扩 rlimit)。
    Native {
        /// 预留 rlimit 枚举槽(Linux I07.5 激活)
        #[serde(default)]
        rlimit_placeholder: Option<String>,
    },
}

/// 沙盒策略(主方案 §8.6)。**不含**真实 env 值(只含 env key metadata)。
///
/// I07:内存态,JSON round-trip;持久化延 I08。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxProfile {
    /// profile id(UI / approval 卡片展示)
    pub id: String,
    /// 允许读取的目录(runner 在此之外读 → Rejected)
    pub read_dirs: Vec<PathBuf>,
    /// 允许写入的目录
    pub write_dirs: Vec<PathBuf>,
    /// 允许的网络 host(I07 仅记录;真网络隔离 I07.5/I08)
    pub allow_hosts: Vec<String>,
    /// env 是否继承父进程 —— **必须 false**(AGENTS §7)
    pub env_inherit: bool,
    /// wall timeout(毫秒)
    pub wall_ms: u64,
    /// wasm 内存上限(MB);native 仅记录
    pub memory_mb: u32,
}

impl SandboxProfile {
    /// 构造时强制校验 `env_inherit == false`(ADR §I-7.3 的 compile-time 等价检查)。
    pub fn new(
        id: impl Into<String>,
        read_dirs: Vec<PathBuf>,
        write_dirs: Vec<PathBuf>,
        wall_ms: u64,
    ) -> Self {
        Self {
            id: id.into(),
            read_dirs,
            write_dirs,
            allow_hosts: Vec::new(),
            env_inherit: false,
            wall_ms,
            memory_mb: 64,
        }
    }
}

/// 统一执行计划(ADR 0007 §D3)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPlan {
    /// runner 类型
    pub runner_kind: RunnerKind,
    /// 子进程 / wasm instance 的工作目录(必须在 read_dirs 内)
    pub cwd: PathBuf,
    /// 允许读取的目录(canonicalized;含 cwd)
    pub read_dirs: Vec<PathBuf>,
    /// 允许写入的目录
    pub write_dirs: Vec<PathBuf>,
    /// 允许的网络 host(I07 仅记录)
    pub allowed_hosts: Vec<String>,
    /// 此 plan 需要的 secret alias 清单(真值不在此处,由 PreparedChildEnv 提供)
    pub env_leases: Vec<String>,
    /// 软 CPU budget(毫秒;I07 仅记录)
    pub cpu_ms: u64,
    /// 硬 wall 超时(毫秒)—— runner 真正使用
    pub wall_ms: u64,
    /// 内存上限(MB;wasm 用 fuel 换算,native 仅记录)
    pub memory_mb: u32,
    /// 是否捕获 stdout
    pub capture_stdout: bool,
    /// 是否捕获 stderr
    pub capture_stderr: bool,
    /// runner 专属字段
    pub runner_specific: RunnerSpecific,
}

impl ExecutionPlan {
    /// 预检:canonicalize cwd,并要求 cwd 在 read_dirs 任一条目下。
    /// 所有 read_dirs / write_dirs 自身也必须能 canonicalize(存在 + 可访问)。
    ///
    /// 失败返 `RunnerError::Rejected`,caller **必须**产 `runner.rejected` 审计事件。
    pub fn validate(&mut self) -> Result<(), RunnerError> {
        // 规范化路径(Windows 用 dunce,避免 \\?\ 前缀不一致)
        self.cwd = canonicalize(&self.cwd, RejectField::Cwd)?;
        for d in self.read_dirs.iter_mut() {
            *d = canonicalize(d, RejectField::ReadDir)?;
        }
        for d in self.write_dirs.iter_mut() {
            *d = canonicalize(d, RejectField::WriteDir)?;
        }

        // cwd 必须在 read_dirs 之一下
        if !path_within_any(&self.cwd, &self.read_dirs) {
            return Err(RunnerError::Rejected {
                field: RejectField::Cwd,
                reason_code: "cwd_outside_read_dirs",
            });
        }
        // write_dirs 必须是 read_dirs 的子集(写即读;禁止"写而不可读"的诡异组合)
        for w in &self.write_dirs {
            if !path_within_any(w, &self.read_dirs) {
                return Err(RunnerError::Rejected {
                    field: RejectField::WriteDir,
                    reason_code: "write_dir_outside_read_dirs",
                });
            }
        }
        // wall_ms 必须为正
        if self.wall_ms == 0 {
            return Err(RunnerError::Rejected {
                field: RejectField::Runner,
                reason_code: "wall_ms_zero",
            });
        }
        Ok(())
    }

    /// 便捷构造:从 SandboxProfile + argv 生成 Native 计划。
    pub fn native_from_profile(profile: &SandboxProfile, cwd: PathBuf) -> Self {
        Self {
            runner_kind: RunnerKind::Native,
            cwd,
            read_dirs: profile.read_dirs.clone(),
            write_dirs: profile.write_dirs.clone(),
            allowed_hosts: profile.allow_hosts.clone(),
            env_leases: Vec::new(),
            cpu_ms: 0,
            wall_ms: profile.wall_ms,
            memory_mb: profile.memory_mb,
            capture_stdout: true,
            capture_stderr: true,
            runner_specific: RunnerSpecific::Native {
                rlimit_placeholder: None,
            },
        }
    }

    /// 便捷构造:从 SandboxProfile 生成 Wasm 计划。
    pub fn wasm_from_profile(profile: &SandboxProfile, cwd: PathBuf) -> Self {
        Self {
            runner_kind: RunnerKind::Wasm,
            cwd,
            read_dirs: profile.read_dirs.clone(),
            write_dirs: profile.write_dirs.clone(),
            allowed_hosts: profile.allow_hosts.clone(),
            env_leases: Vec::new(),
            cpu_ms: 0,
            wall_ms: profile.wall_ms,
            memory_mb: profile.memory_mb,
            capture_stdout: true,
            capture_stderr: true,
            runner_specific: RunnerSpecific::Wasm {
                fuel_units: (profile.memory_mb as u64) * 1_000_000,
                epoch_deadline_ms: profile.wall_ms,
            },
        }
    }
}

fn canonicalize(p: &Path, field: RejectField) -> Result<PathBuf, RunnerError> {
    // dunce::canonicalize 在 Windows 返回不带 `\\?\` 前缀的形式,避免后续 starts_with 比较漂移
    dunce::canonicalize(p).map_err(|_| RunnerError::Rejected {
        field,
        reason_code: "canonicalize_failed",
    })
}

fn path_within_any(p: &Path, allowlist: &[PathBuf]) -> bool {
    allowlist.iter().any(|a| p.starts_with(a))
}

/// 一次执行的结果(stdout / stderr 已**脱敏**)。
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// 退出码;若被 timeout kill 则为 None
    pub exit_code: Option<i32>,
    /// 实际墙钟耗时(毫秒)
    pub wall_elapsed_ms: u64,
    /// 已脱敏的 stdout(line-by-line 过 scrub)
    pub stdout: Vec<u8>,
    /// 已脱敏的 stderr
    pub stderr: Vec<u8>,
    /// **ISS-020**:post-exec leak 二次扫描标记。`scrub_text` 漏掉(跨行
    /// secret / 攻击者构造的 lookalike placeholder 等)→ `scan_hard_findings`
    /// 命中 → 标 true。caller(ISS-019 Tauri embed Hub)应禁止后续 tool 读取
    /// 本 result 的 stdout/stderr,但 runner 层不做访问控制本身。
    pub quarantined: bool,
    /// **ISS-020**:命中的 hard rule names(stdout + stderr 合并去重,**保
    /// `vigil_redaction::HARD_RULES` 全局声明顺序**,即 aws / github / anthropic /
    /// openai / pem / jwt / env_assignment / slack / stripe / google / gitlab /
    /// database_url 子序列);`quarantined=false` 时为空 Vec。
    pub leak_findings: Vec<&'static str>,
}

impl Default for ExecutionResult {
    /// 测试默认值:空输出 + 未 quarantine。生产路径不应走 Default,而是由
    /// `spawn_native` / `WasmRunner::run` 完整构造。
    fn default() -> Self {
        Self {
            exit_code: None,
            wall_elapsed_ms: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            quarantined: false,
            leak_findings: Vec::new(),
        }
    }
}
