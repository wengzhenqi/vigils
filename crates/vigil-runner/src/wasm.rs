//! Wasm runner(wasmtime + WASI preopen)—— ADR 0007 §D1。
//!
//! 严格不变量:
//! - 默认 `inherit_env = false`(§I-7.5)
//! - 默认 network = off(WASI 标准行为,不 preopen socket)
//! - fuel + epoch 双限制,保证即使无限循环也能在 wall_ms 内被中断
//! - preopen 只给 `plan.read_dirs`;write 必须在 `plan.write_dirs` 交集内(wasm 侧由 WASI rights 管)

use std::sync::Arc;
use std::time::{Duration, Instant};

use wasmtime::{Config, Engine, Linker, Module, Store};
// v0.12 P1(2026-05-13)wasmtime 25 → 41 升级:
// - `wasmtime_wasi::preview1::*` → `wasmtime_wasi::p1::*`(短形式命名,p0/p1/p2/p3 对齐 WASI 标准版本)
// - `wasmtime_wasi::pipe::MemoryOutputPipe` → `wasmtime_wasi::p2::pipe::MemoryOutputPipe`(pipe 移到 p2 命名空间)
// - WasiCtxBuilder/DirPerms/FilePerms 仍在 root re-export(`pub use`),无需改
use wasmtime_wasi::p1::{add_to_linker_sync, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtxBuilder};

use vigil_runner_types::{
    ExecutionPlan, ExecutionResult, RejectField, RunnerAuditSink, RunnerError, RunnerEvent,
    RunnerKind, RunnerSpecific, ScrubCallback,
};

/// WasmRunner:对单个 `.wasm` 模块运行一次。
///
/// **Codex R1 BLOCKER 修复**:`Engine` 不再被 runner 复用,每次 `run()` 独立构造。
/// 原因:epoch bumper 是分离线程(`std::thread::spawn + sleep`),无法取消;
/// 若 Engine 复用,上一次的 bumper 会在 wall_ms 后对同一 Engine 调
/// `increment_epoch()`,打断后续 run 的 guest。独立 Engine 让 bumper 的 epoch
/// 只作用于它自己那次 run(Engine drop 后,bumper 持有 clone 的 Engine 自身,
/// increment 到被 drop 的 epoch 池无副作用)。
pub struct WasmRunner {
    scrub: ScrubCallback,
}

impl std::fmt::Debug for WasmRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmRunner").finish_non_exhaustive()
    }
}

impl WasmRunner {
    /// 构造。`scrub` 通常用 [`crate::default_scrub`]。
    pub fn new(scrub: ScrubCallback) -> Result<Self, RunnerError> {
        Ok(Self { scrub })
    }

    /// 每次 run 用的独立 Engine 工厂。
    fn build_engine() -> Result<Engine, RunnerError> {
        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        cfg.epoch_interruption(true);
        Engine::new(&cfg).map_err(|_| RunnerError::Internal("wasm_engine_init"))
    }

    /// 运行 `wasm_bytes`(可以是 `.wasm` 或 `.wat` 文本;wasmtime 接受两者)。
    ///
    /// 调用 `_start`(WASI command entry point)。
    /// stdout/stderr 通过 pipe 捕获,read 后每行 scrub。
    ///
    /// 失败语义:
    /// - `RunnerError::Rejected` — plan kind 不是 Wasm / fuel/epoch 配置异常
    /// - `RunnerError::Timeout` — wall_ms 到期被 epoch 中断 / fuel 耗尽
    /// - `RunnerError::WasmTrap(msg)` — guest trap(msg 已 scrub)
    /// - `RunnerError::Io` — WASI context 创建或 preopen 失败
    pub fn run(
        &self,
        plan: &ExecutionPlan,
        wasm_bytes: &[u8],
        audit: &dyn RunnerAuditSink,
    ) -> Result<ExecutionResult, RunnerError> {
        if plan.runner_kind != RunnerKind::Wasm {
            let e = RunnerError::Rejected {
                field: RejectField::Runner,
                reason_code: "plan_runner_kind_not_wasm",
            };
            emit_rejected(audit, &e);
            return Err(e);
        }
        let (fuel, epoch_deadline_ms) = match plan.runner_specific {
            RunnerSpecific::Wasm {
                fuel_units,
                epoch_deadline_ms,
            } => (fuel_units, epoch_deadline_ms),
            // ADR 0018:`RunnerSpecific` 现来自 vigil-runner-types,#[non_exhaustive]
            // 在跨 crate 时强制 `_` wildcard;Native + 任何未来加项都按非-Wasm 拒绝。
            _ => {
                let e = RunnerError::Rejected {
                    field: RejectField::Runner,
                    reason_code: "runner_specific_not_wasm",
                };
                emit_rejected(audit, &e);
                return Err(e);
            }
        };
        let _ = epoch_deadline_ms; // 保留给 epoch bumper 线程(下面用 wall_ms 驱动)

        // 每次 run 独立 Engine(R1 BLOCKER 修复)
        let engine = Self::build_engine()?;

        // 构造 stdout/stderr pipe(v0.12 wasmtime-wasi 41 移到 `p2::pipe::MemoryOutputPipe`)
        let stdout_sink = MemoryOutputPipe::new(1024 * 1024);
        let stderr_sink = MemoryOutputPipe::new(1024 * 1024);

        // WasiCtx:inherit_env = false(ADR §I-7.5),preopen read_dirs
        let mut wasi = WasiCtxBuilder::new();
        wasi.stdout(stdout_sink.clone());
        wasi.stderr(stderr_sink.clone());
        // network 默认 off;stdin 默认 closed。
        for d in &plan.read_dirs {
            let write_perms = if plan.write_dirs.iter().any(|w| w == d) {
                (DirPerms::all(), FilePerms::all())
            } else {
                (DirPerms::READ, FilePerms::READ)
            };
            if wasi
                .preopened_dir(d, "/workspace", write_perms.0, write_perms.1)
                .is_err()
            {
                audit.emit(RunnerEvent::IoError {
                    phase: "wasi_preopen",
                    reason_code: "preopen_failed",
                });
                return Err(RunnerError::Io {
                    phase: "wasi_preopen",
                    reason_code: "preopen_failed",
                });
            }
        }
        let wasi_ctx: WasiP1Ctx = wasi.build_p1();

        let mut store = Store::new(&engine, wasi_ctx);
        store
            .set_fuel(fuel)
            .map_err(|_| RunnerError::Internal("wasm_set_fuel"))?;
        store.set_epoch_deadline(1);

        // epoch bumper:wall_ms 后递增 epoch → guest 中断
        // R1 BLOCKER 修复:engine clone 独立于 self,bumper 即使 sleep 过头也只影响
        // 这一次 run 的 engine(函数返回后 engine drop,bumper 再 increment_epoch
        // 作用在已 drop 的 engine 上,无副作用)。
        let engine_clone = engine.clone();
        let wall_ms = plan.wall_ms;
        let bumper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(wall_ms));
            engine_clone.increment_epoch();
        });

        // 编译 + 链接
        let module = match Module::new(&engine, wasm_bytes) {
            Ok(m) => m,
            Err(e) => {
                let trap = RunnerError::WasmTrap((self.scrub)(&e.to_string()));
                audit.emit(RunnerEvent::IoError {
                    phase: "wasm_compile",
                    reason_code: "module_compile_failed",
                });
                return Err(trap);
            }
        };
        let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
        add_to_linker_sync(&mut linker, |ctx| ctx)
            .map_err(|_| RunnerError::Internal("wasm_linker_wasi"))?;

        // started 事件(Wasm 在这里"开始运行")
        let env_keys: Vec<String> = Vec::new(); // Wasm 默认 env_none
        let cwd_str = plan.cwd.to_string_lossy().to_string();
        audit.emit(RunnerEvent::Started {
            runner_kind: "Wasm",
            server_id: None,
            wall_ms: plan.wall_ms,
            env_keys: &env_keys,
            cwd: &cwd_str,
        });

        let start = Instant::now();
        let instance = match linker.instantiate(&mut store, &module) {
            Ok(i) => i,
            Err(e) => {
                let msg = e.to_string();
                audit.emit(RunnerEvent::IoError {
                    phase: "wasm_instantiate",
                    reason_code: "instantiate_failed",
                });
                return Err(RunnerError::WasmTrap((self.scrub)(&msg)));
            }
        };
        let func = match instance.get_typed_func::<(), ()>(&mut store, "_start") {
            Ok(f) => f,
            Err(_) => {
                let e = RunnerError::Rejected {
                    field: RejectField::Runner,
                    reason_code: "wasm_missing_start",
                };
                emit_rejected(audit, &e);
                return Err(e);
            }
        };

        let run_result = func.call(&mut store, ());
        let wall_elapsed_ms = start.elapsed().as_millis() as u64;
        // bumper 线程可能仍在 sleep;不 join,让它自然退出。
        // R1 BLOCKER 修复:engine 即将 drop,bumper 持 clone 的 engine 也 drop,
        // increment_epoch 作用在已释放的 epoch 池上,无副作用。
        drop(bumper);

        if let Err(e) = run_result {
            let msg = e.to_string();
            // epoch / fuel 类中断都算 Timeout 对外呈现
            if msg.contains("epoch") || msg.contains("fuel") || msg.contains("interrupted") {
                audit.emit(RunnerEvent::KilledByTimeout {
                    wall_ms: plan.wall_ms,
                });
                return Err(RunnerError::Timeout {
                    wall_ms: plan.wall_ms,
                });
            }
            // R2 MUST-FIX 1:非 timeout 的 guest trap 也要发审计(归到 IoError
            // phase="wasm_call",reason_code="guest_trap";保持 5 类事件枚举不膨胀)
            audit.emit(RunnerEvent::IoError {
                phase: "wasm_call",
                reason_code: "guest_trap",
            });
            return Err(RunnerError::WasmTrap((self.scrub)(&msg)));
        }

        // 收集 stdout/stderr + 逐行 scrub
        let stdout_raw = stdout_sink.contents().to_vec();
        let stderr_raw = stderr_sink.contents().to_vec();
        let stdout = scrub_bytes(&stdout_raw, &self.scrub);
        let stderr = scrub_bytes(&stderr_raw, &self.scrub);

        // ISS-020:post-exec leak hook(与 native.rs 同形态)。
        let (quarantined, leak_findings) =
            crate::leak_scan::post_exec_leak_scan(&stdout, &stderr, audit);

        audit.emit(RunnerEvent::Completed {
            exit_code: Some(0),
            wall_elapsed_ms,
            stdout_bytes: stdout.len(),
            stderr_bytes: stderr.len(),
        });

        Ok(ExecutionResult {
            exit_code: Some(0), // WASI `_start` 正常返回 = 0
            wall_elapsed_ms,
            stdout,
            stderr,
            quarantined,
            leak_findings,
        })
    }
}

fn emit_rejected(audit: &dyn RunnerAuditSink, err: &RunnerError) {
    if let RunnerError::Rejected { field, reason_code } = err {
        audit.emit(RunnerEvent::Rejected {
            field: *field,
            reason_code,
        });
    }
}

fn scrub_bytes(raw: &[u8], scrub: &Arc<dyn Fn(&str) -> String + Send + Sync>) -> Vec<u8> {
    let s = String::from_utf8_lossy(raw);
    let mut out = Vec::with_capacity(raw.len());
    for line in s.lines() {
        let cleaned = scrub(line);
        out.extend_from_slice(cleaned.as_bytes());
        out.push(b'\n');
    }
    out
}
