//! `LeaseBroker`:short-lived secret lease 的生命周期管理。
//!
//! ADR 0006 §D2 / §D3 / §D7:
//! - 运行时 cache:`Mutex<HashMap<LeaseId, CachedSecret>>`,lazy eviction
//! - bound 三元组校验在 mint + resolve 双点
//! - Firewall 决策后,Hub 在 spawn 前 just-in-time mint;调用结束立即 revoke
//!
//! 审计事件(经 `Arc<Ledger>` 写入):
//! - `secret.lease_minted` / `secret.lease_revoked`
//! - `secret.lease_misuse_attempt`(三元组 mismatch)
//! - `lease.mint_failed`(keychain 不可达等)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::json;
use vigil_audit::Ledger;
use vigil_types::{InjectionMethod, SecretLease};

use crate::error::{LeaseError, MismatchField};
use crate::store::SecretStore;
use crate::value::SecretValue;

/// `mint_lease` 输入参数。
#[derive(Debug, Clone)]
pub struct MintRequest {
    /// 要 mint 的 secret alias。
    pub secret_ref: String,
    /// 当前 session。
    pub session_id: String,
    /// 目标 server。
    pub server_id: String,
    /// 目标 tool。
    pub tool_name: String,
    /// 若由审批签发,关联审批 id。
    pub approval_id: Option<String>,
    /// 注入方式(I06 仅支持 `ChildEnv`,其他方式 mint 不拒,只有 inject 层拒)。
    pub injection_method: InjectionMethod,
    /// Lease 存活时间(秒);到期后 `resolve_value` 返 `Expired`。
    pub ttl_secs: i64,
}

/// `resolve_value` 的调用上下文 —— 用于校验 bound 三元组。
#[derive(Debug, Clone)]
pub struct ResolveContext {
    /// 当前 session。
    pub session_id: String,
    /// 当前 server。
    pub server_id: String,
    /// 当前 tool。
    pub tool_name: String,
}

/// Cache 内部结构:真实 secret 值 + 到期时间。
///
/// 注:`revoke_lease` 直接从 cache 移除(Zeroizing 立即清零),不保留 tombstone ——
/// 因此 revoked 后再 resolve 返 `NotFound`(而非 `Revoked`)。这是 I06 故意的简化,
/// 最小化 secret 值在内存驻留时间。ADR 0006 §D3 的 `Revoked` 变种保留为 API 稳定性,
/// 但 I06 运行时路径不触发。
struct CachedSecret {
    lease: SecretLease,
    value: SecretValue,
}

/// Lease broker —— 真实值的唯一运行时持有者。
pub struct LeaseBroker {
    store: Arc<dyn SecretStore>,
    ledger: Arc<Ledger>,
    cache: Mutex<HashMap<String, CachedSecret>>,
}

impl std::fmt::Debug for LeaseBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseBroker")
            .field("store_backend", &self.store.backend_kind())
            .finish_non_exhaustive()
    }
}

impl LeaseBroker {
    /// 新建 broker。`store` 提供真实值,`ledger` 用于审计事件。
    pub fn new(store: Arc<dyn SecretStore>, ledger: Arc<Ledger>) -> Self {
        Self {
            store,
            ledger,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Mint 一条新 lease。
    ///
    /// 1. 从 store 读真实值(keychain 不可达 → `StoreError` + `lease.mint_failed` 审计)
    /// 2. 生成 `SecretLease`(uuid + bound_* + expires_at)
    /// 3. 插入 cache
    /// 4. 写审计 `secret.lease_minted`(metadata only,无真实值)
    pub fn mint_lease(&self, req: MintRequest) -> Result<SecretLease, LeaseError> {
        // 先尝试从 store 取值 —— 失败时审计 secret.lease_mint_failed。
        let value = match self.store.get(&req.secret_ref) {
            Ok(v) => v,
            Err(store_err) => {
                // Codex R1 BLOCKER-2:payload 只含结构化 reason_code,**不含**后端错误原文,
                // 防 keyring / DBus backend 的错误消息里回显真实 value 时泄漏到 SQLite。
                let code = store_err.reason_code();
                let redacted = format!(
                    "lease_mint_failed {} {} {}",
                    req.secret_ref,
                    self.store.backend_kind(),
                    code
                );
                let _ = self.ledger.append_event(
                    &req.session_id,
                    "secret.lease_mint_failed",
                    &json!({
                        "secret_ref": req.secret_ref,
                        "backend": self.store.backend_kind(),
                        "reason_code": code,
                    }),
                    Some(&redacted),
                );
                return Err(store_err.into());
            }
        };

        let now = current_unix_time();
        let lease = SecretLease {
            lease_id: uuid::Uuid::new_v4().to_string(),
            secret_ref: req.secret_ref.clone(),
            bound_session_id: req.session_id.clone(),
            bound_server_id: req.server_id.clone(),
            bound_tool_name: req.tool_name.clone(),
            approval_id: req.approval_id.clone(),
            injection_method: req.injection_method,
            expires_at: now + req.ttl_secs,
        };

        {
            let mut g = self
                .cache
                .lock()
                .map_err(|_| LeaseError::Internal("cache lock poisoned"))?;
            g.insert(
                lease.lease_id.clone(),
                CachedSecret {
                    lease: lease.clone(),
                    value,
                },
            );
        } // drop guard 再 audit,避免 I04 ledger 死锁同款问题

        // Codex R1 NICE-TO-HAVE:mint 成功后更新 last_used_at,让 UI 排序 / 审计元数据生效。
        let _ = self.ledger.touch_secret_ref(&req.secret_ref);

        let redacted = format!(
            "lease_minted {} {} {} {}",
            lease.lease_id, lease.secret_ref, lease.bound_server_id, lease.bound_tool_name
        );
        let _ = self.ledger.append_event(
            &lease.bound_session_id,
            "secret.lease_minted",
            &json!({
                "lease_id": lease.lease_id,
                "secret_ref": lease.secret_ref,
                "bound_session_id": lease.bound_session_id,
                "bound_server_id": lease.bound_server_id,
                "bound_tool_name": lease.bound_tool_name,
                "approval_id": lease.approval_id,
                "injection_method": lease.injection_method,
                "expires_at": lease.expires_at,
            }),
            Some(&redacted),
        );

        Ok(lease)
    }

    /// 读取真实值 —— **同时**校验 bound 三元组 + 到期 + revoke 标记。
    ///
    /// 三元组不匹配时:写 `secret.lease_misuse_attempt` 审计,返 `ContextMismatch`。
    pub fn resolve_value(
        &self,
        lease_id: &str,
        ctx: &ResolveContext,
    ) -> Result<SecretValue, LeaseError> {
        // 1. 取 cache + 校验
        let (value, audit_payload) = {
            let mut g = self
                .cache
                .lock()
                .map_err(|_| LeaseError::Internal("cache lock poisoned"))?;
            let entry = g
                .get(lease_id)
                .ok_or_else(|| LeaseError::NotFound(lease_id.to_string()))?;

            let now = current_unix_time();
            if now >= entry.lease.expires_at {
                // lazy 淘汰:到期即删,下次就是 NotFound
                g.remove(lease_id);
                return Err(LeaseError::Expired(lease_id.to_string()));
            }

            // bound 三元组校验:任意一维不匹配都要审计 + 拒绝
            if entry.lease.bound_session_id != ctx.session_id {
                let payload = json!({
                    "lease_id": lease_id,
                    "mismatch_field": MismatchField::Session.as_str(),
                });
                let audit_session = ctx.session_id.clone();
                return {
                    drop(g);
                    // 关键词作独立 token 便于 FTS(tokenchars 不含 `:`,此处用空格分隔)
                    let redacted = format!(
                        "lease_misuse_attempt lease_id {} field {}",
                        lease_id,
                        payload
                            .get("mismatch_field")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?")
                    );
                    let _ = self.ledger.append_event(
                        &audit_session,
                        "secret.lease_misuse_attempt",
                        &payload,
                        Some(&redacted),
                    );
                    Err(LeaseError::ContextMismatch {
                        lease_id: lease_id.to_string(),
                        field: MismatchField::Session,
                    })
                };
            }
            if entry.lease.bound_server_id != ctx.server_id {
                let payload = json!({
                    "lease_id": lease_id,
                    "mismatch_field": MismatchField::Server.as_str(),
                });
                let audit_session = ctx.session_id.clone();
                return {
                    drop(g);
                    // 关键词作独立 token 便于 FTS(tokenchars 不含 `:`,此处用空格分隔)
                    let redacted = format!(
                        "lease_misuse_attempt lease_id {} field {}",
                        lease_id,
                        payload
                            .get("mismatch_field")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?")
                    );
                    let _ = self.ledger.append_event(
                        &audit_session,
                        "secret.lease_misuse_attempt",
                        &payload,
                        Some(&redacted),
                    );
                    Err(LeaseError::ContextMismatch {
                        lease_id: lease_id.to_string(),
                        field: MismatchField::Server,
                    })
                };
            }
            if entry.lease.bound_tool_name != ctx.tool_name {
                let payload = json!({
                    "lease_id": lease_id,
                    "mismatch_field": MismatchField::Tool.as_str(),
                });
                let audit_session = ctx.session_id.clone();
                return {
                    drop(g);
                    // 关键词作独立 token 便于 FTS(tokenchars 不含 `:`,此处用空格分隔)
                    let redacted = format!(
                        "lease_misuse_attempt lease_id {} field {}",
                        lease_id,
                        payload
                            .get("mismatch_field")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?")
                    );
                    let _ = self.ledger.append_event(
                        &audit_session,
                        "secret.lease_misuse_attempt",
                        &payload,
                        Some(&redacted),
                    );
                    Err(LeaseError::ContextMismatch {
                        lease_id: lease_id.to_string(),
                        field: MismatchField::Tool,
                    })
                };
            }

            let v = entry.value.clone();
            (v, None::<serde_json::Value>)
        };
        // audit_payload 目前成功路径不产事件(mint 已审计过)
        let _ = audit_payload;
        Ok(value)
    }

    /// 显式 revoke —— 幂等(已 revoke 或不存在都返 Ok)。
    ///
    /// 调用结束 Hub 必须 revoke,即使 tool call 报错也要走此路径。
    pub fn revoke_lease(&self, lease_id: &str) -> Result<(), LeaseError> {
        let session = {
            let mut g = self
                .cache
                .lock()
                .map_err(|_| LeaseError::Internal("cache lock poisoned"))?;
            // remove 返回 entry,从中取 session 再 drop value(Zeroizing 在 drop 时清零)
            g.remove(lease_id).map(|c| c.lease.bound_session_id)
        };
        if let Some(sess) = session {
            let redacted = format!("lease_revoked {lease_id} explicit");
            let _ = self.ledger.append_event(
                &sess,
                "secret.lease_revoked",
                &json!({ "lease_id": lease_id, "reason": "explicit" }),
                Some(&redacted),
            );
        }
        Ok(())
    }

    /// 清扫所有已过期 lease —— 返清除数量。
    ///
    /// 提供主动触发点(例如 Hub 定期维护),lazy 淘汰为主路径。
    pub fn sweep_expired(&self) -> Result<usize, LeaseError> {
        let now = current_unix_time();
        let removed: Vec<(String, String)> = {
            let mut g = self
                .cache
                .lock()
                .map_err(|_| LeaseError::Internal("cache lock poisoned"))?;
            let expired: Vec<(String, String)> = g
                .iter()
                .filter_map(|(id, c)| {
                    if now >= c.lease.expires_at {
                        Some((id.clone(), c.lease.bound_session_id.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            for (id, _) in &expired {
                g.remove(id);
            }
            expired
        };
        for (id, session) in &removed {
            let redacted = format!("lease_revoked {id} expired");
            let _ = self.ledger.append_event(
                session,
                "secret.lease_revoked",
                &json!({ "lease_id": id, "reason": "expired" }),
                Some(&redacted),
            );
        }
        Ok(removed.len())
    }

    /// 显式关闭:drain 全部 cache,强制 Zeroizing 落地。
    /// `Drop` 也会走同样逻辑,但显式 shutdown 便于测试断言和跨进程清理。
    pub fn shutdown(&self) {
        if let Ok(mut g) = self.cache.lock() {
            g.clear();
        }
    }

    /// 当前 cache 大小(测试 / diagnostics 用)。
    pub fn cache_len(&self) -> usize {
        self.cache.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// fail-closed gate:I06 仅支持 `ChildEnv`(ADR 0006 §D4)。
    ///
    /// Hub / caller 在注入前显式调用此方法,避免日后新增 `InjectionMethod` 变种后
    /// 遗漏某条路径就悄无声息地失败。非 ChildEnv 返 `UnsupportedInjectionMethod`。
    pub fn assert_injection_supported(method: InjectionMethod) -> Result<(), LeaseError> {
        match method {
            InjectionMethod::ChildEnv => Ok(()),
            other => Err(LeaseError::UnsupportedInjectionMethod(other)),
        }
    }

    /// 批量撤销一组 lease(内部用;调用 revoke_lease 逐条审计)。
    pub fn revoke_many(&self, lease_ids: &[String]) {
        for id in lease_ids {
            let _ = self.revoke_lease(id);
        }
    }
}

/// `prepare_child_env` 返回的 RAII 句柄。
///
/// **Codex R1 BLOCKER-1 修复**:env 字段私有 + `take_env()` 单次消费语义。
/// - `env_keys()`:只读的 key 清单(非敏感,供 diagnostics / UI 预览)
/// - `take_env()`:**唯一**取出真实值的 API,调用一次后内部 env 被 drop 并继续 RAII revoke
/// - caller 应立即把返回的 HashMap 交给 `Command::envs()` 等一次性 spawn API,
///   不要存入长期持有的数据结构
/// - Drop 时自动 revoke 所有 lease(Zeroizing 同步清零)
pub struct PreparedChildEnv {
    env: Option<std::collections::HashMap<String, String>>,
    lease_ids: Vec<String>,
    broker: std::sync::Weak<LeaseBroker>,
}

impl PreparedChildEnv {
    /// 返回 env 变量名清单(非敏感,只含 `env_var_name`,**不含** value)。
    pub fn env_keys(&self) -> Vec<String> {
        self.env
            .as_ref()
            .map(|m| {
                let mut v: Vec<String> = m.keys().cloned().collect();
                v.sort();
                v
            })
            .unwrap_or_default()
    }

    /// 单次消费:取出 env 变量 HashMap(key → 真实 value)并让后续 `take_env` 返 `None`。
    ///
    /// caller 应立即在 spawn 调用链中把返回值消费掉,不要持久化 / clone。
    /// Drop 时仍会 revoke(value 已进子进程 env,父进程 cache 清零)。
    pub fn take_env(&mut self) -> Option<std::collections::HashMap<String, String>> {
        self.env.take()
    }

    /// 内部 lease 数量(diagnostics / 测试)。
    pub fn lease_count(&self) -> usize {
        self.lease_ids.len()
    }
}

impl std::fmt::Debug for PreparedChildEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedChildEnv")
            .field("env_keys", &self.env_keys())
            .field("lease_count", &self.lease_ids.len())
            .field("env_consumed", &self.env.is_none())
            .finish_non_exhaustive()
    }
}

impl Drop for PreparedChildEnv {
    fn drop(&mut self) {
        if let Some(broker) = self.broker.upgrade() {
            broker.revoke_many(&self.lease_ids);
        }
    }
}

impl LeaseBroker {
    /// 查 ledger 的 `resolve_child_env_bindings(server, tool)` → 对每条 binding mint lease →
    /// resolve value → 组装 `PreparedChildEnv`。
    ///
    /// **注意**:本方法持 `Arc<Self>` 调用,以便 `PreparedChildEnv` 在 Drop 时
    /// 反向 revoke。若 broker 已被 drop,Drop 内 `upgrade` 返 None,revoke 静默跳过。
    ///
    /// 失败语义(ADR 0006 §D7):
    /// - 任何一条 binding mint 失败 → 立即 revoke 已 mint 的,返 `LeaseError`
    ///   (fail-closed,调用方启动 upstream 失败)
    /// - 只涉及 ChildEnv 绑定;若未来扩展其他注入方式,此方法仍只返 ChildEnv env 子集
    pub fn prepare_child_env(
        self: &Arc<Self>,
        ctx: &ResolveContext,
        approval_id: Option<String>,
        ttl_secs: i64,
    ) -> Result<PreparedChildEnv, LeaseError> {
        let bindings = self
            .ledger
            .resolve_child_env_bindings(&ctx.server_id, &ctx.tool_name)
            .map_err(|_| {
                // ledger 后端错误不透传原文(保持与 SecretStore 一样的脱敏口径)
                LeaseError::StoreError(crate::error::SecretStoreError::BackendUnavailable)
            })?;

        let mut env = std::collections::HashMap::new();
        let mut lease_ids: Vec<String> = Vec::new();

        for b in bindings {
            // ChildEnv 必须有 env_var_name(registry 层已校验);这里二次守。
            let Some(env_key) = b.env_var_name else {
                self.revoke_many(&lease_ids);
                return Err(LeaseError::Internal(
                    "ChildEnv binding missing env_var_name",
                ));
            };
            let lease = match self.mint_lease(MintRequest {
                secret_ref: b.secret_ref.clone(),
                session_id: ctx.session_id.clone(),
                server_id: ctx.server_id.clone(),
                tool_name: ctx.tool_name.clone(),
                approval_id: approval_id.clone(),
                injection_method: vigil_types::InjectionMethod::ChildEnv,
                ttl_secs,
            }) {
                Ok(l) => l,
                Err(e) => {
                    self.revoke_many(&lease_ids);
                    return Err(e);
                }
            };
            lease_ids.push(lease.lease_id.clone());

            let value = match self.resolve_value(&lease.lease_id, ctx) {
                Ok(v) => v,
                Err(e) => {
                    self.revoke_many(&lease_ids);
                    return Err(e);
                }
            };
            env.insert(env_key, value.expose().to_string());
        }

        Ok(PreparedChildEnv {
            env: Some(env),
            lease_ids,
            broker: Arc::downgrade(self),
        })
    }
}

impl Drop for LeaseBroker {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// 当前 Unix 时间戳(秒)。抽出便于测试未来可注入 clock。
fn current_unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
