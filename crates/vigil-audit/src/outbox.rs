//! Outbox —— ADR 0004 §D7 实装(ADR 0003 §D7 延期项)。
//!
//! 用途:对"高风险外发"类 tool call(发邮件、HTTP POST、浏览器提交),先把
//! 将要发送的内容冻结为 `Drafted` 预览,提交审批 → 批准后才真正调上游。
//! 这样即使审批后发现内容有问题,也能在 `Executed` 之前取消。
//!
//! I04 实装 `kind = http_post`(最常见);email / browser_submit 留作 I09+。

use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AuditError, Result};
use crate::ledger::{now_secs, Ledger};

/// Outbox 条目种类。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum OutboxKind {
    /// 对外 HTTP POST
    HttpPost,
    /// 发邮件(I09 启用)
    Email,
    /// 浏览器表单提交(I09 启用)
    BrowserSubmit,
}

/// Outbox 状态机(ADR 0004 §D7)。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[serde(rename_all = "PascalCase")]
pub enum OutboxStatus {
    /// 已生成预览,未提交审批
    Drafted,
    /// 已关联 approval_id,等待用户审批
    PendingApproval,
    /// 审批通过,等待执行
    Approved,
    /// 审批拒绝
    Denied,
    /// 审批到期
    Expired,
    /// 已执行上游
    Executed,
    /// 上游调用失败
    Failed,
    /// session 结束 / 用户取消
    Cancelled,
}

/// 一条 Outbox 条目。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboxItem {
    /// 唯一 id
    pub outbox_id: String,
    /// 对应 tool call
    pub invocation_id: String,
    /// 所属 session
    pub session_id: String,
    /// 类型
    pub kind: OutboxKind,
    /// 已脱敏的"将要发送"预览(结构化 JSON)
    pub preview_json: serde_json::Value,
    /// 关联 approval(若 `PendingApproval` 及以后)
    pub approval_id: Option<String>,
    /// 当前状态
    pub status: OutboxStatus,
    /// 创建时间
    pub created_at: i64,
    /// 被批准 / 拒绝时间
    pub approved_at: Option<i64>,
    /// 执行时间
    pub executed_at: Option<i64>,
}

impl Ledger {
    /// 创建一条 Drafted outbox。Hub 在识别出 `CommSend` / `NetOutbound` 效应后
    /// 先 draft,再 submit_outbox_for_approval。
    pub fn draft_outbox(
        &self,
        invocation_id: &str,
        session_id: &str,
        kind: OutboxKind,
        preview: &serde_json::Value,
    ) -> Result<OutboxItem> {
        let outbox_id = Uuid::new_v4().to_string();
        let now = now_secs();
        let preview_str = serde_jcs::to_string(preview)?;

        // fail-closed:preview 若含硬指纹,拒绝入 draft —— caller 必须先 redact
        if let Some(rule) = vigil_redaction::detect_hard_secret(&preview_str) {
            return Err(AuditError::HardSecretDetected { rule });
        }

        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        guard.execute(
            "INSERT INTO outbox_items
              (outbox_id, invocation_id, session_id, kind, preview_json,
               status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'Drafted', ?6)",
            rusqlite::params![
                outbox_id,
                invocation_id,
                session_id,
                kind_to_str(kind),
                preview_str,
                now,
            ],
        )?;
        Ok(OutboxItem {
            outbox_id,
            invocation_id: invocation_id.to_string(),
            session_id: session_id.to_string(),
            kind,
            preview_json: preview.clone(),
            approval_id: None,
            status: OutboxStatus::Drafted,
            created_at: now,
            approved_at: None,
            executed_at: None,
        })
    }

    /// 将 Drafted 绑定到 approval:状态推进到 PendingApproval。
    pub fn submit_outbox_for_approval(&self, outbox_id: &str, approval_id: &str) -> Result<()> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let n = guard.execute(
            "UPDATE outbox_items
             SET status = 'PendingApproval', approval_id = ?1
             WHERE outbox_id = ?2 AND status = 'Drafted'",
            rusqlite::params![approval_id, outbox_id],
        )?;
        if n == 0 {
            return Err(AuditError::InvalidInput {
                reason: "outbox not in Drafted state or not found",
            });
        }
        Ok(())
    }

    /// 审批完成后调用:PendingApproval → Approved。
    /// 只有 Hub 在 wait_for_resolution 返回 Approved 时触发。
    pub fn mark_outbox_approved(&self, outbox_id: &str) -> Result<()> {
        self.transition_outbox(outbox_id, "PendingApproval", "Approved", true)
    }

    /// 审批拒绝 / 到期。
    pub fn mark_outbox_denied(&self, outbox_id: &str) -> Result<()> {
        self.transition_outbox(outbox_id, "PendingApproval", "Denied", false)
    }

    /// 审批到期。
    pub fn mark_outbox_expired(&self, outbox_id: &str) -> Result<()> {
        self.transition_outbox(outbox_id, "PendingApproval", "Expired", false)
    }

    /// 执行成功:Approved → Executed。
    pub fn mark_outbox_executed(&self, outbox_id: &str) -> Result<()> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let now = now_secs();
        let n = guard.execute(
            "UPDATE outbox_items
             SET status = 'Executed', executed_at = ?1
             WHERE outbox_id = ?2 AND status = 'Approved'",
            rusqlite::params![now, outbox_id],
        )?;
        if n == 0 {
            return Err(AuditError::InvalidInput {
                reason: "outbox not in Approved state or not found",
            });
        }
        Ok(())
    }

    /// 执行失败:Approved → Failed。
    pub fn mark_outbox_failed(&self, outbox_id: &str) -> Result<()> {
        self.transition_outbox(outbox_id, "Approved", "Failed", false)
    }

    /// session 结束 / 用户取消。`Drafted` 或 `PendingApproval` 都可取消。
    pub fn cancel_outbox(&self, outbox_id: &str) -> Result<()> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let n = guard.execute(
            "UPDATE outbox_items
             SET status = 'Cancelled'
             WHERE outbox_id = ?1 AND status IN ('Drafted', 'PendingApproval')",
            rusqlite::params![outbox_id],
        )?;
        if n == 0 {
            return Err(AuditError::InvalidInput {
                reason: "outbox not in cancellable state or not found",
            });
        }
        Ok(())
    }

    /// 读一条 outbox。
    pub fn get_outbox(&self, outbox_id: &str) -> Result<Option<OutboxItem>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let row = guard
            .query_row(
                "SELECT outbox_id, invocation_id, session_id, kind, preview_json,
                        approval_id, status, created_at, approved_at, executed_at
                 FROM outbox_items WHERE outbox_id = ?1",
                rusqlite::params![outbox_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, i64>(7)?,
                        r.get::<_, Option<i64>>(8)?,
                        r.get::<_, Option<i64>>(9)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, inv, sess, kind_s, preview_s, appr, status_s, created, approved, executed)) =
            row
        else {
            return Ok(None);
        };
        Ok(Some(OutboxItem {
            outbox_id: id,
            invocation_id: inv,
            session_id: sess,
            kind: parse_kind(&kind_s)?,
            preview_json: serde_json::from_str(&preview_s)?,
            approval_id: appr,
            status: parse_status(&status_s)?,
            created_at: created,
            approved_at: approved,
            executed_at: executed,
        }))
    }

    fn transition_outbox(
        &self,
        outbox_id: &str,
        from: &str,
        to: &str,
        set_approved_at: bool,
    ) -> Result<()> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let now = now_secs();
        let n = if set_approved_at {
            guard.execute(
                "UPDATE outbox_items
                 SET status = ?1, approved_at = ?2
                 WHERE outbox_id = ?3 AND status = ?4",
                rusqlite::params![to, now, outbox_id, from],
            )?
        } else {
            guard.execute(
                "UPDATE outbox_items
                 SET status = ?1
                 WHERE outbox_id = ?2 AND status = ?3",
                rusqlite::params![to, outbox_id, from],
            )?
        };
        if n == 0 {
            return Err(AuditError::InvalidInput {
                reason: "outbox not in expected state or not found",
            });
        }
        Ok(())
    }
}

fn kind_to_str(k: OutboxKind) -> &'static str {
    // non_exhaustive + `_` 模式被编译期判为 unreachable(本 crate 内);保留
    // `_` 会 warn。 AGENTS.md §Implementation rules 要求非 exhaustive 枚举仍要
    // fail-closed,这里用显式的最窄回落而非 `_`。
    #[allow(unreachable_patterns)]
    match k {
        OutboxKind::HttpPost => "http_post",
        OutboxKind::Email => "email",
        OutboxKind::BrowserSubmit => "browser_submit",
        _ => "http_post",
    }
}

fn parse_kind(s: &str) -> Result<OutboxKind> {
    Ok(match s {
        "http_post" => OutboxKind::HttpPost,
        "email" => OutboxKind::Email,
        "browser_submit" => OutboxKind::BrowserSubmit,
        _ => {
            return Err(AuditError::InvalidInput {
                reason: "unknown outbox kind",
            })
        }
    })
}

fn parse_status(s: &str) -> Result<OutboxStatus> {
    Ok(match s {
        "Drafted" => OutboxStatus::Drafted,
        "PendingApproval" => OutboxStatus::PendingApproval,
        "Approved" => OutboxStatus::Approved,
        "Denied" => OutboxStatus::Denied,
        "Expired" => OutboxStatus::Expired,
        "Executed" => OutboxStatus::Executed,
        "Failed" => OutboxStatus::Failed,
        "Cancelled" => OutboxStatus::Cancelled,
        _ => {
            return Err(AuditError::InvalidInput {
                reason: "unknown outbox status",
            })
        }
    })
}
