//! ToolCallSpan —— AGENTS.md §1 "DecisionRecord before execution" 的**编译期**强制。
//!
//! 类型状态(见 ADR 0002 §D2):
//! ```text
//! Opened  ──decision_recorded()──▶  Decided  ──executed()/execute_failed()──▶  Done
//!    │                                  │
//!    └── Drop 若未转移 ────────────────┘
//!          │
//!          ▼
//!    自动追加 "tool_call.abandoned" 事件(best-effort)
//! ```
//!
//! 错误时序(如直接从 Opened 调 executed())在**编译期**被拒绝:没有对应的方法。

use std::marker::PhantomData;

use serde_json::json;
use vigil_types::DecisionRecord;

use crate::error::Result;
use crate::ledger::Ledger;

/// 标记:刚打开,尚未记录 decision。
#[derive(Debug)]
pub struct Opened;

/// 标记:已记录 decision,等待执行结果。
#[derive(Debug)]
pub struct Decided;

/// 类型状态机承载体。
///
/// 生命周期 `'a` 绑定到底层 `Ledger`,保证 span 不会比 ledger 活得久。
#[derive(Debug)]
pub struct ToolCallSpan<'a, S> {
    ledger: &'a Ledger,
    invocation_id: String,
    session_id: String,
    // finalized = true 表示已经到达 terminal 或已主动转移;Drop 不再补 abandon。
    finalized: bool,
    _state: PhantomData<S>,
}

impl<'a> ToolCallSpan<'a, Opened> {
    /// 由 `Ledger::tool_call_span` 调用,写入 `tool_call.opened` 事件并返回 span。
    pub(crate) fn open(
        ledger: &'a Ledger,
        invocation_id: String,
        session_id: String,
    ) -> Result<Self> {
        ledger.append_event_internal(
            &session_id,
            "tool_call.opened",
            &json!({"invocation_id": invocation_id}),
            Some(&format!("invocation_id:{}", invocation_id)),
        )?;
        Ok(Self {
            ledger,
            invocation_id,
            session_id,
            finalized: false,
            _state: PhantomData,
        })
    }

    /// Step 1(必做):将 `DecisionRecord` 以 `tool_call.decided` 写入账本,
    /// 并把状态推进到 `Decided`。
    pub fn decision_recorded(
        mut self,
        decision: &DecisionRecord,
    ) -> Result<ToolCallSpan<'a, Decided>> {
        let payload = json!({
            "invocation_id": self.invocation_id,
            "decision_id": decision.decision_id,
            "decision": decision.decision,
            "risk_score": decision.risk_score,
            "reasons": decision.reasons,
            "policy_ids": decision.policy_ids,
        });
        self.ledger.append_event_internal(
            &self.session_id,
            "tool_call.decided",
            &payload,
            Some(&format!(
                "invocation_id:{} decision_id:{}",
                self.invocation_id, decision.decision_id
            )),
        )?;
        // 标记当前 Opened span 为"已推进",其 Drop 不会再补 abandon。
        self.finalized = true;
        Ok(ToolCallSpan {
            ledger: self.ledger,
            invocation_id: self.invocation_id.clone(),
            session_id: self.session_id.clone(),
            finalized: false,
            _state: PhantomData,
        })
    }
}

impl<'a> ToolCallSpan<'a, Decided> {
    /// Step 2(成功路径):写入 `tool_call.executed` 并终结 span。
    pub fn executed(mut self, summary: &str) -> Result<()> {
        // FTS 摘要里始终保留 invocation_id,方便按调用聚合检索(见 FTS 测试)。
        let fts = format!("invocation_id:{} {}", self.invocation_id, summary);
        self.ledger.append_event_internal(
            &self.session_id,
            "tool_call.executed",
            &json!({"invocation_id": self.invocation_id, "summary": summary}),
            Some(&fts),
        )?;
        self.finalized = true;
        Ok(())
    }

    /// Step 2(失败路径):写入 `tool_call.execute_failed` 并终结 span。
    pub fn execute_failed(mut self, reason: &str) -> Result<()> {
        let fts = format!("invocation_id:{} {}", self.invocation_id, reason);
        self.ledger.append_event_internal(
            &self.session_id,
            "tool_call.execute_failed",
            &json!({"invocation_id": self.invocation_id, "reason": reason}),
            Some(&fts),
        )?;
        self.finalized = true;
        Ok(())
    }
}

impl<'a, S> Drop for ToolCallSpan<'a, S> {
    /// 若 span 在未到达 terminal 或未主动推进时被 drop,自动补一条
    /// `tool_call.abandoned` 事件,保持审计链不断裂。
    ///
    /// Drop 不能返回错误,此处吞掉底层 IO 失败 —— 最坏情况下账本少一条 abandon
    /// 事件,但不会影响 hash chain 的已有部分。
    fn drop(&mut self) {
        if self.finalized {
            return;
        }
        let r = self.ledger.append_event_internal(
            &self.session_id,
            "tool_call.abandoned",
            &json!({"invocation_id": self.invocation_id}),
            Some(&format!("invocation_id:{}", self.invocation_id)),
        );
        if r.is_err() {
            // 最小可观察性:Drop 不能返回错误,但累加计数,Ledger::span_drop_failures()
            // 可读;生产中若 > 0 应当告警。
            self.ledger
                .drop_failure_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

impl Ledger {
    /// 打开一个 tool call 的时序约束 span(类型状态机,见 ADR 0002 §D2)。
    pub fn tool_call_span<'a>(
        &'a self,
        invocation_id: impl Into<String>,
        session_id: impl Into<String>,
    ) -> Result<ToolCallSpan<'a, Opened>> {
        ToolCallSpan::<Opened>::open(self, invocation_id.into(), session_id.into())
    }
}
