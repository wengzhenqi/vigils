//! EffectVector / EffectKind：Vigil 自己推断出来的真实影响（不依赖 tool description）。

use serde::{Deserialize, Serialize};

/// 单次调用被推断出的副作用向量。
///
/// 所有 policy / 风险评分 / UI 展示都基于此结构，而非 tool description。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EffectVector {
    /// 归类后的效应集合（可能多条同时成立）。
    pub effects: Vec<EffectKind>,
    /// 读文件：规范化后的绝对路径。
    pub paths_read: Vec<String>,
    /// 写文件：规范化后的绝对路径。
    pub paths_write: Vec<String>,
    /// 网络目标：`host[:port]`。
    pub network_hosts: Vec<String>,
    /// 引用的 secret alias（`secret://...` 形式，不含真实值）。
    pub secret_refs: Vec<String>,
    /// 对外发送的接收方（邮箱 / webhook / issue 仓库等）。
    pub recipients: Vec<String>,
    /// 是否具破坏性（rm -rf / DROP / DELETE 等）。
    pub destructive: bool,
    /// 是否可回滚（Outbox 模式 / dry-run 可用）。
    pub reversible: bool,
}

/// 效应种类。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[serde(rename_all = "PascalCase")]
pub enum EffectKind {
    /// 读本地文件。
    FsRead,
    /// 写本地文件。
    FsWrite,
    /// 读数据库。
    DbRead,
    /// 写数据库。
    DbWrite,
    /// 出站网络。
    NetOutbound,
    /// Wasm 执行。
    ExecWasm,
    /// 原生进程执行。
    ExecNative,
    /// 使用 secret（走 lease）。
    SecretUse,
    /// 在浏览器中提交表单 / 发送消息。
    BrowserSubmit,
    /// 向第三方通讯渠道发送（邮件 / IM / PR comment）。
    CommSend,
    /// 凭据交换 / OAuth 回调等。
    CredentialExchange,
}
