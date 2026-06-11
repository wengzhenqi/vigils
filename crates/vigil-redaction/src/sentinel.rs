//! P0 注入防护 — nonce sentinel(确定性信号,可 deny)。
//!
//! 与元指令软信号([`crate::scan_meta_instructions`])**本质不同**:本模块的 sentinel
//! 前缀 `vigil-untrusted-` 是 Vigil 私有的、不会出现在合法外部数据中的字面量。因此
//! "文本里出现该前缀" 是**确定性零误报**信号 —— 可作 fail-closed deny(与 secret
//! 硬指纹 DENY 语义同级)。元指令是语义高误报只能提分,二者代码分流不混阈值。
//!
//! 设计(`docs/strategy/2026-06-11-p0-injection-defense-plan.md` 冲突点 #1):
//! - 128-bit CSPRNG nonce 标签 `<vigil-untrusted-{hex}>…</vigil-untrusted-{hex}>`,
//!   一次性不复用(不用 base64 / 逐词 datamarking,避免破坏 detokenize 占位符流 +
//!   对代码/中文失效)。
//! - 伪造检测靠**固定前缀字面量**,而非具体某次的随机 nonce —— 攻击者无法预知任何
//!   nonce,但只要文本含本模块私有前缀即视为可疑。

/// 不可信数据包裹标签的固定前缀。这是伪造检测的锚点(私有字面量,合法外部数据不含)。
pub const UNTRUSTED_SENTINEL_PREFIX: &str = "vigil-untrusted-";

/// 生成一对一次性不可信数据包裹标签(open / close)。
///
/// 用 128-bit CSPRNG nonce(`getrandom`,与 vigil-token 同源 RNG)渲染成 32 位 hex,
/// 返回 `("<vigil-untrusted-{hex}>", "</vigil-untrusted-{hex}>")`。调用方应把不可信
/// 数据(如工具输出)夹在这对标签之间注入,模型侧据此区分"指令" vs "数据"。
///
/// **一次性**:每次调用产新 nonce;不要缓存复用(复用会让攻击者一旦学得旧 nonce 即可
/// 伪造对应区间)。生成失败(getrandom 系统熵不可用,极罕见)时回退到全零 nonce 仍
/// 返回良构标签 —— sentinel 的安全价值在"前缀存在性"而非 nonce 不可预测性,
/// [`detect_sentinel_forgery`] 检的是前缀不是具体 nonce。
pub fn make_untrusted_marker() -> (String, String) {
    let mut nonce = [0u8; 16]; // 128-bit
                               // getrandom 失败(极罕见:无 /dev/urandom 等)不 panic;回退全零,
                               // 标签仍良构。前缀存在性才是 forgery 检测依据,见下方 detect_。
    if getrandom::getrandom(&mut nonce).is_err() {
        // 熵源故障极罕见但应可观测:全零 nonce 标签可预测,运维需据此排查熵源
        // (单轮内仍被 forgery 前缀检测兜底,不构成即时漏洞,故仅告警不 fail-closed)。
        eprintln!(
            "vigil: getrandom failed for untrusted-data marker nonce; \
             falling back to a zero nonce (entropy source may be unavailable)"
        );
    }
    let hex = to_hex(&nonce);
    let open = format!("<{UNTRUSTED_SENTINEL_PREFIX}{hex}>");
    let close = format!("</{UNTRUSTED_SENTINEL_PREFIX}{hex}>");
    (open, close)
}

/// 检测文本是否含 Vigil 私有 sentinel 前缀(`vigil-untrusted-`)。
///
/// **确定性零误报**:合法外部数据不含此私有 sentinel,故命中即"疑似伪造/注入构造"。
/// 与元指令软信号不同,这个**可以**作 fail-closed 信号(调用方可据此 deny)。
///
/// 检的是固定前缀**字面量存在性**,不验 nonce 合法性 —— 攻击者即便不知道某次真实
/// nonce,只要试图自造 `vigil-untrusted-...` 包裹来冒充"已审数据/系统指令"就被抓。
///
/// **注**:PostToolUse datamarking 路径已改用 [`strip_sentinel_markers`](剥离+重包,
/// 不 deny)以消除跨轮回流误 deny(见计划文档 MEDIUM-1)。本函数保留供其它确定性
/// deny 场景与守门测试使用。
pub fn detect_sentinel_forgery(text: &str) -> bool {
    text.contains(UNTRUSTED_SENTINEL_PREFIX)
}

/// 匹配任意 Vigil untrusted 开/闭标签:`<vigil-untrusted-{body}>` 或 `</vigil-untrusted-{body}>`。
/// body 放宽到 0+ 个**非 `>`/非空白**字符——**必须覆盖 [`detect_sentinel_forgery`] 的
/// `.contains("vigil-untrusted-")` 大小写无关命中面**(hostile review HIGH):Vigil 自产 nonce 是
/// 小写 hex,但攻击者可预埋大写 `DEADBEEF` / 混合大小写 / 非 hex body —— 若 strip 漏剥而 detect
/// 命中,会留 `sentinel_stripped` 审计盲点 + 残留标签自污染。`</?` 兼开闭。前缀私有,合法数据不含,
/// 故 `[^>\s]*` 不会误剥正常文本。
static SENTINEL_MARKER_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
    regex::Regex::new(r"</?vigil-untrusted-[^>\s]*>").expect("sentinel marker regex")
});

/// 剥离文本里所有 Vigil untrusted 开/闭标签,**保留标签间的内容**,返回 `(剥离后文本, 是否剥离过)`。
///
/// # 为什么 strip 而非 deny(计划文档 MEDIUM-1 的彻底修复)
/// untrusted 标签语义=「不可信数据」,攻击者伪造它**无攻击收益**(被包内容反被标记为数据);
/// nonce 随机已防闭合逃逸。故 PostToolUse datamarking 不再对 forgery fail-closed deny,改为:
/// - **剥离已有标签**(无论来源:攻击者预埋的伪标签、或 Vigil 上一轮标签经模型持久化后跨轮回流);
/// - 调用方随后用**新 nonce** 标签重新包裹整段输出 → 回流内容被重标为数据、攻击者预埋串被无害化。
///
/// 这样回流的合法工具结果不再被误 deny,攻击者 `</vigil-untrusted-猜>恶意<...>` 被剥离后,
/// 「恶意」内容只会被新 nonce 标签重新包成「数据」,安全。
///
/// 只移除**标签本身**(开/闭),不动标签间内容;无标签时原样返回 + `false`(no-op)。
pub fn strip_sentinel_markers(text: &str) -> (String, bool) {
    if !text.contains(UNTRUSTED_SENTINEL_PREFIX) {
        // 快速路径:不含私有前缀 → 必无标签可剥,避免无谓正则扫描与分配。
        return (text.to_string(), false);
    }
    let stripped = SENTINEL_MARKER_RE.replace_all(text, "");
    // replace_all 返回 Cow;若发生替换则为 Owned,否则 Borrowed(理论上前缀存在时总会替换,
    // 但前缀出现在非良构标签里也可能不匹配 → 用 stripped != text 精确判定是否剥离过)。
    let changed = stripped != text;
    (stripped.into_owned(), changed)
}

/// 16 字节渲染为 32 位小写 hex(避免引入 hex crate 到默认依赖树;实现极简)。
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// open/close 标签良构:含前缀、成对、close 比 open 多一个 `/`。
    #[test]
    fn marker_is_well_formed() {
        let (open, close) = make_untrusted_marker();
        assert!(open.starts_with("<vigil-untrusted-"));
        assert!(open.ends_with('>'));
        assert!(close.starts_with("</vigil-untrusted-"));
        assert!(close.ends_with('>'));
        // open 去掉首尾 `<>` 后即 close 去掉 `</>` 的同一 nonce 体
        let open_body = open.trim_start_matches('<').trim_end_matches('>');
        let close_body = close.trim_start_matches("</").trim_end_matches('>');
        assert_eq!(open_body, close_body, "open/close 应同 nonce");
    }

    /// nonce 一次性:两次调用产不同标签(全零碰撞概率 2^-128,忽略)。
    #[test]
    fn marker_is_unique_per_call() {
        let (o1, _) = make_untrusted_marker();
        let (o2, _) = make_untrusted_marker();
        assert_ne!(o1, o2, "每次调用应产新 nonce");
    }

    /// 自产标签可被 forgery 检测命中(本模块自身产物含前缀)。
    #[test]
    fn detect_catches_own_marker() {
        let (open, close) = make_untrusted_marker();
        assert!(detect_sentinel_forgery(&open));
        assert!(detect_sentinel_forgery(&close));
        let wrapped = format!("{open}some untrusted data{close}");
        assert!(detect_sentinel_forgery(&wrapped));
    }

    /// 攻击者自造的伪 sentinel 也命中(前缀存在即可疑)。
    #[test]
    fn detect_catches_forged_prefix() {
        assert!(detect_sentinel_forgery(
            "<vigil-untrusted-deadbeefdeadbeefdeadbeefdeadbeef>fake"
        ));
        assert!(detect_sentinel_forgery("prefix vigil-untrusted-anything"));
    }

    /// 合法外部数据(不含私有前缀)零误报。
    #[test]
    fn detect_no_false_positive_on_clean_text() {
        assert!(!detect_sentinel_forgery("hello world"));
        assert!(!detect_sentinel_forgery(
            "discuss <untrusted> data and trusted boundaries"
        ));
        assert!(!detect_sentinel_forgery(
            "vigil untrusted (无连字符前缀不命中)"
        ));
        assert!(!detect_sentinel_forgery(""));
    }

    /// strip 剥离一对自产标签:标签消失、标签间内容保留、changed=true。
    #[test]
    fn strip_removes_own_marker_pair_keeps_content() {
        let (open, close) = make_untrusted_marker();
        let wrapped = format!("{open}payload data{close}");
        let (stripped, changed) = strip_sentinel_markers(&wrapped);
        assert!(changed, "含标签应报告剥离过");
        assert_eq!(stripped, "payload data", "标签间内容须原样保留");
        // 剥离后不再含私有前缀(forgery 检测对其不再命中)。
        assert!(!detect_sentinel_forgery(&stripped));
    }

    /// strip 对无标签文本是 no-op:原样返回 + changed=false。
    #[test]
    fn strip_noop_on_clean_text() {
        let (s1, c1) = strip_sentinel_markers("build succeeded\n");
        assert_eq!(s1, "build succeeded\n");
        assert!(!c1);

        let (s2, c2) = strip_sentinel_markers("");
        assert_eq!(s2, "");
        assert!(!c2);

        // 含 "untrusted" 字样但无私有前缀 → 不动。
        let (s3, c3) = strip_sentinel_markers("discuss <untrusted> data boundaries");
        assert_eq!(s3, "discuss <untrusted> data boundaries");
        assert!(!c3);
    }

    /// strip 剥离嵌套/多个标签(回流 + 攻击者预埋混杂):全部标签剥净,内容保留。
    #[test]
    fn strip_removes_multiple_and_nested_markers() {
        // 嵌套:外层 Vigil 回流 + 内层攻击者预埋伪标签(任意 hex / 空 hex)。
        let text = "<vigil-untrusted-aaaa>outer \
                    <vigil-untrusted-deadbeef>inner</vigil-untrusted-deadbeef> \
                    tail</vigil-untrusted-aaaa>";
        let (stripped, changed) = strip_sentinel_markers(text);
        assert!(changed);
        assert_eq!(stripped, "outer inner tail");
        assert!(!detect_sentinel_forgery(&stripped));

        // 空 hex 闭合标签(攻击者 `</vigil-untrusted->` 试图闭合)也被剥。
        let (s2, c2) = strip_sentinel_markers("</vigil-untrusted->evil<vigil-untrusted->");
        assert!(c2);
        assert_eq!(s2, "evil");
        assert!(!detect_sentinel_forgery(&s2));
    }

    /// HIGH 守门(hostile review 维度2):大写/混合大小写/非 hex body 的良构伪标签也被 strip。
    /// 修复前正则 `[0-9a-f]*` 只匹配小写 → 攻击者 `<vigil-untrusted-DEADBEEF>` 被 detect 命中却
    /// strip no-op → 审计盲点 + 残留自污染。修后 `[^>\s]*` 覆盖面对齐 detect。
    #[test]
    fn strip_removes_uppercase_and_non_hex_body_markers() {
        for (input, want) in [
            (
                "<vigil-untrusted-DEADBEEF>evil</vigil-untrusted-DEADBEEF>",
                "evil",
            ), // 大写 hex
            ("<vigil-untrusted-AbCdEf>x</vigil-untrusted-AbCdEf>", "x"), // 混合大小写
            ("<vigil-untrusted-XYZ123>y</vigil-untrusted-XYZ123>", "y"), // 非 hex body
        ] {
            let (stripped, changed) = strip_sentinel_markers(input);
            assert!(changed, "良构伪标签(任意 body)必须被剥: {input:?}");
            assert_eq!(stripped, want, "标签间内容须保留: {input:?}");
            assert!(
                !detect_sentinel_forgery(&stripped),
                "剥后不应残留可被 detect 命中的标签: {input:?}"
            );
        }
    }
}
