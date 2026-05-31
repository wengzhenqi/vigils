//! ISS-008 Phase 1:Privacy Filter 推理引擎抽象。
//!
//! 设计目标(详见 `docs/adr/0013-hardfp-model-merge.md` + roadmap ISS-008):
//! - 为 [`crate::scan::scan_text`] 引入**可注入的 Model 侧 finding 来源**,使
//!   "Hard 路径已闭环 + Model 路径预留扩展"成为同一函数的两条 path,而不是
//!   分两个公共 API 导致 caller 双轨升级。
//! - **默认 feature 0 ort 痕迹**:[`NoopEngine`] 提供"返空 model findings"等价语义,
//!   `scan_text` delegating 到它,行为与 v0.3 完全一致(`scan_text_v03_public_api_intact`
//!   守门测试不动继续过)。
//! - **`--features ort` 路径**:[`OrtEngine`] 用 ORT 1.24 q4f16 Privacy Filter 模型
//!   做真推理,产出 BIOES 解码后的 Span findings。
//!
//! **不变量**:
//! - `EngineError` **不持有** `ort::Error`(后者非 `Send + Sync`),全部子分类持 `String`。
//! - `From<EngineError> for ScanError` 一律塌缩为 `ScanError::InferenceFailed { reason }`,
//!   `reason` 仅来自 `e.to_string()`,**绝不**拼接 input 内容(由 caller 保证)。
//! - 所有引擎实现都 `Send + Sync`,在编译期由 [`static_assertions`] mod 守门。
//! - 未识别的模型 label(BIOES core 不在 [`crate::label::PrivacyLabel::from_kind`] 白名单)
//!   走 `eprintln!` warn 跳过,**不**panic / **不**fail-closed(Phase 1 决议)。
//! - `OrtEngine` 内部 `Mutex<Session>`:rc.12 `Session::run` 需要 `&mut self`,
//!   `infer(&self, ..)` 用 Mutex 包外让 trait 保持 `&self`(锁开销 ns 级 vs 推理 358-630 ms)。

use crate::merge::Finding;
use crate::scan::ScanError;
use thiserror::Error;

/// 引擎私有诊断错误。
///
/// 6 变体覆盖从模型加载到张量解码的全链路失败模式;**绝不**持有 `ort::Error`
/// 本身(rc.12 该类型非 `Send + Sync`,会污染 trait object 边界)。所有 ort/tokenizer
/// 错误一律 `e.to_string()` 后塞进 `String` 字段。
///
/// caller 拿到的不是这个类型 —— `From<EngineError> for ScanError` 把 6 变体
/// 全塌缩到 [`ScanError::InferenceFailed`],只暴露统一的 `reason`。
#[derive(Error, Debug)]
pub enum EngineError {
    /// 指定 dir 下缺少模型文件(`tokenizer.json` / `config.json` / `model_q4f16.onnx`
    /// 三件齐全才算就绪)或 `VIGIL_PRIVACY_FILTER_MODEL_DIR` 未设置。
    #[error("model not found in directory: {dir}")]
    ModelNotFound {
        /// 失败时尝试加载的目录(诊断用,不含模型权重内容)
        dir: String,
    },
    /// `tokenizers::Tokenizer::from_file` 失败。内部串来自 tokenizers crate。
    #[error("tokenizer load failed: {0}")]
    TokenizerLoad(String),
    /// ORT `Session::builder` / `commit_from_file` / 优化等级设置等 init 阶段失败。
    #[error("ORT session init failed: {0}")]
    SessionInit(String),
    /// 推理执行阶段失败(`tokenizer.encode` / `session.run`)。
    #[error("inference run failed: {0}")]
    InferRun(String),
    /// 输出张量 shape 不符预期或 `try_extract_tensor::<f32>` 失败。
    #[error("decode tensor shape failed: {0}")]
    DecodeShape(String),
    /// 其它内部错误(config.json 解析 / Mutex poisoned 等),用兜底变体避免新增 variant
    /// 立刻冲击 caller。
    #[error("internal engine error: {0}")]
    Internal(String),
}

impl From<EngineError> for ScanError {
    fn from(e: EngineError) -> Self {
        // 6 变体全塌缩到 InferenceFailed;reason 只来自 e.to_string(),
        // 绝不拼接 input 内容(避免 caller 把原文 secret 写进 audit log)。
        ScanError::InferenceFailed {
            reason: format!("{e}"),
        }
    }
}

/// Privacy Filter 推理引擎抽象。`scan_text_with_engine` 通过本 trait 拿 Model 侧 findings,
/// 与 Hard 侧 [`crate::scan::collect_hard_findings`] 输出送 `merge_findings` 决策合并。
///
/// 实现要求:
/// - 必须 `Send + Sync`(由 trait bound 强制;`scan_text_with_engine` 接 `&dyn`,
///   线程边界由 caller 决定)。
/// - `infer` 失败应返 [`EngineError`] 各分类;`scan_text_with_engine` 经
///   `From<EngineError> for ScanError` 自动转 [`ScanError::InferenceFailed`]。
/// - 返回的 `Finding` `risk_delta` **可填 0**:caller 在 `scan_text_with_engine` 内会
///   按 `risk_of(kind)` 重新补值(engine 与 risk 表彻底解耦,SSOT 见 ADR 0012 §1.3)。
///   `kind` 字段必须是 `&'static str`(由 [`crate::label::PrivacyLabel::as_str`] 提供)。
pub trait RedactionEngine: Send + Sync {
    /// 对 `text` 做模型推理,返回 Model 侧 findings。
    ///
    /// # Errors
    /// 任意 [`EngineError`] 变体表示推理失败;caller 的 `scan_text_with_engine`
    /// 会以 `?` 转 [`ScanError::InferenceFailed`] 早返(fail-closed)。
    fn infer(&self, text: &str) -> Result<Vec<Finding>, EngineError>;

    /// **v0.9 Sprint 1 P1.2** — 带 lang 上下文的推理(spike)。
    ///
    /// **default 实现**:忽略 `lang` 参数,委托 [`Self::infer`](向后兼容,SemVer
    /// 安全;现有 RedactionEngine 实现不需改)。
    ///
    /// **OrtEngine override**:若 descriptor 提供
    /// [`crate::model_descriptor::LangConditionalThresholdProfile`](通过新方法
    /// `lang_conditional_profile()`),threshold 应用时优先查
    /// `(lang, label)` override;无则 fallback default profile。
    ///
    /// **lang 规范**:case-sensitive,推荐 ISO 639-1 lowercase(`"en"` / `"de"` /
    /// `"it"` / `"fr"` / ...),与 fixture lang 字段对齐。`None` 等价 `infer()`
    /// 行为(无 lang 上下文)。
    fn infer_with_lang(
        &self,
        text: &str,
        _lang: Option<&str>,
    ) -> Result<Vec<Finding>, EngineError> {
        self.infer(text)
    }
}

/// "什么也不做"的引擎:始终返回空 Model findings。
///
/// 用途:让 [`crate::scan::scan_text`] 公共 API 可 delegating 到
/// `scan_text_with_engine(input, &NoopEngine)`,默认 feature 路径 0 ort 依赖,
/// 而行为与 Stage 1 scaffold "Hard + 空 Model" 完全等价。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEngine;

impl RedactionEngine for NoopEngine {
    fn infer(&self, _text: &str) -> Result<Vec<Finding>, EngineError> {
        Ok(Vec::new())
    }
}

/// 测试 / 集成用:固定返回构造时给的 findings 切片。
///
/// 用于在不接真模型的前提下走通 `scan_text_with_engine` → merge 链路,验证
/// risk_delta 注入 / merge / aggregate 各环节(无 ort 依赖,默认 feature 即可用)。
#[derive(Debug, Default, Clone)]
pub struct MockEngine {
    findings: Vec<Finding>,
}

impl MockEngine {
    /// 用一组预设 findings 构造 mock(每次 `infer` 都克隆返出)。
    pub fn from_findings(findings: Vec<Finding>) -> Self {
        Self { findings }
    }
}

impl RedactionEngine for MockEngine {
    fn infer(&self, _text: &str) -> Result<Vec<Finding>, EngineError> {
        Ok(self.findings.clone())
    }
}

// 编译期 Send + Sync 守门(默认 feature)。新增引擎类型必须同步进这里。
#[cfg(test)]
mod static_assertions {
    use super::*;
    fn _assert_send_sync<T: Send + Sync>() {}
    #[allow(dead_code)]
    fn _check() {
        _assert_send_sync::<MockEngine>();
        _assert_send_sync::<NoopEngine>();
        _assert_send_sync::<Box<dyn RedactionEngine>>();
    }
}

// ──────────────────────────── ORT 真推理引擎(feature gated)────────────────────────────

#[cfg(feature = "ort")]
mod ort_engine {
    use super::{EngineError, Finding, RedactionEngine};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use ort::execution_providers::CPUExecutionProvider;
    use ort::inputs;
    use ort::session::{builder::GraphOptimizationLevel, Session};
    use ort::value::Value;
    use tokenizers::Tokenizer;

    /// ORT 1.24 q4f16 Privacy Filter 模型推理引擎。
    ///
    /// **生命周期纪律**(ISS-022 Phase 2 实测,详见 `project_vigil_v04_iss022_done.md`):
    /// - cold-start ~7 s(commit_from_file + 809 MB weights);构造一次长期持有,
    ///   不要把 [`OrtEngine::from_env`] 放进 hot path。
    /// - warm 推理 358-630 ms / sample(CPU);Stage 2 API 必须 async 化(ADR 0013)。
    ///
    /// **线程模型**:
    /// - rc.12 `Session::run` 需 `&mut self`(spike `main.rs:165` 实测)。我们让
    ///   `OrtEngine.session` 持 `Mutex<Session>`,trait 保持 `infer(&self, ..)`。
    ///   锁开销纳秒级,与 358 ms 推理相比可忽略;并发场景由 caller 决定是否多实例。
    pub struct OrtEngine {
        session: Mutex<Session>,
        tokenizer: Tokenizer,
        /// 由 `config.json` 解析得;index = label_id,value = label 字面量(可能含 BIOES 前缀)。
        id2label: Vec<String>,
        /// 仅供 `Debug` / 诊断;不参与推理逻辑。
        #[allow(dead_code)]
        model_dir: PathBuf,
        /// v0.7-α3 Phase 3 S2(E6a):descriptor 决定 decode kind + canonical mapping;
        /// 默认 [`OpenAIPrivacyFilterDescriptor`] 保 v0.6 回归不变;新模型走
        /// [`Self::from_env_with_descriptor`] 注入。
        descriptor: Box<dyn crate::model_descriptor::ModelDescriptor>,
    }

    impl std::fmt::Debug for OrtEngine {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // Session / Tokenizer 不实现 Debug 或 Debug 输出冗长,这里只露诊断字段。
            f.debug_struct("OrtEngine")
                .field("model_dir", &self.model_dir)
                .field("id2label_count", &self.id2label.len())
                .finish_non_exhaustive()
        }
    }

    impl OrtEngine {
        /// 从环境变量 `VIGIL_PRIVACY_FILTER_MODEL_DIR`(absolute path)读模型并构造 Session。
        ///
        /// 模型目录必须包含三件套:`tokenizer.json` / `config.json` / `model_q4f16.onnx`。
        /// 三件齐全才算就绪;任一缺失返 [`EngineError::ModelNotFound`]。
        ///
        /// # Errors
        /// - [`EngineError::ModelNotFound`]:env 未设置 / dir 不存在 / 三件套缺失
        /// - [`EngineError::TokenizerLoad`] / [`EngineError::SessionInit`] / [`EngineError::Internal`]:
        ///   底层 init 失败(具体 e.to_string() 进 `String` 字段)
        pub fn from_env() -> Result<Self, EngineError> {
            let dir = std::env::var("VIGIL_PRIVACY_FILTER_MODEL_DIR").map_err(|_| {
                EngineError::ModelNotFound {
                    dir: "<env unset>".to_string(),
                }
            })?;
            let model_dir = PathBuf::from(&dir);
            let tok_path = model_dir.join("tokenizer.json");
            let cfg_path = model_dir.join("config.json");
            let onnx_path = model_dir.join("model_q4f16.onnx");
            // 三件齐全检查(spike 同口径);任一缺失即视为模型未就绪
            for p in [&tok_path, &cfg_path, &onnx_path] {
                if !p.exists() {
                    return Err(EngineError::ModelNotFound { dir: dir.clone() });
                }
            }

            let tokenizer = Tokenizer::from_file(&tok_path)
                .map_err(|e| EngineError::TokenizerLoad(e.to_string()))?;
            let id2label = parse_id2label(&cfg_path)?;

            // ort::init().commit() 在 rc.12 返 bool(成功 / 重复 init 都返 ok),不返 Result。
            // 多次 init 无副作用(spike main.rs:31)。
            let _ = ort::init()
                .with_name("vigil-redaction-ort")
                .with_execution_providers([CPUExecutionProvider::default().build()])
                .commit();

            let session = Session::builder()
                .map_err(|e| EngineError::SessionInit(e.to_string()))?
                .with_optimization_level(GraphOptimizationLevel::Level1)
                .map_err(|e| EngineError::SessionInit(e.to_string()))?
                .with_intra_threads(4)
                .map_err(|e| EngineError::SessionInit(e.to_string()))?
                .commit_from_file(&onnx_path)
                .map_err(|e| EngineError::SessionInit(e.to_string()))?;

            Ok(Self {
                session: Mutex::new(session),
                tokenizer,
                id2label,
                model_dir,
                // 默认 OpenAIPrivacyFilterDescriptor(BIOES 解码 + 33-class id2label)
                // 保 v0.6 回归不变;新模型走 from_env_with_descriptor 工厂
                descriptor: Box::new(crate::model_descriptor::OpenAIPrivacyFilterDescriptor),
            })
        }

        /// v0.7-α3 Phase 3 S2(E6a):带 descriptor 注入的工厂,支持 BIO scheme 模型。
        ///
        /// 与 [`Self::from_env`] 区别:descriptor 决定 decode kind(BIOES vs BIO)+
        /// canonical_mapping(影响 [`crate::PrivacyLabel::from_kind`] 路由)。
        ///
        /// **典型用例**:
        /// - xlmr-pii(BIO):`from_env_with_descriptor(Box::new(XlmrPiiDescriptor))`
        /// - yonigo-pii(BIO):`from_env_with_descriptor(Box::new(YonigoPiiDescriptor))`
        /// - openai(默认 BIOES):`from_env()`(等价 [`OpenAIPrivacyFilterDescriptor`])
        ///
        /// **环境变量**与 [`Self::from_env`] 一致使用 `VIGIL_PRIVACY_FILTER_MODEL_DIR`。
        /// 若 ensemble 多模型场景需独立路径,用 [`Self::from_dir_with_descriptor`]。
        #[allow(dead_code)]
        pub fn from_env_with_descriptor(
            descriptor: Box<dyn crate::model_descriptor::ModelDescriptor>,
        ) -> Result<Self, EngineError> {
            let mut engine = Self::from_env()?;
            engine.descriptor = descriptor;
            Ok(engine)
        }

        /// v0.7-α3 Phase 3 S4(E6a):从指定目录构造 OrtEngine + descriptor 注入。
        ///
        /// 与 [`Self::from_env_with_descriptor`] 区别:**不**读 env,直接接 `dir`
        /// 参数。专为 ensemble 多模型场景:每模型独立 dir,避免 env var 互斥。
        ///
        /// **典型用例**(ensemble runtime):
        /// ```ignore
        /// use std::sync::Arc;
        /// use std::path::Path;
        /// use vigil_redaction::OrtEngine;
        /// use vigil_redaction::EnsembleEngine;
        /// // (model_descriptor 是 crate-private,这里仅示意)
        /// // let openai = Arc::new(OrtEngine::from_dir_with_descriptor(
        /// //     Path::new("/var/vigil/models/openai-pf/v1"),
        /// //     Box::new(OpenAIPrivacyFilterDescriptor),
        /// // ).unwrap());
        /// // let xlmr = Arc::new(OrtEngine::from_dir_with_descriptor(...).unwrap());
        /// // let ens = EnsembleEngine::new(vec![openai, xlmr]);
        /// ```
        ///
        /// **三件套契约**与 [`Self::from_env`] 同口径:`tokenizer.json` /
        /// `config.json` / `model_q4f16.onnx`(后续可能扩 model.onnx)三件齐全。
        ///
        /// # Errors
        /// - [`EngineError::ModelNotFound`]:dir 不存在或三件套缺失
        /// - [`EngineError::TokenizerLoad`] / [`EngineError::SessionInit`] /
        ///   [`EngineError::Internal`]:底层 init 失败
        #[allow(dead_code)]
        pub fn from_dir_with_descriptor(
            dir: &Path,
            descriptor: Box<dyn crate::model_descriptor::ModelDescriptor>,
        ) -> Result<Self, EngineError> {
            let dir_str = dir.to_string_lossy().into_owned();
            let model_dir = dir.to_path_buf();
            let tok_path = model_dir.join("tokenizer.json");
            let cfg_path = model_dir.join("config.json");
            // v0.7-α4 R1b:用 descriptor.onnx_filename() 取代 hardcoded "model_q4f16.onnx",
            // 适配多模型布局(OpenAI 顶层 / xlmr 在 onnx/ 子目录 / yonigo model.onnx)
            let onnx_path = model_dir.join(descriptor.onnx_filename());
            for p in [&tok_path, &cfg_path, &onnx_path] {
                if !p.exists() {
                    return Err(EngineError::ModelNotFound {
                        dir: dir_str.clone(),
                    });
                }
            }
            let tokenizer = Tokenizer::from_file(&tok_path)
                .map_err(|e| EngineError::TokenizerLoad(e.to_string()))?;
            let id2label = parse_id2label(&cfg_path)?;
            let _ = ort::init()
                .with_name("vigil-redaction-ort")
                .with_execution_providers([CPUExecutionProvider::default().build()])
                .commit();
            let session = Session::builder()
                .map_err(|e| EngineError::SessionInit(e.to_string()))?
                .with_optimization_level(GraphOptimizationLevel::Level1)
                .map_err(|e| EngineError::SessionInit(e.to_string()))?
                .with_intra_threads(4)
                .map_err(|e| EngineError::SessionInit(e.to_string()))?
                .commit_from_file(&onnx_path)
                .map_err(|e| EngineError::SessionInit(e.to_string()))?;
            Ok(Self {
                session: Mutex::new(session),
                tokenizer,
                id2label,
                model_dir,
                descriptor,
            })
        }

        /// 返回当前 engine 装载的 descriptor model_id(诊断 / audit 关联)。
        #[allow(dead_code)] // S3 EnsembleEngine 用此调度三引擎
        pub fn descriptor_model_id(&self) -> &str {
            self.descriptor.model_id()
        }

        /// v0.7-α2 Phase 2B(ADR 0016):预热 ORT session,把 cold inference 摊到启动期。
        ///
        /// **意图**:首次 [`infer`] 调用包含 graph optimization / kernel JIT / arena
        /// 分配等 cold-path 开销(实测 ~7s on CPU q4f16);本 API 用 1-token 短文本
        /// 触发同样路径,把 cold 开销前移到 app 启动 / 模型分发完成时,真正 user
        /// 请求即落 warm 路径(实测 ~462ms/sample)。
        ///
        /// **不变量保留**:
        /// - 仅消耗 1 次推理预算(短 prompt,~ms 级 token 数);不写日志、不影响 ledger
        /// - 失败传 [`EngineError`] 但 caller 一般忽略(预热失败应不影响 cold-path 退化能力);
        ///   推荐 caller `let _ = engine.warmup();` fire-and-forget
        /// - 线程安全:与 `infer` 同走 `Mutex<Session>` 锁路径
        ///
        /// # 推荐用法
        ///
        /// apps/desktop GUI build 启动时异步 spawn:
        /// ```ignore
        /// let engine = Arc::new(OrtEngine::from_env()?);
        /// std::thread::spawn({
        ///     let e = engine.clone();
        ///     move || { let _ = e.warmup(); }
        /// });
        /// ```
        ///
        /// # Errors
        /// 同 [`infer`]:任何推理路径错误都会 propagate;caller 通常忽略。
        pub fn warmup(&self) -> Result<(), EngineError> {
            // 用单字符短文本(tokenizer 至少给 [CLS]+[SEP],seq_len ≥ 2);
            // 推理结果丢弃,目的纯粹是触发 cold-path 一次性开销
            let _ = <Self as RedactionEngine>::infer(self, "a")?;
            Ok(())
        }
    }

    impl RedactionEngine for OrtEngine {
        fn infer(&self, text: &str) -> Result<Vec<Finding>, EngineError> {
            // **v0.9 Sprint 1 P1.2**:legacy 路径 → infer_with_lang(text, None)
            // (lang None 等价 v0.8 行为,threshold 走 threshold_profile() default;
            // 不引入 LangConditionalThresholdProfile.overrides — caller 没 lang 上下文)
            self.infer_with_lang(text, None)
        }

        fn infer_with_lang(
            &self,
            text: &str,
            lang: Option<&str>,
        ) -> Result<Vec<Finding>, EngineError> {
            // ─── 1. tokenize ───
            let enc = self
                .tokenizer
                .encode(text, true)
                .map_err(|e| EngineError::InferRun(e.to_string()))?;
            let ids: Vec<i64> = enc.get_ids().iter().map(|&i| i as i64).collect();
            let mask: Vec<i64> = enc.get_attention_mask().iter().map(|&m| m as i64).collect();
            let offsets = enc.get_offsets().to_vec();
            let seq_len = ids.len();
            if seq_len == 0 {
                // 空 token 序列(理论上 tokenizer 至少给 [CLS]/[SEP],但保守兜底)
                return Ok(Vec::new());
            }

            // ─── 2. 构 Value(spike main.rs:179-182 形态)───
            let input_ids_val = Value::from_array((vec![1i64, seq_len as i64], ids))
                .map_err(|e| EngineError::DecodeShape(e.to_string()))?;
            let mask_val = Value::from_array((vec![1i64, seq_len as i64], mask))
                .map_err(|e| EngineError::DecodeShape(e.to_string()))?;

            // ─── 3 + 4. session.run + 提取 logits(都在锁内,因为 SessionOutputs<'_>
            //          借 session;锁外只持 owned (shape, data) 副本以解耦借用)───
            let (shape, data): (Vec<i64>, Vec<f32>) = {
                let mut session = self
                    .session
                    .lock()
                    .map_err(|e| EngineError::Internal(format!("session mutex poisoned: {e}")))?;
                let outputs = session
                    .run(inputs![
                        "input_ids" => input_ids_val,
                        "attention_mask" => mask_val,
                    ])
                    .map_err(|e| EngineError::InferRun(e.to_string()))?;

                // 取 logits 张量(spike main.rs:192-198)。try_extract_tensor 借 outputs,
                // outputs 又借 session;必须在锁释放前把数据 to_vec 出来。
                let (_name, logits_val) = outputs
                    .iter()
                    .next()
                    .ok_or_else(|| EngineError::DecodeShape("no output tensor".to_string()))?;
                let (raw_shape, raw_data) = logits_val
                    .try_extract_tensor::<f32>()
                    .map_err(|e| EngineError::DecodeShape(e.to_string()))?;
                (raw_shape.to_vec(), raw_data.to_vec())
                // session 锁在此 block 末释放,后续是纯 CPU 解码不持锁
            };

            if shape.len() != 3 || shape[0] != 1 || shape[1] as usize != seq_len {
                return Err(EngineError::DecodeShape(format!(
                    "unexpected logits shape: {shape:?}"
                )));
            }
            let num_labels = shape[2] as usize;

            // ─── 5. argmax + max-shifted softmax(spike main.rs:201-211)───
            // 注:`1.0 / sum_exp` 是 max-shifted softmax 的等价写法
            // (exp(max - max) / Σexp(x - max) = 1 / Σ);保持与 spike 一致避免误改。
            let mut token_preds: Vec<(usize, f32)> = Vec::with_capacity(seq_len);
            for t in 0..seq_len {
                let base = t * num_labels;
                let slice = &data[base..base + num_labels];
                let (arg, max_logit) = slice.iter().enumerate().fold(
                    (0usize, f32::NEG_INFINITY),
                    |(ai, av), (i, &v)| if v > av { (i, v) } else { (ai, av) },
                );
                let sum: f32 = slice.iter().map(|&v| (v - max_logit).exp()).sum();
                let conf = if sum > 0.0 { 1.0 / sum } else { 0.0 };
                token_preds.push((arg, conf));
            }

            // ─── 6. 合并 BIOES 同 core label 的连续 token 为 span ───
            //       (spike main.rs:214-247 同算法)
            let mut findings: Vec<Finding> = Vec::new();
            let mut i = 0usize;
            while i < seq_len {
                let (lid, conf) = token_preds[i];
                let label_raw = &self.id2label[lid];
                if label_raw == "O" || label_raw.is_empty() {
                    i += 1;
                    continue;
                }
                let core_raw = strip_bioes(label_raw);
                let start = offsets[i].0;
                let mut end = offsets[i].1;
                let mut conf_min = conf;
                let mut j = i + 1;
                while j < seq_len {
                    let (nid, nconf) = token_preds[j];
                    let nlabel = &self.id2label[nid];
                    if nlabel == "O" || strip_bioes(nlabel) != core_raw {
                        break;
                    }
                    end = offsets[j].1;
                    conf_min = conf_min.min(nconf);
                    j += 1;
                }

                if start < end && end <= text.len() {
                    // ─── 7. canonical mapping via ModelDescriptor(v0.7-α3 S2)───
                    //       descriptor.canonical_mapping(core_raw) 路由到 8 类 PrivacyLabel;
                    //       OpenAI descriptor 内部 normalize lowercase,xlmr/yonigo 直
                    //       match uppercase 字面量。SSOT 移到 descriptor,engine 不再
                    //       hardcode PrivacyLabel::from_kind 路径,使新模型不需改 engine。
                    match self.descriptor.canonical_mapping(core_raw) {
                        Some(label) => {
                            // ─── v0.7-α4 R1h + v0.9 Sprint 1 P1.2 — threshold filter ───
                            // 优先级:
                            // 1. lang_conditional_profile().threshold_for(label, lang)
                            //    (P1.2 新路径 — caller 提供 lang 时命中 (lang, label)
                            //    override,否则该 profile 自身的 default)
                            // 2. fallback threshold_profile()(legacy / lang None 路径)
                            //
                            // > 1.0 阈值等价"屏蔽该 label",留给互补 engine + Hard
                            // rules 兜底。**关键**:不能用 `continue`(会跳过外层
                            // `i = j.max(i + 1)` 推进导致死循环);用 if-pass 包 push。
                            let min_conf_opt = self
                                .descriptor
                                .lang_conditional_profile()
                                .and_then(|p| p.threshold_for(label, lang))
                                .or_else(|| {
                                    self.descriptor
                                        .threshold_profile()
                                        .and_then(|p| p.thresholds.get(&label).copied())
                                });
                            let pass_threshold = min_conf_opt
                                .map(|min_conf| conf_min >= min_conf)
                                .unwrap_or(true);
                            if pass_threshold {
                                // Finding.kind 是 &'static str,这里用 PrivacyLabel::as_str()
                                // 拿 'static 字面量(label.rs::as_str 已是 'static 契约)。
                                // risk_delta 由 caller `scan_text_with_engine` 按 risk_of(kind)
                                // 重新补值(C-7 决议:engine 不依赖 risk 表,避免漂移)。
                                findings.push(Finding::model(
                                    label.as_str(),
                                    (start, end),
                                    conf_min,
                                    0,
                                ));
                            }
                            // pass_threshold == false → silent drop(R1h FP filter)
                        }
                        None => {
                            // descriptor 显式 None = 该 native label 在 canonical 8 类外
                            // 应忽略(如 OpenAI/xlmr 的 AGE/GENDER/SEX);非显式漏(隐式
                            // 遗漏由 assert_canonical_mapping_total 测试守门捕获)。
                            // 不再 stderr warn 避免噪声(改 quiet 跳过)。
                        }
                    }
                }
                i = j.max(i + 1);
            }
            Ok(findings)
        }
    }

    /// 剥 BIOES 前缀:`B-Person` / `I-Person` / `E-Person` / `S-Person` → `Person`。
    /// 非 BIOES 前缀的 label 原样返回(例如 spike 模型可能直出 `private_email`)。
    fn strip_bioes(label: &str) -> &str {
        if let Some((prefix, rest)) = label.split_once('-') {
            if matches!(prefix, "B" | "I" | "E" | "S") {
                return rest;
            }
        }
        label
    }

    /// 从 `config.json` 抽 `id2label` 表,按 id 升序还原 `Vec<String>`。
    /// HF 标准 config 格式:`{"id2label": {"0": "O", "1": "B-Person", ...}}`。
    fn parse_id2label(cfg_path: &Path) -> Result<Vec<String>, EngineError> {
        let raw = std::fs::read_to_string(cfg_path)
            .map_err(|e| EngineError::Internal(format!("read config.json: {e}")))?;
        let cfg: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| EngineError::Internal(format!("parse config.json: {e}")))?;
        let id2label = cfg
            .get("id2label")
            .and_then(|v| v.as_object())
            .ok_or_else(|| EngineError::Internal("config.json missing id2label".to_string()))?;
        let mut entries: Vec<(usize, String)> = id2label
            .iter()
            .map(|(k, v)| {
                (
                    k.parse().unwrap_or(0),
                    v.as_str().unwrap_or("?").to_string(),
                )
            })
            .collect();
        entries.sort_by_key(|&(id, _)| id);
        Ok(entries.into_iter().map(|(_, n)| n).collect())
    }

    // 编译期 Send + Sync 守门(--features ort 路径)
    #[cfg(test)]
    mod ort_static_assertions {
        use super::*;
        fn _assert_send_sync<T: Send + Sync>() {}
        #[allow(dead_code)]
        fn _check() {
            _assert_send_sync::<OrtEngine>();
        }
    }
}

#[cfg(feature = "ort")]
pub use ort_engine::OrtEngine;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge::FindingSource;

    #[test]
    fn noop_engine_returns_empty_findings() {
        let engine = NoopEngine;
        let result = engine.infer("anything").expect("noop should not fail");
        assert!(result.is_empty(), "NoopEngine 必须返空 Vec");
    }

    #[test]
    fn mock_engine_returns_preset_findings() {
        let preset = vec![
            Finding::model("private_person", (0, 5), 0.9, 5),
            Finding::model("private_email", (10, 30), 0.95, 10),
        ];
        let engine = MockEngine::from_findings(preset.clone());
        let got = engine.infer("ignored").expect("mock should not fail");
        assert_eq!(got, preset, "MockEngine 应原样返回构造时的 findings");
        // 第二次调用不应被消耗
        let got2 = engine.infer("ignored").expect("mock again");
        assert_eq!(got2, preset);
    }

    #[test]
    fn mock_engine_default_is_empty() {
        let engine = MockEngine::default();
        let got = engine.infer("anything").expect("default mock");
        assert!(got.is_empty());
    }

    #[test]
    fn engine_error_to_scan_error_collapses_to_inference_failed() {
        let cases: Vec<(EngineError, &str)> = vec![
            (
                EngineError::ModelNotFound {
                    dir: "/tmp/x".to_string(),
                },
                "model not found",
            ),
            (
                EngineError::TokenizerLoad("bad json".to_string()),
                "tokenizer load",
            ),
            (
                EngineError::SessionInit("ort init fail".to_string()),
                "session init",
            ),
            (
                EngineError::InferRun("session.run fail".to_string()),
                "inference run",
            ),
            (
                EngineError::DecodeShape("bad shape".to_string()),
                "decode tensor",
            ),
            (
                EngineError::Internal("config.json missing".to_string()),
                "internal",
            ),
        ];
        for (e, fragment) in cases {
            let scan_err: ScanError = e.into();
            // 6 EngineError 变体必须全塌缩到 InferenceFailed,先用 matches! 守门塌缩走向,
            // 再单独取 reason 校验包含原 Display 片段(避免单 if-let 的 else 走 panic!,
            // 兼顾 workspace clippy::panic + clippy::assertions_on_constants 双严格规则)。
            assert!(
                matches!(scan_err, ScanError::InferenceFailed { .. }),
                "EngineError 应塌缩到 InferenceFailed,实际:{scan_err:?}"
            );
            if let ScanError::InferenceFailed { reason } = scan_err {
                assert!(
                    reason.contains(fragment),
                    "InferenceFailed.reason 应含原 EngineError Display 片段 {fragment:?},\
                     实际 reason = {reason:?}"
                );
            }
        }
    }

    #[test]
    fn mock_engine_finding_source_is_model() {
        let preset = vec![Finding::model("private_phone", (0, 11), 0.88, 5)];
        let engine = MockEngine::from_findings(preset);
        let got = engine.infer("ignored").expect("mock");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].source, FindingSource::Model);
    }

    // ─────────── v0.7-α3 S2 守门 ───────────

    /// OrtEngine.from_env_with_descriptor 在 env 缺失时返 ModelNotFound 不 panic。
    /// 与 from_env 同 fail-fast 口径(沿用 ADR 0012)。
    #[cfg(feature = "ort")]
    #[test]
    fn ort_engine_from_env_with_descriptor_env_miss_returns_modelnotfound() {
        if std::env::var("VIGIL_PRIVACY_FILTER_MODEL_DIR").is_ok() {
            eprintln!("skip: env already set");
            return;
        }
        // 注入 XlmrPiiDescriptor — 工厂应仍 fail-fast 在 env miss(因为没有真模型路径)
        let r = OrtEngine::from_env_with_descriptor(Box::new(
            crate::model_descriptor::XlmrPiiDescriptor::default(),
        ));
        assert!(
            matches!(r, Err(EngineError::ModelNotFound { .. })),
            "env unset 应返 ModelNotFound,实际: {:?}",
            r.map(|_| "Ok(engine)")
        );
    }

    /// 三 descriptor 类型可作为 Box<dyn ModelDescriptor> 注入(类型层兼容守门)。
    /// 编译期检查;不需真 ort 模型。
    #[test]
    fn descriptors_dyn_box_compatible_with_engine_field() {
        // 编译期类型测试:Box<dyn ModelDescriptor> 可装载 3 个实例,符合 OrtEngine.descriptor 字段类型
        let _list: Vec<Box<dyn crate::model_descriptor::ModelDescriptor>> = vec![
            Box::new(crate::model_descriptor::OpenAIPrivacyFilterDescriptor),
            Box::new(crate::model_descriptor::XlmrPiiDescriptor::default()),
            Box::new(crate::model_descriptor::YonigoPiiDescriptor),
        ];
    }

    /// S4(E6a):from_dir_with_descriptor 在 dir 不存在时返 ModelNotFound 不 panic。
    #[cfg(feature = "ort")]
    #[test]
    fn ort_engine_from_dir_with_descriptor_missing_dir_returns_modelnotfound() {
        use std::path::Path;
        let bogus_dir = Path::new("/nonexistent/vigil/spike-p3/model");
        let r = OrtEngine::from_dir_with_descriptor(
            bogus_dir,
            Box::new(crate::model_descriptor::XlmrPiiDescriptor::default()),
        );
        assert!(
            matches!(r, Err(EngineError::ModelNotFound { .. })),
            "不存在 dir 应返 ModelNotFound,实际: {:?}",
            r.map(|_| "Ok(engine)")
        );
    }
}
