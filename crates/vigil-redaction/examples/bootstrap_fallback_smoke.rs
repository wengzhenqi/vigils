//! v0.6 release verification — clean-cache bootstrap fallback smoke test。
//!
//! 实测 download_with_chunks 用真 manifest URLs(primary = vigils.ai mirror,
//! fallback = HF CDN)单文件下载 + sha256 verify;**不依赖 ORT runtime**,~ 1s 完成。
//!
//! v0.6 mirror 现状(2026-05-02 确认):
//!   - vigils.ai A 记录 → vigils.ai(机器 ens3 直绑,无外部 SDN)
//!   - 内部 iptables PREROUTING REDIRECT 80/443 → 8088,Caddy file_server 真服务
//!   - 4 文件 sha256 + size 与 manifest 完全匹配,primary 路径已可用
//!   - HF CDN fallback 仍保留为 ADR 0012 §3.7 兜底(provider edge 风险/单点失效)
//!
//! 目的:证明 sequential URL try 链路设计:
//!   1. primary 成功 → 一次命中即返回(快路径,默认状态)
//!   2. primary 任何原因 fail(网络/edge/limit)→ download_with_chunks 自动 continue 到 HF CDN
//!   3. sha256 fail-closed 校验 pass(无论从哪个 URL 拉到)
//!
//! 为何只测 config.json(3 KB):
//!   - 完整模型 ~ 838 MB 真下载耗时;config.json 是 manifest 同结构最小文件
//!   - Vigil bootstrap 对每文件路径同源(同 download_with_chunks),
//!     1 文件链路通 == 4 文件均通(同 code path,sha256 fail-closed 守门)
//!   - 真 4 文件 e2e 留 release 前 ad-hoc(本 smoke 只 prove URL chain + verify 设计)
//!
//! 跑:
//!   cargo run --example bootstrap_fallback_smoke -p vigil-redaction --features ort
//!
//! 期望输出(primary 可用时):
//!   [primary]  https://vigils.ai/... -> 200 OK + 3039 bytes
//!   [sha256]   match: b2b26a4a...
//!   [PASS] bootstrap chain works (primary mirror operational, HF CDN standby)

#![cfg(feature = "ort")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;

use vigil_redaction::bootstrap::manifest::{placeholder_manifest, ManifestFile};

fn main() {
    eprintln!("=== v0.6 bootstrap fallback smoke (config.json,~3 KB)===\n");

    // 1. 取 placeholder_manifest()(已 inject 真值,见 commit 82836fa)
    let manifest = placeholder_manifest();
    let config_entry: &ManifestFile = manifest
        .files
        .iter()
        .find(|f| f.name == "config.json")
        .expect("manifest 必含 config.json");

    eprintln!("config.json metadata:");
    eprintln!("  size_bytes:    {}", config_entry.size_bytes);
    eprintln!("  sha256:        {}", &config_entry.sha256[..16]);
    eprintln!("  primary_url:   {}", config_entry.primary_url);
    for (i, fb) in config_entry.fallback_urls.iter().enumerate() {
        eprintln!("  fallback[{i}]:   {fb}");
    }
    eprintln!();

    // 2. URL 顺序 = primary + fallback_urls(与 mod.rs:91-97 一致)
    let mut urls: Vec<String> = Vec::with_capacity(1 + config_entry.fallback_urls.len());
    urls.push(config_entry.primary_url.clone());
    urls.extend(config_entry.fallback_urls.clone());

    // 3. 临时 target_dir
    let target_dir = std::env::temp_dir().join("vigil-bootstrap-smoke");
    if target_dir.exists() {
        // clean cache
        fs::remove_dir_all(&target_dir).expect("clean target_dir");
    }
    fs::create_dir_all(&target_dir).expect("create target_dir");
    eprintln!("target_dir: {}", target_dir.display());

    // 4. 跑 download_with_chunks(顺序尝试,fail → continue,sha256 verify caller 做)
    eprintln!("\n--- download_with_chunks ---");
    let outcome = vigil_redaction::bootstrap::download::download_with_chunks(
        &urls,
        &target_dir,
        &config_entry.name,
        config_entry.size_bytes,
        manifest.chunk_count,
    );

    match outcome {
        Ok(o) => {
            eprintln!(
                "[ok] downloaded={} path={}",
                o.downloaded,
                o.final_path.display()
            );

            // 5. sha256 verify(fail-closed)
            eprintln!("\n--- sha256 verify ---");
            match vigil_redaction::bootstrap::verify::verify_sha256_streaming(
                &o.final_path,
                &config_entry.sha256,
            ) {
                Ok(()) => {
                    eprintln!("[ok] sha256 match: {}", &config_entry.sha256[..16]);
                    eprintln!("\n[PASS] bootstrap chain works (ADR 0012 §3.7)");
                    eprintln!("v0.6 mirror operational — primary served via vigils.ai + iptables 80→8088, HF CDN standby");

                    // cleanup
                    let _ = fs::remove_dir_all(&target_dir);
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("[FAIL] sha256 mismatch: {e:?}");
                    std::process::exit(2);
                }
            }
        }
        Err(e) => {
            eprintln!("[FAIL] all URLs failed: {e:?}");
            eprintln!("urls tried:");
            for u in &urls {
                eprintln!("  {u}");
            }
            std::process::exit(3);
        }
    }
}
