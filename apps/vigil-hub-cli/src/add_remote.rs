//! `vigil-hub add-remote-mcp` 子命令实装(I10b-β)。
//!
//! 流程串联(ADR 0011 §5):
//!   PRM discover → AS metadata discover → loopback bind → browser open →
//!   authorize URL → wait for callback → exchange code → token persist。
//!
//! **β R1 修订**:`run` 接 `Deps` 依赖注入(SecretStore factory / HttpClient
//! factory),prod 路径用 `KeyringSecretStore` + `ReqwestHttpClient`,CLI 集成测试
//! 注入 InMemorySecretStore + 自签 CA 客户端。

use std::sync::Arc;

use oauth2::CsrfToken;
use url::Url;

use vigil_audit::Ledger;
use vigil_http_auth::{
    build_authorization_url, exchange_code_for_token, fetch_and_validate_prm, new_pkce_pair,
    token_ref_for_access, token_ref_for_refresh, HttpClient, OAuthTokenMetadata, TokenKind,
    TokenStore,
};
use vigil_http_transport::{open_browser, HttpJwksSource, LoopbackServer};
use vigil_lease::{SecretStore, SecretValue};

use crate::AddRemoteArgs;

// re-export 便于 integration test 导入
pub use crate::duration_secs;

/// `add-remote-mcp` 的可注入依赖集。
///
/// prod(main.rs)用 [`Deps::production`] 构造,使用:
/// - `ReqwestHttpClient`(rustls + webpki-roots)
/// - `KeyringSecretStore`("os-keychain" feature;失败 fail-closed 报错)
///
/// CLI 集成测试可自行构造 `Deps { ... }`,注入 test-only TLS client 与内存
/// SecretStore(仅 tests/,不进 prod artifact)。
pub struct Deps {
    pub http_client: Arc<dyn HttpClient>,
    pub secret_store: Arc<dyn SecretStore>,
    /// 允许 test 让 CLI 接受 `http://` URL(绕过 `--url` 的 https gate);
    /// prod 默认 false —— 只接受 https。
    pub allow_insecure_url: bool,
}

impl std::fmt::Debug for Deps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deps")
            .field("secret_store_backend", &self.secret_store.backend_kind())
            .field("allow_insecure_url", &self.allow_insecure_url)
            .finish_non_exhaustive()
    }
}

impl Deps {
    /// prod 构造器:真 rustls + OS keychain。失败 fail-closed。
    pub fn production() -> Result<Self, String> {
        use vigil_http_transport::ReqwestHttpClient;
        use vigil_lease::KeyringSecretStore;

        let http =
            Arc::new(ReqwestHttpClient::new().map_err(|e| format!("build http client: {e}"))?);
        // KeyringSecretStore 构造不失败(延迟到第一次 put/get);β R1 要求
        // "platform 不可用时 fail-closed 并明确报错,不静默回退内存" —— 我们走
        // "写入时报错" 策略,由 `put_access_token` 内部透传 `BackendUnavailable`。
        let secret_store = Arc::new(KeyringSecretStore::new("vigil"));
        Ok(Self {
            http_client: http,
            secret_store,
            allow_insecure_url: false,
        })
    }
}

pub fn run(args: AddRemoteArgs) -> Result<(), String> {
    let deps = Deps::production()?;
    run_with_deps(args, deps)
}

/// 测试 / 内部使用的主入口;prod 路径走 `run`。
pub fn run_with_deps(args: AddRemoteArgs, deps: Deps) -> Result<(), String> {
    // 1. 基本校验
    let base_url: Url = args
        .url
        .parse()
        .map_err(|e| format!("invalid --url: {e}"))?;
    if !deps.allow_insecure_url && base_url.scheme() != "https" {
        return Err("--url must be https:// (ADR 0011 §I-11.3)".into());
    }
    if args.scopes.is_empty() {
        return Err("--scopes must be non-empty".into());
    }

    // 2. HttpClient
    let http_discover: Arc<dyn HttpClient> = deps.http_client.clone();

    // 3. PRM discover(RFC 9728)
    eprintln!("→ fetching PRM at {base_url}...");
    let prm = fetch_and_validate_prm(&*http_discover, &base_url)
        .map_err(|e| format!("prm discover: {e}"))?;
    if prm.authorization_servers.is_empty() {
        return Err("prm.authorization_servers is empty".into());
    }
    let as_url = &prm.authorization_servers[0];
    eprintln!("  PRM.resource = {}", prm.resource);
    eprintln!("  AS = {}", as_url);

    // 4. AS metadata discover(RFC 8414)
    let jwks_src = HttpJwksSource::new(http_discover.clone());
    let as_meta = jwks_src
        .fetch_as_metadata(as_url.as_str())
        .map_err(|e| format!("as metadata discover: {e}"))?;
    eprintln!("  AS.issuer     = {}", as_meta.issuer);
    eprintln!("  AS.jwks_uri   = {}", as_meta.jwks_uri);
    let token_endpoint = as_meta
        .token_endpoint
        .as_deref()
        .ok_or_else(|| "AS metadata missing token_endpoint".to_string())?;
    let authorize_endpoint = as_meta
        .authorization_endpoint
        .as_deref()
        .ok_or_else(|| "AS metadata missing authorization_endpoint".to_string())?;

    // I10c-α1 R1 BLOCKER 5:token/authorize endpoint **必须** https(refresh_token 是
    // 明文 OAuth secret,绝不能发给 http:// endpoint)。prod 不放行 `--allow-insecure-url`
    // 绕过 —— deps.allow_insecure_url 仅 test 用。
    if !deps.allow_insecure_url {
        let token_ep_url: Url = token_endpoint
            .parse()
            .map_err(|e| format!("token endpoint parse: {e}"))?;
        if token_ep_url.scheme() != "https" {
            return Err(format!(
                "AS token_endpoint must be https:// (got {}); \
                 refusing to send refresh_token to plain HTTP",
                token_ep_url.scheme()
            ));
        }
        let authz_ep_url: Url = authorize_endpoint
            .parse()
            .map_err(|e| format!("authorize endpoint parse: {e}"))?;
        if authz_ep_url.scheme() != "https" {
            return Err(format!(
                "AS authorization_endpoint must be https:// (got {})",
                authz_ep_url.scheme()
            ));
        }
    }

    // 5. PKCE + CSRF state
    let pkce = new_pkce_pair();
    let state = CsrfToken::new_random();

    // 6. loopback server(127.0.0.1:ephemeral)
    let loopback = LoopbackServer::bind(state.secret().clone(), "/callback")
        .map_err(|e| format!("loopback bind: {e}"))?;
    let redirect_uri: Url = loopback
        .redirect_uri()
        .parse()
        .map_err(|e| format!("loopback uri parse: {e}"))?;
    eprintln!("  redirect_uri  = {redirect_uri}");

    // 7. authorize URL + browser open(fallback:打印 URL 让用户手动)
    let authz_url = build_authorization_url(
        &authorize_endpoint
            .parse::<Url>()
            .map_err(|e| format!("authorize endpoint parse: {e}"))?,
        &args.client_id,
        &redirect_uri,
        &args.scopes,
        &state,
        &pkce.challenge,
        &prm.resource,
    )
    .map_err(|e| format!("build authorize url: {e}"))?;

    eprintln!("\n  opening browser to:");
    eprintln!("    {authz_url}\n");
    if !open_browser(authz_url.as_str()) {
        eprintln!("  (browser did not open; please **copy** the URL above and open it manually)");
    }

    // 8. 等 loopback callback(默认 60s;内部对 bad request 继续监听至超时)
    let callback = loopback
        .wait_for_callback(crate::duration_secs(args.timeout_secs))
        .map_err(|e| format!("loopback wait: {e}"))?;
    eprintln!("→ received callback, exchanging code...");

    // 9. exchange code for token
    let token_endpoint_url: Url = token_endpoint
        .parse()
        .map_err(|e| format!("token endpoint parse: {e}"))?;
    let tr = exchange_code_for_token(
        &*http_discover,
        &token_endpoint_url,
        &args.client_id,
        &redirect_uri,
        &callback.code,
        &pkce.verifier,
        &prm.resource,
    )
    .map_err(|e| format!("exchange code: {e}"))?;

    // 10. Ledger + TokenStore 落库(SecretStore 从 deps 注入 —— prod = Keyring,test = InMemory)
    let ledger = Arc::new(
        Ledger::open(&args.ledger)
            .map_err(|e| format!("ledger open {}: {e}", args.ledger.display()))?,
    );
    let ts = TokenStore::new(deps.secret_store.clone(), ledger);

    let resource = prm.resource.as_str().to_string();
    let token_ref = token_ref_for_access(&resource, &args.client_id);
    let scope_set = tr
        .scope
        .as_deref()
        .map(|s| {
            s.split(' ')
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| args.scopes.clone());
    let expires_at = tr.expires_in.map(|secs| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64 + secs)
            .unwrap_or(0)
    });

    let meta = OAuthTokenMetadata {
        token_ref: token_ref.clone(),
        resource: resource.clone(),
        authorization_server: as_url.as_str().to_string(),
        issuer: as_meta.issuer.clone(),
        scope_set,
        token_kind: TokenKind::Access,
        expires_at,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    };
    ts.put_access_token(&meta, SecretValue::new(tr.access_token))
        .map_err(|e| format!("token persist: {e}"))?;

    // I10c-α1:若 AS 返 refresh_token,同步入库(SecretStore + metadata)。
    // refresh metadata 的 token_ref / scope / expires_at 与 access 同源,但 kind=refresh。
    if let Some(refresh_token) = tr.refresh_token {
        let refresh_ref = token_ref_for_refresh(&resource, &args.client_id);
        let refresh_meta = OAuthTokenMetadata {
            token_ref: refresh_ref,
            resource: resource.clone(),
            authorization_server: as_url.as_str().to_string(),
            issuer: as_meta.issuer.clone(),
            scope_set: meta.scope_set.clone(),
            token_kind: TokenKind::Refresh,
            // refresh token 的 expires_at 常由 AS 另外字段传(Vigil 不追踪,留 None)
            expires_at: None,
            created_at: meta.created_at,
        };
        ts.put_refresh_token(&refresh_meta, SecretValue::new(refresh_token))
            .map_err(|e| format!("refresh token persist: {e}"))?;
        eprintln!("  refresh_token stored (auto-refresh enabled for future calls)");
    }

    eprintln!(
        "\n✓ remote MCP registered\n  resource    = {resource}\n  token_ref   = {token_ref}\n  issuer      = {iss}",
        iss = as_meta.issuer
    );
    Ok(())
}
