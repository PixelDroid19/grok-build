use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use super::manager::OpenAiSubscriptionAuthManager;
use super::model::{
    CLIENT_ID, ISSUER, OpenAiAuthStatus, OpenAiEndpoints, StoredOpenAiAuth, TokenResponse,
    default_redirect_uri,
};
use super::oauth::{
    DeviceAuthorization, build_authorize_url, build_browser_authorization,
    exchange_device_authorization, extract_account_id, generate_pkce, parse_callback_params,
    request_device_authorization,
};
use super::storage::OpenAiAuthStorage;

fn unsigned_jwt(claims: serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("{header}.{payload}.")
}

#[tokio::test]
async fn pkce_authorize_url_uses_openai_subscription_contract() {
    let pkce = generate_pkce();
    assert!(pkce.verifier.len() >= 43);
    assert!(
        pkce.verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
    );
    assert_ne!(pkce.verifier, pkce.challenge);

    let url = build_authorize_url(&OpenAiEndpoints::default(), &pkce, "state-1");
    let parsed = url::Url::parse(&url).unwrap();
    assert_eq!(parsed.scheme(), "https");
    assert_eq!(parsed.host_str(), Some("auth.openai.com"));
    assert_eq!(parsed.path(), "/oauth/authorize");
    let params: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
    assert_eq!(params.get("client_id").map(String::as_str), Some(CLIENT_ID));
    assert_eq!(
        params.get("redirect_uri").map(String::as_str),
        Some(default_redirect_uri().as_str())
    );
    assert_eq!(
        params.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    assert_eq!(
        params.get("code_challenge").map(String::as_str),
        Some(pkce.challenge.as_str())
    );
    assert_eq!(
        params.get("scope").map(String::as_str),
        Some("openid profile email offline_access")
    );
    assert_eq!(
        params.get("id_token_add_organizations").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        params.get("codex_cli_simplified_flow").map(String::as_str),
        Some("true")
    );

    let browser = build_browser_authorization(&OpenAiEndpoints::default(), pkce, "state-2");
    assert_eq!(browser.redirect_uri, default_redirect_uri());
    assert!(browser.authorize_url.contains("state=state-2"));
}

#[test]
fn token_parsing_prefers_chatgpt_account_claims_without_validation() {
    let nested = unsigned_jwt(json!({
        "https://api.openai.com/auth": { "chatgpt_account_id": "acct_nested" },
        "organizations": [{ "id": "org_fallback" }]
    }));
    let direct = unsigned_jwt(json!({ "chatgpt_account_id": "acct_direct" }));
    let org = unsigned_jwt(json!({ "organizations": [{ "id": "org_only" }] }));

    assert_eq!(
        extract_account_id(&TokenResponse {
            id_token: Some(nested),
            access_token: Some(direct.clone()),
            refresh_token: "refresh".into(),
            expires_in: Some(3600),
        })
        .as_deref(),
        Some("acct_nested")
    );
    assert_eq!(
        extract_account_id(&TokenResponse {
            id_token: None,
            access_token: Some(direct),
            refresh_token: "refresh".into(),
            expires_in: Some(3600),
        })
        .as_deref(),
        Some("acct_direct")
    );
    assert_eq!(
        extract_account_id(&TokenResponse {
            id_token: Some(org),
            access_token: None,
            refresh_token: "refresh".into(),
            expires_in: Some(3600),
        })
        .as_deref(),
        Some("org_only")
    );
}

#[test]
fn callback_params_require_matching_state_and_surface_oauth_errors() {
    let success = std::collections::HashMap::from([
        ("code".to_string(), "authorization-code".to_string()),
        ("state".to_string(), "state-1".to_string()),
    ]);
    assert_eq!(
        parse_callback_params(&success, "state-1").unwrap().as_str(),
        "authorization-code"
    );

    let denied = std::collections::HashMap::from([
        ("error".to_string(), "access_denied".to_string()),
        (
            "error_description".to_string(),
            "User denied access".to_string(),
        ),
    ]);
    assert!(
        parse_callback_params(&denied, "state-1")
            .unwrap_err()
            .to_string()
            .contains("User denied access")
    );

    let wrong_state = std::collections::HashMap::from([
        ("code".to_string(), "authorization-code".to_string()),
        ("state".to_string(), "state-2".to_string()),
    ]);
    assert!(
        parse_callback_params(&wrong_state, "state-1")
            .unwrap_err()
            .to_string()
            .contains("state")
    );
}

#[test]
fn token_bearing_debug_output_is_redacted() {
    let tokens = TokenResponse {
        id_token: Some("id-token-secret".into()),
        access_token: Some("access-token-secret".into()),
        refresh_token: "refresh-token-secret".into(),
        expires_in: Some(3600),
    };
    let auth =
        StoredOpenAiAuth::from_token_response(tokens, Some("acct_123".into()), chrono::Utc::now())
            .unwrap();
    let debug = format!("{auth:?}");

    assert!(debug.contains("acct_123"));
    assert!(!debug.contains("access-token-secret"));
    assert!(!debug.contains("refresh-token-secret"));
    assert!(!debug.contains("id-token-secret"));
}

#[test]
fn storage_persists_separate_owner_only_openai_auth_file() {
    let home = TempDir::new().unwrap();
    let storage = OpenAiAuthStorage::new(home.path());
    let auth = StoredOpenAiAuth::from_token_response(
        TokenResponse {
            id_token: None,
            access_token: Some("access-secret".into()),
            refresh_token: "refresh-secret".into(),
            expires_in: Some(3600),
        },
        Some("acct_123".into()),
        chrono::Utc::now(),
    )
    .unwrap();

    storage.write(&auth).unwrap();

    assert!(home.path().join("openai-auth.json").exists());
    assert!(!home.path().join("auth.json").exists());
    assert_eq!(
        storage.read().unwrap().unwrap().account_id.as_deref(),
        Some("acct_123")
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(home.path().join("openai-auth.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[tokio::test]
async fn current_bearer_refreshes_expired_token_once_for_concurrent_callers() {
    let server = RefreshServer::start().await;
    let storage_home = TempDir::new().unwrap();
    let storage = OpenAiAuthStorage::new(storage_home.path());
    storage
        .write(
            &StoredOpenAiAuth::from_token_response(
                TokenResponse {
                    id_token: None,
                    access_token: Some("expired-access".into()),
                    refresh_token: "initial-refresh".into(),
                    expires_in: Some(0),
                },
                Some("acct_old".into()),
                chrono::Utc::now() - chrono::Duration::seconds(60),
            )
            .unwrap(),
        )
        .unwrap();
    let manager = Arc::new(OpenAiSubscriptionAuthManager::new(
        storage,
        server.endpoints(),
    ));

    let calls = (0..8).map(|_| {
        let manager = manager.clone();
        tokio::spawn(async move { manager.current_bearer().await.unwrap() })
    });
    let results = futures::future::join_all(calls).await;

    for result in results {
        let bearer = result.unwrap();
        assert_eq!(bearer.access_token, "fresh-access");
        assert_eq!(bearer.account_id.as_deref(), Some("acct_new"));
    }
    assert_eq!(server.refresh_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        manager.status().await.unwrap(),
        OpenAiAuthStatus::Authenticated {
            account_id: Some("acct_new".into()),
            expired: false,
        }
    );
    assert_eq!(
        manager.current_account_id().await.unwrap().as_deref(),
        Some("acct_new")
    );
}

#[tokio::test]
async fn headless_device_flow_stops_on_cancellation_without_token_exchange() {
    let server = DeviceServer::start(DeviceMode::Pending).await;
    let cancel = CancellationToken::new();
    let auth = DeviceAuthorization {
        device_auth_id: "device-1".into(),
        user_code: "CODE-1".into(),
        interval_seconds: 1,
    };
    cancel.cancel();

    let err = exchange_device_authorization(&server.endpoints(), auth, cancel)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("cancelled"));
    assert_eq!(server.token_polls.load(Ordering::SeqCst), 0);
    assert_eq!(server.oauth_exchanges.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn headless_device_flow_uses_opencode_device_endpoints() {
    let server = DeviceServer::start(DeviceMode::Approved).await;

    let auth = request_device_authorization(&server.endpoints())
        .await
        .unwrap();
    assert_eq!(auth.device_auth_id, "device-1");
    assert_eq!(auth.user_code, "CODE-1");
    assert_eq!(auth.interval_seconds, 1);

    let tokens = exchange_device_authorization(&server.endpoints(), auth, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(tokens.access_token.as_deref(), Some("device-access"));
    assert_eq!(tokens.refresh_token, "device-refresh");
    assert_eq!(server.user_code_requests.load(Ordering::SeqCst), 1);
    assert_eq!(server.token_polls.load(Ordering::SeqCst), 1);
    assert_eq!(server.oauth_exchanges.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn headless_device_flow_surfaces_error_response_and_skips_oauth_exchange() {
    let server = DeviceServer::start(DeviceMode::Denied).await;
    let auth = DeviceAuthorization {
        device_auth_id: "device-1".into(),
        user_code: "CODE-1".into(),
        interval_seconds: 1,
    };

    let err = exchange_device_authorization(&server.endpoints(), auth, CancellationToken::new())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("access_denied"));
    assert_eq!(server.token_polls.load(Ordering::SeqCst), 1);
    assert_eq!(server.oauth_exchanges.load(Ordering::SeqCst), 0);
}

#[test]
fn exported_defaults_match_openai_subscription_reference() {
    assert_eq!(ISSUER, "https://auth.openai.com");
    assert_eq!(CLIENT_ID, "app_EMoamEEZ73f0CkXaXp7hrann");
    assert_eq!(
        default_redirect_uri(),
        "http://localhost:1455/auth/callback"
    );
}

struct RefreshServer {
    base_url: String,
    refresh_calls: Arc<AtomicUsize>,
}

impl RefreshServer {
    async fn start() -> Self {
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/oauth/token", post(refresh_handler))
            .with_state(refresh_calls.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            base_url: format!("http://{addr}"),
            refresh_calls,
        }
    }

    fn endpoints(&self) -> OpenAiEndpoints {
        OpenAiEndpoints::new(self.base_url.clone())
    }
}

async fn refresh_handler(State(calls): State<Arc<AtomicUsize>>) -> impl IntoResponse {
    calls.fetch_add(1, Ordering::SeqCst);
    Json(json!({
        "access_token": "fresh-access",
        "refresh_token": "fresh-refresh",
        "expires_in": 3600,
        "id_token": unsigned_jwt(json!({ "chatgpt_account_id": "acct_new" })),
    }))
}

#[derive(Clone, Copy)]
enum DeviceMode {
    Pending,
    Denied,
    Approved,
}

struct DeviceServer {
    base_url: String,
    user_code_requests: Arc<AtomicUsize>,
    token_polls: Arc<AtomicUsize>,
    oauth_exchanges: Arc<AtomicUsize>,
}

struct DeviceState {
    mode: DeviceMode,
    user_code_requests: Arc<AtomicUsize>,
    token_polls: Arc<AtomicUsize>,
    oauth_exchanges: Arc<AtomicUsize>,
}

impl DeviceServer {
    async fn start(mode: DeviceMode) -> Self {
        let user_code_requests = Arc::new(AtomicUsize::new(0));
        let token_polls = Arc::new(AtomicUsize::new(0));
        let oauth_exchanges = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(DeviceState {
            mode,
            user_code_requests: user_code_requests.clone(),
            token_polls: token_polls.clone(),
            oauth_exchanges: oauth_exchanges.clone(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/api/accounts/deviceauth/usercode",
                post(device_user_code_handler),
            )
            .route("/api/accounts/deviceauth/token", post(device_token_handler))
            .route("/oauth/token", post(oauth_token_handler))
            .with_state(state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            base_url: format!("http://{addr}"),
            user_code_requests,
            token_polls,
            oauth_exchanges,
        }
    }

    fn endpoints(&self) -> OpenAiEndpoints {
        OpenAiEndpoints::new(self.base_url.clone())
    }
}

async fn device_user_code_handler(State(state): State<Arc<DeviceState>>) -> impl IntoResponse {
    state.user_code_requests.fetch_add(1, Ordering::SeqCst);
    Json(json!({
        "device_auth_id": "device-1",
        "user_code": "CODE-1",
        "interval": "1"
    }))
}

async fn device_token_handler(State(state): State<Arc<DeviceState>>) -> impl IntoResponse {
    state.token_polls.fetch_add(1, Ordering::SeqCst);
    match state.mode {
        DeviceMode::Pending => (
            StatusCode::ACCEPTED,
            Json(json!({ "error": "authorization_pending" })),
        ),
        DeviceMode::Denied => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "access_denied" })),
        ),
        DeviceMode::Approved => (
            StatusCode::OK,
            Json(json!({
                "authorization_code": "authorization-code",
                "code_verifier": "device-code-verifier"
            })),
        ),
    }
}

async fn oauth_token_handler(State(state): State<Arc<DeviceState>>) -> impl IntoResponse {
    state.oauth_exchanges.fetch_add(1, Ordering::SeqCst);
    Json(json!({
        "access_token": "device-access",
        "refresh_token": "device-refresh",
        "expires_in": 3600
    }))
}
