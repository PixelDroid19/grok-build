use std::collections::HashMap;
use std::time::Duration as StdDuration;

use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
};
use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::model::{
    CLIENT_ID, OpenAiAuthError, OpenAiEndpoints, TokenResponse, default_redirect_uri,
};

const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
const OAUTH_POLLING_SAFETY_MARGIN_MS: u64 = 3000;
const OAUTH_CALLBACK_TIMEOUT_MS: u64 = 5 * 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PkceCodes {
    pub verifier: String,
    pub challenge: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceAuthorization {
    pub device_auth_id: String,
    pub user_code: String,
    pub interval_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserAuthorization {
    pub authorize_url: String,
    pub redirect_uri: String,
    pub pkce: PkceCodes,
    pub state: String,
}

#[derive(Clone)]
struct CallbackState {
    expected_state: String,
    tx: tokio::sync::mpsc::Sender<Result<String, OpenAiAuthError>>,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorizationResponse {
    device_auth_id: String,
    user_code: String,
    interval: String,
}

#[derive(Debug, Deserialize)]
struct DeviceExchangeResponse {
    authorization_code: String,
    code_verifier: String,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: Option<String>,
    error_description: Option<String>,
}

pub fn generate_pkce() -> PkceCodes {
    let bytes: [u8; 43] = rand::random();
    let verifier: String = bytes
        .iter()
        .map(|byte| CHARS[*byte as usize % CHARS.len()] as char)
        .collect();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    PkceCodes {
        verifier,
        challenge,
    }
}

pub fn build_authorize_url(endpoints: &OpenAiEndpoints, pkce: &PkceCodes, state: &str) -> String {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params
        .append_pair("response_type", "code")
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", &default_redirect_uri())
        .append_pair("scope", "openid profile email offline_access")
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("id_token_add_organizations", "true")
        .append_pair("codex_cli_simplified_flow", "true")
        .append_pair("state", state)
        .append_pair("originator", "grok-build");
    format!("{}?{}", endpoints.authorize_url(), params.finish())
}

pub fn build_browser_authorization(
    endpoints: &OpenAiEndpoints,
    pkce: PkceCodes,
    state: impl Into<String>,
) -> BrowserAuthorization {
    let state = state.into();
    BrowserAuthorization {
        authorize_url: build_authorize_url(endpoints, &pkce, &state),
        redirect_uri: default_redirect_uri(),
        pkce,
        state,
    }
}

pub fn parse_callback_params(
    params: &HashMap<String, String>,
    expected_state: &str,
) -> Result<String, OpenAiAuthError> {
    if let Some(error) = params.get("error") {
        let message = params
            .get("error_description")
            .filter(|description| !description.is_empty())
            .cloned()
            .unwrap_or_else(|| error.clone());
        return Err(OpenAiAuthError::Callback(message));
    }

    let code = params
        .get("code")
        .filter(|code| !code.is_empty())
        .ok_or_else(|| OpenAiAuthError::Callback("missing authorization code".to_owned()))?;
    let state = params
        .get("state")
        .ok_or_else(|| OpenAiAuthError::Callback("missing callback state".to_owned()))?;
    if state != expected_state {
        return Err(OpenAiAuthError::Callback(
            "callback state mismatch".to_owned(),
        ));
    }
    Ok(code.clone())
}

fn callback_page(message: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html><html><body><h1>Grok Build</h1><p>{message}</p></body></html>"#
    ))
}

async fn handle_callback(
    State(state): State<CallbackState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    match parse_callback_params(&params, &state.expected_state) {
        Ok(code) => {
            let _ = state.tx.try_send(Ok(code));
            (
                StatusCode::OK,
                callback_page("Authorization complete. You can close this page now."),
            )
        }
        Err(error) => {
            let message = error.to_string();
            let _ = state.tx.try_send(Err(error));
            (
                StatusCode::BAD_REQUEST,
                callback_page(&format!("Authorization failed: {message}")),
            )
        }
    }
}

pub async fn wait_for_browser_callback(
    redirect_uri: &str,
    expected_state: &str,
    cancel: CancellationToken,
    timeout: StdDuration,
) -> Result<String, OpenAiAuthError> {
    let parsed = url::Url::parse(redirect_uri)
        .map_err(|_| OpenAiAuthError::Callback("invalid callback URI".to_owned()))?;
    let host = parsed.host_str().unwrap_or("127.0.0.1").to_owned();
    let port = parsed.port().unwrap_or(1455);
    let path = parsed.path().to_owned();

    let listener = tokio::net::TcpListener::bind((host.as_str(), port))
        .await
        .map_err(|error| OpenAiAuthError::Callback(error.to_string()))?;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<String, OpenAiAuthError>>(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let app = Router::new()
        .route(&path, get(handle_callback))
        .with_state(CallbackState {
            expected_state: expected_state.to_owned(),
            tx: tx.clone(),
        });

    let serve = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    let result = tokio::select! {
        result = tokio::time::timeout(timeout, rx.recv()) => match result {
            Ok(Some(result)) => result,
            Ok(None) => Err(OpenAiAuthError::Callback("OAuth callback channel closed".to_owned())),
            Err(_) => Err(OpenAiAuthError::Callback("OAuth callback timed out".to_owned())),
        },
        _ = cancel.cancelled() => Err(OpenAiAuthError::Cancelled),
    };

    let _ = shutdown_tx.send(());
    let _ = serve.await;
    result
}

pub async fn wait_for_browser_callback_default(
    redirect_uri: &str,
    expected_state: &str,
    cancel: CancellationToken,
) -> Result<String, OpenAiAuthError> {
    wait_for_browser_callback(
        redirect_uri,
        expected_state,
        cancel,
        StdDuration::from_millis(OAUTH_CALLBACK_TIMEOUT_MS),
    )
    .await
}

pub async fn wait_and_exchange_browser_callback(
    endpoints: &OpenAiEndpoints,
    pkce: PkceCodes,
    state: impl Into<String>,
    redirect_uri: &str,
    open_in_browser: bool,
    timeout: StdDuration,
    cancel: CancellationToken,
) -> Result<TokenResponse, OpenAiAuthError> {
    let state = state.into();
    if open_in_browser {
        let auth_url = build_authorize_url(endpoints, &pkce, &state);
        webbrowser::open(&auth_url).map_err(|error| {
            OpenAiAuthError::Callback(format!("failed to open browser: {error}"))
        })?;
    }

    let code = wait_for_browser_callback(redirect_uri, &state, cancel, timeout).await?;
    exchange_code_for_tokens(endpoints, &code, redirect_uri, &pkce).await
}

pub async fn exchange_code_for_tokens(
    endpoints: &OpenAiEndpoints,
    code: &str,
    redirect_uri: &str,
    pkce: &PkceCodes,
) -> Result<TokenResponse, OpenAiAuthError> {
    let response = crate::http::shared_client()
        .post(endpoints.token_url())
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", CLIENT_ID),
            ("code_verifier", pkce.verifier.as_str()),
        ])
        .timeout(StdDuration::from_secs(15))
        .send()
        .await?;
    parse_token_response(response).await
}

pub async fn refresh_access_token(
    endpoints: &OpenAiEndpoints,
    refresh_token: &str,
) -> Result<TokenResponse, OpenAiAuthError> {
    let response = crate::http::shared_client()
        .post(endpoints.token_url())
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", CLIENT_ID),
        ])
        .timeout(StdDuration::from_secs(15))
        .send()
        .await?;
    parse_token_response(response).await
}

pub async fn request_device_authorization(
    endpoints: &OpenAiEndpoints,
) -> Result<DeviceAuthorization, OpenAiAuthError> {
    let response = crate::http::shared_client()
        .post(endpoints.device_user_code_url())
        .header("User-Agent", user_agent())
        .json(&serde_json::json!({ "client_id": CLIENT_ID }))
        .timeout(StdDuration::from_secs(15))
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(error_from_response(response).await);
    }
    let data: DeviceAuthorizationResponse = response.json().await?;
    let interval_seconds = data.interval.parse::<u64>().unwrap_or(5).max(1);
    Ok(DeviceAuthorization {
        device_auth_id: data.device_auth_id,
        user_code: data.user_code,
        interval_seconds,
    })
}

pub async fn exchange_device_authorization(
    endpoints: &OpenAiEndpoints,
    auth: DeviceAuthorization,
    cancel: CancellationToken,
) -> Result<TokenResponse, OpenAiAuthError> {
    loop {
        if cancel.is_cancelled() {
            return Err(OpenAiAuthError::Cancelled);
        }
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(OpenAiAuthError::Cancelled),
            response = crate::http::shared_client()
                .post(endpoints.device_token_url())
                .header("User-Agent", user_agent())
                .json(&serde_json::json!({
                    "device_auth_id": auth.device_auth_id.as_str(),
                    "user_code": auth.user_code.as_str(),
                }))
                .timeout(StdDuration::from_secs(15))
                .send() => response?,
        };

        if response.status().is_success() {
            let data: DeviceExchangeResponse = response.json().await?;
            return exchange_device_code_for_tokens(endpoints, data).await;
        }

        let status = response.status();
        let error = parse_error_body(response).await;
        if error.as_deref() == Some("authorization_pending")
            || status == reqwest::StatusCode::FORBIDDEN
            || status == reqwest::StatusCode::NOT_FOUND
        {
            tokio::select! {
                _ = cancel.cancelled() => return Err(OpenAiAuthError::Cancelled),
                _ = tokio::time::sleep(
                    StdDuration::from_secs(auth.interval_seconds)
                        + StdDuration::from_millis(OAUTH_POLLING_SAFETY_MARGIN_MS)
                ) => {}
            }
            continue;
        }

        return Err(OpenAiAuthError::Http {
            status: status.as_u16(),
            message: error.unwrap_or_else(|| status.to_string()),
        });
    }
}

async fn exchange_device_code_for_tokens(
    endpoints: &OpenAiEndpoints,
    data: DeviceExchangeResponse,
) -> Result<TokenResponse, OpenAiAuthError> {
    let response = crate::http::shared_client()
        .post(endpoints.token_url())
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", data.authorization_code.as_str()),
            ("redirect_uri", endpoints.device_redirect_uri().as_str()),
            ("client_id", CLIENT_ID),
            ("code_verifier", data.code_verifier.as_str()),
        ])
        .timeout(StdDuration::from_secs(15))
        .send()
        .await?;
    parse_token_response(response).await
}

pub fn extract_account_id(tokens: &TokenResponse) -> Option<String> {
    tokens
        .id_token
        .as_deref()
        .and_then(extract_account_id_from_jwt)
        .or_else(|| {
            tokens
                .access_token
                .as_deref()
                .and_then(extract_account_id_from_jwt)
        })
}

fn extract_account_id_from_jwt(token: &str) -> Option<String> {
    let claims = parse_jwt_claims(token)?;
    claims
        .get("chatgpt_account_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            claims
                .get("https://api.openai.com/auth")
                .and_then(|value| value.get("chatgpt_account_id"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        })
        .or_else(|| {
            claims
                .get("organizations")
                .and_then(Value::as_array)
                .and_then(|orgs| orgs.first())
                .and_then(|org| org.get("id"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        })
}

fn parse_jwt_claims(token: &str) -> Option<HashMap<String, Value>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| URL_SAFE.decode(parts[1]))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

async fn parse_token_response(
    response: reqwest::Response,
) -> Result<TokenResponse, OpenAiAuthError> {
    if !response.status().is_success() {
        return Err(error_from_response(response).await);
    }
    let tokens: TokenResponse = response.json().await?;
    if tokens
        .access_token
        .as_deref()
        .unwrap_or_default()
        .is_empty()
    {
        return Err(OpenAiAuthError::MissingAccessToken);
    }
    if tokens.refresh_token.is_empty() {
        return Err(OpenAiAuthError::MissingRefreshToken);
    }
    Ok(tokens)
}

async fn error_from_response(response: reqwest::Response) -> OpenAiAuthError {
    let status = response.status();
    OpenAiAuthError::Http {
        status: status.as_u16(),
        message: parse_error_body(response)
            .await
            .unwrap_or_else(|| status.to_string()),
    }
}

async fn parse_error_body(response: reqwest::Response) -> Option<String> {
    let body = response.text().await.ok()?;
    let error = serde_json::from_str::<ErrorResponse>(&body).ok()?;
    error
        .error_description
        .filter(|s| !s.is_empty())
        .or(error.error.filter(|s| !s.is_empty()))
}

fn user_agent() -> String {
    format!("grok-build/{}", xai_grok_version::VERSION)
}
