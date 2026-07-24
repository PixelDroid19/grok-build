use std::collections::HashMap;
use std::time::Duration as StdDuration;

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::model::{
    CLIENT_ID, OpenAiAuthError, OpenAiEndpoints, TokenResponse, default_redirect_uri,
};

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
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
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
        if error.as_deref() == Some("authorization_pending") {
            tokio::select! {
                _ = cancel.cancelled() => return Err(OpenAiAuthError::Cancelled),
                _ = tokio::time::sleep(StdDuration::from_secs(auth.interval_seconds)) => {}
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
