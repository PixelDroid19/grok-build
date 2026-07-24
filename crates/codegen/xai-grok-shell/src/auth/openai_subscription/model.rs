use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::oauth::extract_account_id;

pub const ISSUER: &str = "https://auth.openai.com";
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const CALLBACK_PORT: u16 = 1455;
pub const CALLBACK_PATH: &str = "/auth/callback";
pub const DEFAULT_EXPIRES_IN_SECS: i64 = 3600;

pub fn default_redirect_uri() -> String {
    format!("http://localhost:{CALLBACK_PORT}{CALLBACK_PATH}")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenAiEndpoints {
    issuer: String,
}

impl OpenAiEndpoints {
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into().trim_end_matches('/').to_owned(),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn authorize_url(&self) -> String {
        format!("{}/oauth/authorize", self.issuer)
    }

    pub fn token_url(&self) -> String {
        format!("{}/oauth/token", self.issuer)
    }

    pub fn device_user_code_url(&self) -> String {
        format!("{}/api/accounts/deviceauth/usercode", self.issuer)
    }

    pub fn device_token_url(&self) -> String {
        format!("{}/api/accounts/deviceauth/token", self.issuer)
    }

    pub fn device_verification_url(&self) -> String {
        format!("{}/codex/device", self.issuer)
    }

    pub fn device_redirect_uri(&self) -> String {
        format!("{}/deviceauth/callback", self.issuer)
    }
}

impl Default for OpenAiEndpoints {
    fn default() -> Self {
        Self::new(ISSUER)
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TokenResponse {
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub access_token: Option<String>,
    pub refresh_token: String,
    #[serde(default)]
    pub expires_in: Option<i64>,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("id_token", &self.id_token.as_deref().map(redacted_token))
            .field(
                "access_token",
                &self.access_token.as_deref().map(redacted_token),
            )
            .field("refresh_token", &redacted_token(&self.refresh_token))
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredOpenAiAuth {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

impl fmt::Debug for StoredOpenAiAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredOpenAiAuth")
            .field("access_token", &redacted_token(&self.access_token))
            .field("refresh_token", &redacted_token(&self.refresh_token))
            .field("expires_at", &self.expires_at)
            .field("account_id", &self.account_id)
            .field("id_token", &self.id_token.as_deref().map(redacted_token))
            .finish()
    }
}

impl StoredOpenAiAuth {
    pub fn from_token_response(
        tokens: TokenResponse,
        account_id: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, OpenAiAuthError> {
        if tokens.refresh_token.is_empty() {
            return Err(OpenAiAuthError::MissingRefreshToken);
        }
        let access_token = tokens
            .access_token
            .clone()
            .filter(|token| !token.is_empty())
            .ok_or(OpenAiAuthError::MissingAccessToken)?;
        let expires_in = tokens.expires_in.unwrap_or(DEFAULT_EXPIRES_IN_SECS).max(0);
        Ok(Self {
            access_token,
            refresh_token: tokens.refresh_token.clone(),
            expires_at: now + Duration::seconds(expires_in),
            account_id: account_id.or_else(|| extract_account_id(&tokens)),
            id_token: tokens.id_token,
        })
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct OpenAiBearer {
    pub access_token: String,
    pub account_id: Option<String>,
}

impl fmt::Debug for OpenAiBearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenAiBearer")
            .field("access_token", &redacted_token(&self.access_token))
            .field("account_id", &self.account_id)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenAiAuthStatus {
    NotAuthenticated,
    Authenticated {
        account_id: Option<String>,
        expired: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum OpenAiAuthError {
    #[error("ChatGPT subscription auth is not configured. Sign in with OpenAI first.")]
    NotAuthenticated,
    #[error("OpenAI token response did not include an access token")]
    MissingAccessToken,
    #[error("OpenAI token response did not include a refresh token")]
    MissingRefreshToken,
    #[error("OpenAI auth storage failed: {0}")]
    Storage(#[from] std::io::Error),
    #[error("OpenAI auth request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("OpenAI auth response was invalid: {0}")]
    InvalidResponse(String),
    #[error("OpenAI auth request failed with HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("OpenAI OAuth callback failed: {0}")]
    Callback(String),
    #[error("OpenAI device authorization was cancelled")]
    Cancelled,
}

fn redacted_token(token: &str) -> String {
    if token.len() <= 8 {
        return "<redacted>".to_owned();
    }
    format!("<redacted:{}>", &token[token.len() - 4..])
}
