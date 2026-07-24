use chrono::Utc;

use super::model::{
    OpenAiAuthError, OpenAiAuthStatus, OpenAiBearer, OpenAiEndpoints, StoredOpenAiAuth,
    TokenResponse,
};
use super::oauth::{extract_account_id, refresh_access_token};
use super::storage::OpenAiAuthStorage;

pub struct OpenAiSubscriptionAuthManager {
    storage: OpenAiAuthStorage,
    endpoints: OpenAiEndpoints,
    refresh_lock: tokio::sync::Mutex<()>,
}

impl OpenAiSubscriptionAuthManager {
    pub fn new(storage: OpenAiAuthStorage, endpoints: OpenAiEndpoints) -> Self {
        Self {
            storage,
            endpoints,
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub async fn current_bearer(&self) -> Result<OpenAiBearer, OpenAiAuthError> {
        let current = self
            .storage
            .read()?
            .ok_or(OpenAiAuthError::NotAuthenticated)?;
        if !current.is_expired_at(Utc::now()) {
            return Ok(to_bearer(current));
        }
        self.refresh_expired(current.refresh_token).await
    }

    pub async fn status(&self) -> Result<OpenAiAuthStatus, OpenAiAuthError> {
        let Some(auth) = self.storage.read()? else {
            return Ok(OpenAiAuthStatus::NotAuthenticated);
        };
        let expired = auth.is_expired_at(Utc::now());
        Ok(OpenAiAuthStatus::Authenticated {
            account_id: auth.account_id,
            expired,
        })
    }

    pub async fn current_account_id(&self) -> Result<Option<String>, OpenAiAuthError> {
        Ok(match self.status().await? {
            OpenAiAuthStatus::NotAuthenticated => None,
            OpenAiAuthStatus::Authenticated { account_id, .. } => account_id,
        })
    }

    pub fn store_token_response(
        &self,
        tokens: TokenResponse,
    ) -> Result<OpenAiBearer, OpenAiAuthError> {
        let auth = StoredOpenAiAuth::from_token_response(tokens, None, Utc::now())?;
        let bearer = to_bearer(auth.clone());
        self.storage.write(&auth)?;
        Ok(bearer)
    }

    pub async fn clear(&self) -> Result<(), OpenAiAuthError> {
        self.storage.clear()?;
        Ok(())
    }

    async fn refresh_expired(
        &self,
        refresh_token: String,
    ) -> Result<OpenAiBearer, OpenAiAuthError> {
        let _guard = self.refresh_lock.lock().await;
        if let Some(current) = self.storage.read()?
            && !current.is_expired_at(Utc::now())
        {
            return Ok(to_bearer(current));
        }

        let _file_lock = self.storage.lock()?;
        let (refresh_token, previous_account_id) = match self.storage.read_locked()? {
            Some(current) if !current.is_expired_at(Utc::now()) => return Ok(to_bearer(current)),
            Some(current) => (current.refresh_token, current.account_id),
            None => (refresh_token, None),
        };

        let tokens = refresh_access_token(&self.endpoints, &refresh_token).await?;
        let account_id = extract_account_id(&tokens).or(previous_account_id);
        let auth = StoredOpenAiAuth::from_token_response(tokens, account_id, Utc::now())?;
        self.storage.write_locked(&auth)?;
        Ok(to_bearer(auth))
    }
}

fn to_bearer(auth: StoredOpenAiAuth) -> OpenAiBearer {
    OpenAiBearer {
        access_token: auth.access_token,
        account_id: auth.account_id,
    }
}
