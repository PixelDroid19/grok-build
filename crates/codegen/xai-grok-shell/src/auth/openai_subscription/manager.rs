use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

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

static SHARED_MANAGERS: OnceLock<Mutex<HashMap<PathBuf, Weak<OpenAiSubscriptionAuthManager>>>> =
    OnceLock::new();

impl OpenAiSubscriptionAuthManager {
    pub fn new(storage: OpenAiAuthStorage, endpoints: OpenAiEndpoints) -> Self {
        Self {
            storage,
            endpoints,
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Return the process-wide coordinator for one Grok home.
    ///
    /// Every session using the same credentials shares `refresh_lock`, so an
    /// expired or rejected token produces one refresh request rather than one
    /// request per active conversation.
    pub fn shared_default(grok_home: &Path) -> Arc<Self> {
        let registry = SHARED_MANAGERS.get_or_init(|| Mutex::new(HashMap::new()));
        let mut managers = registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(manager) = managers.get(grok_home).and_then(Weak::upgrade) {
            return manager;
        }
        let manager = Arc::new(Self::new(
            OpenAiAuthStorage::new(grok_home),
            OpenAiEndpoints::default(),
        ));
        managers.insert(grok_home.to_path_buf(), Arc::downgrade(&manager));
        manager
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

    /// Refresh a bearer rejected by the Codex backend.
    ///
    /// If another caller already replaced `rejected_access_token`, reuse that
    /// token. This makes concurrent 401 recovery single-flight.
    pub async fn refresh_rejected_bearer(
        &self,
        rejected_access_token: &str,
    ) -> Result<OpenAiBearer, OpenAiAuthError> {
        let _guard = self.refresh_lock.lock().await;
        let current = self
            .storage
            .read()?
            .ok_or(OpenAiAuthError::NotAuthenticated)?;
        if current.access_token != rejected_access_token && !current.is_expired_at(Utc::now()) {
            return Ok(to_bearer(current));
        }

        let (refresh_token, previous_account_id) = {
            let _file_lock = self.storage.lock()?;
            let current = self
                .storage
                .read_locked()?
                .ok_or(OpenAiAuthError::NotAuthenticated)?;
            if current.access_token != rejected_access_token && !current.is_expired_at(Utc::now()) {
                return Ok(to_bearer(current));
            }
            (current.refresh_token, current.account_id)
        };

        let tokens = refresh_access_token(&self.endpoints, &refresh_token).await?;
        let account_id = extract_account_id(&tokens).or(previous_account_id);
        let auth = StoredOpenAiAuth::from_token_response(tokens, account_id, Utc::now())?;

        let _file_lock = self.storage.lock()?;
        if let Some(current) = self.storage.read_locked()?
            && current.access_token != rejected_access_token
            && !current.is_expired_at(Utc::now())
        {
            return Ok(to_bearer(current));
        }
        self.storage.write_locked(&auth)?;
        Ok(to_bearer(auth))
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

        let (refresh_token, previous_account_id) = {
            let _file_lock = self.storage.lock()?;
            match self.storage.read_locked()? {
                Some(current) if !current.is_expired_at(Utc::now()) => {
                    return Ok(to_bearer(current));
                }
                Some(current) => (current.refresh_token, current.account_id),
                None => (refresh_token, None),
            }
        };

        let tokens = refresh_access_token(&self.endpoints, &refresh_token).await?;
        let account_id = extract_account_id(&tokens).or(previous_account_id);
        let auth = StoredOpenAiAuth::from_token_response(tokens, account_id, Utc::now())?;

        let _file_lock = self.storage.lock()?;
        if let Some(current) = self.storage.read_locked()?
            && !current.is_expired_at(Utc::now())
        {
            return Ok(to_bearer(current));
        }
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
