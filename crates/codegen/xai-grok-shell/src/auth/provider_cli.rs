use std::io::Read;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio_util::sync::CancellationToken;

use super::model::OPENCODE_GO_API_KEY_SCOPE;
use super::openai_subscription::manager::OpenAiSubscriptionAuthManager;
use super::openai_subscription::model::{OpenAiAuthStatus, OpenAiEndpoints};
use super::openai_subscription::oauth::{
    build_browser_authorization, exchange_device_authorization, generate_pkce,
    request_device_authorization, wait_and_exchange_browser_callback,
};
use super::openai_subscription::storage::OpenAiAuthStorage;

pub async fn login_openai_subscription(device_flow: bool) -> anyhow::Result<()> {
    let home = crate::util::grok_home::grok_home();
    let endpoints = OpenAiEndpoints::default();
    let manager =
        OpenAiSubscriptionAuthManager::new(OpenAiAuthStorage::new(&home), endpoints.clone());
    let cancel = CancellationToken::new();
    let tokens = if device_flow {
        let authorization = request_device_authorization(&endpoints).await?;
        eprintln!(
            "Open {} and enter code: {}",
            endpoints.device_verification_url(),
            authorization.user_code
        );
        exchange_device_authorization(&endpoints, authorization, cancel).await?
    } else {
        let authorization = build_browser_authorization(
            &endpoints,
            generate_pkce(),
            uuid::Uuid::new_v4().to_string(),
        );
        eprintln!("Opening OpenAI sign-in in your browser…");
        wait_and_exchange_browser_callback(
            &endpoints,
            authorization.pkce,
            authorization.state,
            &authorization.redirect_uri,
            true,
            Duration::from_secs(600),
            cancel,
        )
        .await?
    };
    let bearer = manager.store_token_response(tokens)?;
    let catalog = crate::agent::provider_catalog::load_openai_catalog(&home).await;
    if catalog.is_unavailable() {
        eprintln!(
            "Warning: {}",
            catalog
                .warning
                .unwrap_or_else(|| "OpenAI model catalog is unavailable".to_owned())
        );
    }
    if let Some(account_id) = bearer.account_id {
        println!("Signed in to OpenAI account {account_id}.");
    } else {
        println!("Signed in to OpenAI.");
    }
    Ok(())
}

pub async fn login_opencode_go(api_key_stdin: bool) -> anyhow::Result<()> {
    let key = if api_key_stdin {
        let mut value = String::new();
        std::io::stdin()
            .read_to_string(&mut value)
            .context("failed to read OpenCode Go API key from stdin")?;
        value
    } else {
        std::env::var("OPENCODE_API_KEY").context(
            "OPENCODE_API_KEY is not set; set it or pipe the key to `grok login --provider opencode-go --api-key-stdin`",
        )?
    };
    login_opencode_go_with_key(&key).await
}

pub async fn login_opencode_go_with_key(key: &str) -> anyhow::Result<()> {
    if key.trim().is_empty() {
        bail!("OpenCode Go API key is empty");
    }
    super::store_provider_api_key(
        &crate::util::grok_home::grok_home(),
        OPENCODE_GO_API_KEY_SCOPE,
        &key,
    )?;
    let catalog = crate::agent::provider_catalog::load_opencode_go_catalog(
        &crate::util::grok_home::grok_home(),
        Some(key.trim()),
    )
    .await;
    if catalog.is_unavailable() {
        eprintln!(
            "Warning: {}",
            catalog
                .warning
                .unwrap_or_else(|| "OpenCode Go model catalog is unavailable".to_owned())
        );
    }
    println!("Signed in to OpenCode Go.");
    Ok(())
}

pub async fn logout_openai_subscription() -> anyhow::Result<()> {
    OpenAiSubscriptionAuthManager::new(
        OpenAiAuthStorage::new(&crate::util::grok_home::grok_home()),
        OpenAiEndpoints::default(),
    )
    .clear()
    .await?;
    println!("Signed out from OpenAI.");
    Ok(())
}

pub fn logout_opencode_go() -> anyhow::Result<()> {
    super::clear_provider_api_key(
        &crate::util::grok_home::grok_home(),
        OPENCODE_GO_API_KEY_SCOPE,
    )?;
    println!("Signed out from OpenCode Go.");
    Ok(())
}

pub async fn provider_status(provider: &str) -> anyhow::Result<String> {
    match provider {
        "openai" => {
            let status = OpenAiSubscriptionAuthManager::new(
                OpenAiAuthStorage::new(&crate::util::grok_home::grok_home()),
                OpenAiEndpoints::default(),
            )
            .status()
            .await?;
            Ok(match status {
                OpenAiAuthStatus::NotAuthenticated => "openai: disconnected".to_owned(),
                OpenAiAuthStatus::Authenticated {
                    account_id,
                    expired,
                } => format!(
                    "openai: connected{}{}",
                    account_id.map(|id| format!(" ({id})")).unwrap_or_default(),
                    if expired {
                        ", token refresh required"
                    } else {
                        ""
                    }
                ),
            })
        }
        "opencode-go" => Ok(
            if super::read_provider_api_key(
                &crate::util::grok_home::grok_home(),
                OPENCODE_GO_API_KEY_SCOPE,
            )
            .is_some()
                || std::env::var("OPENCODE_API_KEY").is_ok()
            {
                "opencode-go: connected".to_owned()
            } else {
                "opencode-go: disconnected".to_owned()
            },
        ),
        _ => bail!("unsupported provider status: {provider}"),
    }
}

pub fn has_non_xai_provider_auth() -> bool {
    provider_is_authenticated("openai") || provider_is_authenticated("opencode-go")
}

pub fn has_xai_provider_auth(config: &crate::agent::config::Config) -> bool {
    config.create_auth_manager().current_or_expired().is_some()
        || crate::agent::auth_method::has_xai_api_key_env()
}

pub fn provider_is_authenticated(provider: &str) -> bool {
    let home = crate::util::grok_home::grok_home();
    match provider {
        "openai" => OpenAiAuthStorage::new(&home)
            .read()
            .ok()
            .flatten()
            .is_some(),
        "opencode-go" => {
            super::read_provider_api_key(&home, OPENCODE_GO_API_KEY_SCOPE).is_some()
                || std::env::var("OPENCODE_API_KEY")
                    .ok()
                    .is_some_and(|key| !key.trim().is_empty())
        }
        _ => false,
    }
}
