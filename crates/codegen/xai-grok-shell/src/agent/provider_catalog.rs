//! Dynamic provider catalogs for non-xAI model sources.

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::Value;

use crate::agent::config::{self, EnvKeys, ModelEntry, ModelEntryConfig};
use crate::agent::model_providers::ProviderId;
use crate::sampling::ApiBackend;
use xai_grok_sampling_types::{ReasoningEffort, ReasoningEffortOption};

pub const OPENAI_MODELS_DEV_URL: &str = "https://models.dev/api.json";
pub const OPENCODE_GO_MODELS_URL: &str = "https://opencode.ai/zen/go/v1/models";
const PROVIDER_CATALOG_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);
const OPENAI_PROVIDER_BASE_URL: &str = "https://api.openai.com/v1";
const OPENCODE_GO_PROVIDER_BASE_URL: &str = "https://opencode.ai/zen/go/v1";
const OPENCODE_GO_MESSAGES_FAMILIES: &[&str] = &["claude", "minimax", "qwen"];
const OPENCODE_GPT_OPENAI_MIN_VERSION: (u32, u32, u32) = (5, 4, 0);

static PROVIDER_CATALOG_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatalogProvenance {
    Remote,
    FreshCache,
    DiskFallback,
    Unavailable,
}

#[derive(Clone, Debug)]
pub struct ProviderCatalog {
    pub provider_id: ProviderId,
    pub entries: IndexMap<String, ModelEntry>,
    pub provenance: CatalogProvenance,
    pub warning: Option<String>,
}

impl ProviderCatalog {
    fn unavailable(provider_id: ProviderId, warning: String) -> Self {
        Self {
            provider_id,
            entries: IndexMap::new(),
            provenance: CatalogProvenance::Unavailable,
            warning: Some(warning),
        }
    }

    pub fn is_unavailable(&self) -> bool {
        self.provenance == CatalogProvenance::Unavailable
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderCatalogError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("parse error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("catalog contains no usable models")]
    EmptyCatalog,
}

pub async fn load_openai_catalog(cache_dir: &Path) -> ProviderCatalog {
    let client = crate::http::shared_client();
    load_openai_catalog_with_client(cache_dir, &client, OPENAI_MODELS_DEV_URL).await
}

pub async fn load_openai_catalog_with_client(
    cache_dir: &Path,
    client: &reqwest::Client,
    url: &str,
) -> ProviderCatalog {
    load_provider_catalog(
        cache_dir,
        ProviderId::OpenAi,
        url,
        None,
        client,
        parse_openai_models_dev_catalog,
    )
    .await
}

pub async fn load_opencode_go_catalog(cache_dir: &Path, api_key: Option<&str>) -> ProviderCatalog {
    let client = crate::http::shared_client();
    load_opencode_go_catalog_with_client(cache_dir, &client, OPENCODE_GO_MODELS_URL, api_key).await
}

pub async fn load_opencode_go_catalog_with_client(
    cache_dir: &Path,
    client: &reqwest::Client,
    url: &str,
    api_key: Option<&str>,
) -> ProviderCatalog {
    let Some(api_key) = api_key.map(str::trim).filter(|key| !key.is_empty()) else {
        return ProviderCatalog::unavailable(
            ProviderId::OpencodeGo,
            "OpenCode Go model catalog unavailable: missing API key".to_owned(),
        );
    };
    load_provider_catalog(
        cache_dir,
        ProviderId::OpencodeGo,
        url,
        Some(api_key),
        client,
        parse_opencode_go_catalog,
    )
    .await
}

async fn load_provider_catalog(
    cache_dir: &Path,
    provider_id: ProviderId,
    url: &str,
    bearer: Option<&str>,
    client: &reqwest::Client,
    parse: fn(&Value) -> Result<IndexMap<String, ModelEntry>, ProviderCatalogError>,
) -> ProviderCatalog {
    let cache = ProviderCatalogCache::new(cache_dir, provider_id.clone(), url);
    if let Some(entries) = cache.load_fresh() {
        return ProviderCatalog {
            provider_id,
            entries,
            provenance: CatalogProvenance::FreshCache,
            warning: None,
        };
    }

    match fetch_catalog_json(client, url, bearer)
        .await
        .and_then(|json| {
            let entries = parse(&json)?;
            cache.persist(&entries);
            Ok(entries)
        }) {
        Ok(entries) => ProviderCatalog {
            provider_id,
            entries,
            provenance: CatalogProvenance::Remote,
            warning: None,
        },
        Err(error) => match cache.load_valid() {
            Some(entries) => ProviderCatalog {
                provider_id,
                entries,
                provenance: CatalogProvenance::DiskFallback,
                warning: Some(format!(
                    "Provider catalog refresh failed; using validated disk cache: {error}"
                )),
            },
            None => ProviderCatalog::unavailable(
                provider_id,
                format!("Provider catalog unavailable: {error}"),
            ),
        },
    }
}

async fn fetch_catalog_json(
    client: &reqwest::Client,
    url: &str,
    bearer: Option<&str>,
) -> Result<Value, ProviderCatalogError> {
    let mut request = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json");
    if let Some(bearer) = bearer {
        request = request.bearer_auth(bearer);
    }
    let response = request.send().await?.error_for_status()?;
    Ok(response.json::<Value>().await?)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProviderCatalogDiskCache {
    fetched_at: DateTime<Utc>,
    grok_version: String,
    provider_id: ProviderId,
    origin: String,
    entries: IndexMap<String, ModelEntry>,
}

impl ProviderCatalogDiskCache {
    fn is_fresh(&self) -> bool {
        let Ok(ttl) = ChronoDuration::from_std(PROVIDER_CATALOG_CACHE_TTL) else {
            return false;
        };
        let age = Utc::now().signed_duration_since(self.fetched_at);
        age >= ChronoDuration::zero() && age < ttl
    }
}

struct ProviderCatalogCache {
    path: PathBuf,
    provider_id: ProviderId,
    origin: String,
}

fn now_nanos() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => now.as_nanos(),
        Err(_) => 0,
    }
}

impl ProviderCatalogCache {
    fn new(cache_dir: &Path, provider_id: ProviderId, origin: &str) -> Self {
        Self {
            path: cache_dir.join(format!("provider_catalog_{}.json", provider_id.as_str())),
            provider_id,
            origin: origin.to_owned(),
        }
    }

    fn temporary_path(&self) -> PathBuf {
        let seq = PROVIDER_CATALOG_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let pid = process::id();
        let nanos = now_nanos();
        self.path
            .with_extension(format!("json.tmp.{pid}.{nanos}.{seq}"))
    }

    fn load_fresh(&self) -> Option<IndexMap<String, ModelEntry>> {
        let cache = self.load_valid_cache()?;
        cache.is_fresh().then_some(cache.entries)
    }

    fn load_valid(&self) -> Option<IndexMap<String, ModelEntry>> {
        Some(self.load_valid_cache()?.entries)
    }

    fn load_valid_cache(&self) -> Option<ProviderCatalogDiskCache> {
        let data = std::fs::read(&self.path).ok()?;
        let cache: ProviderCatalogDiskCache = serde_json::from_slice(&data).ok()?;
        if cache.grok_version != xai_grok_version::VERSION {
            return None;
        }
        if cache.provider_id != self.provider_id || cache.origin != self.origin {
            return None;
        }
        if cache.entries.is_empty() {
            return None;
        }
        Some(cache)
    }

    fn persist(&self, entries: &IndexMap<String, ModelEntry>) {
        if entries.is_empty() {
            return;
        }
        let cache = ProviderCatalogDiskCache {
            fetched_at: Utc::now(),
            grok_version: xai_grok_version::VERSION.to_owned(),
            provider_id: self.provider_id.clone(),
            origin: self.origin.clone(),
            entries: entries.clone(),
        };
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = self.temporary_path();
        if let Ok(json) = serde_json::to_vec_pretty(&cache)
            && std::fs::write(&tmp, json).is_ok()
        {
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }
}

#[derive(Deserialize)]
struct ModelsDevCatalog {
    openai: ModelsDevProvider,
}

#[derive(Deserialize)]
struct ModelsDevProvider {
    models: IndexMap<String, ModelsDevModel>,
}

#[derive(Deserialize)]
struct ModelsDevModel {
    id: String,
    name: Option<String>,
    description: Option<String>,
    #[serde(default)]
    reasoning: bool,
    #[serde(default)]
    reasoning_options: Vec<ModelsDevReasoningOption>,
    #[serde(default)]
    limit: ModelsDevLimit,
    #[serde(default)]
    experimental: Value,
}

#[derive(Default, Deserialize)]
struct ModelsDevLimit {
    context: Option<u64>,
    output: Option<u32>,
}

#[derive(Deserialize)]
struct ModelsDevReasoningOption {
    #[serde(default)]
    values: Vec<String>,
}

pub(crate) fn parse_openai_models_dev_catalog(
    value: &Value,
) -> Result<IndexMap<String, ModelEntry>, ProviderCatalogError> {
    let catalog: ModelsDevCatalog = serde_json::from_value(value.clone())?;
    let mut entries = IndexMap::new();
    for model in catalog.openai.models.into_values() {
        if !openai_model_is_opencode_compatible(&model) {
            continue;
        }
        let entry = model_entry_from_config(ModelEntryConfig {
            id: Some(ProviderId::OpenAi.catalog_key(&model.id)),
            provider_id: Some(ProviderId::OpenAi),
            model: model.id.clone(),
            base_url: OPENAI_PROVIDER_BASE_URL.to_owned(),
            name: model.name,
            description: model.description,
            max_completion_tokens: model.limit.output,
            temperature: None,
            top_p: None,
            api_key: None,
            env_key: Some(EnvKeys::single("OPENAI_API_KEY")),
            api_backend: ApiBackend::Responses,
            auth_scheme: None,
            reasoning_effort: None,
            supports_reasoning_effort: model.reasoning,
            reasoning_efforts: reasoning_effort_options(model.reasoning_options),
            extra_headers: IndexMap::new(),
            context_window: nonzero_context(model.limit.context),
            auto_compact_threshold_percent: None,
            system_prompt_label: None,
            api_base_url: None,
            use_concise: false,
            agent_type: config::DEFAULT_AGENT_TYPE.to_owned(),
            inference_idle_timeout_secs: None,
            max_retries: None,
            hidden: false,
            supported_in_api: true,
            supports_backend_search: false,
            compactions_remaining: None,
            compaction_at_tokens: None,
            show_model_fingerprint: false,
            stream_tool_calls: None,
            laziness_detector: config::LazinessDetectorPerModelConfig::default(),
        });
        let key = entry
            .info
            .id
            .clone()
            .unwrap_or_else(|| entry.info.model.clone());
        entries.insert(key, entry);
    }
    if entries.is_empty() {
        return Err(ProviderCatalogError::EmptyCatalog);
    }
    Ok(entries)
}

fn openai_model_is_opencode_compatible(model: &ModelsDevModel) -> bool {
    const EXPLICIT_ALLOW: &[&str] = &["gpt-5.5", "gpt-5.3-codex-spark", "gpt-5.4", "gpt-5.4-mini"];
    if EXPLICIT_ALLOW.contains(&model.id.as_str()) {
        return true;
    }
    if model.id == "gpt-5.5-pro" || model.id.starts_with("gpt-5.6") {
        return false;
    }
    if has_reasoning_mode_pro(&model.experimental) {
        return false;
    }
    openai_gpt_numeric_version(&model.id)
        .is_some_and(|version| version > OPENCODE_GPT_OPENAI_MIN_VERSION)
}

fn openai_gpt_numeric_version(id: &str) -> Option<(u32, u32, u32)> {
    let suffix = id.strip_prefix("gpt-")?;
    let versions = suffix
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .next()?;
    let mut parts = versions.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let patch = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    Some((major, minor, patch))
}

fn has_reasoning_mode_pro(value: &Value) -> bool {
    value
        .pointer("/modes/pro/provider/body/reasoning/mode")
        .and_then(Value::as_str)
        .is_some_and(|mode| mode == "pro")
}

fn reasoning_effort_options(options: Vec<ModelsDevReasoningOption>) -> Vec<ReasoningEffortOption> {
    let mut efforts = Vec::new();
    for value in options.into_iter().flat_map(|option| option.values) {
        let Ok(effort) = ReasoningEffort::from_str(&value) else {
            continue;
        };
        let id = effort.as_str().to_owned();
        efforts.push(ReasoningEffortOption {
            id: id.clone(),
            value: effort,
            label: id,
            description: None,
            default: false,
        });
    }
    if let Some(default_index) = efforts
        .iter()
        .position(|option| option.value == ReasoningEffort::Medium)
        .or_else(|| (!efforts.is_empty()).then_some(0))
    {
        efforts[default_index].default = true;
    }
    efforts
}

#[derive(Deserialize)]
struct OpenCodeGoCatalog {
    data: Vec<OpenCodeGoModel>,
}

#[derive(Deserialize)]
struct OpenCodeGoModel {
    id: String,
    name: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    capabilities: Value,
    #[serde(default)]
    limit: OpenCodeGoLimit,
}

#[derive(Default, Deserialize)]
struct OpenCodeGoLimit {
    context: Option<u64>,
    output: Option<u32>,
}

pub(crate) fn parse_opencode_go_catalog(
    value: &Value,
) -> Result<IndexMap<String, ModelEntry>, ProviderCatalogError> {
    let catalog: OpenCodeGoCatalog = serde_json::from_value(value.clone())?;
    let mut entries = IndexMap::new();
    for model in catalog.data {
        if model.id.trim().is_empty() {
            continue;
        }
        let backend = opencode_backend_for(&model);
        let entry = model_entry_from_config(ModelEntryConfig {
            id: Some(ProviderId::OpencodeGo.catalog_key(&model.id)),
            provider_id: Some(ProviderId::OpencodeGo),
            model: model.id.clone(),
            base_url: OPENCODE_GO_PROVIDER_BASE_URL.to_owned(),
            name: model.name.or_else(|| Some(model.id.clone())),
            description: None,
            max_completion_tokens: model.limit.output,
            temperature: None,
            top_p: None,
            api_key: None,
            env_key: Some(EnvKeys::single("OPENCODE_API_KEY")),
            api_backend: backend,
            auth_scheme: None,
            reasoning_effort: None,
            supports_reasoning_effort: false,
            reasoning_efforts: Vec::new(),
            extra_headers: IndexMap::new(),
            context_window: nonzero_context(model.limit.context),
            auto_compact_threshold_percent: None,
            system_prompt_label: None,
            api_base_url: None,
            use_concise: false,
            agent_type: config::DEFAULT_AGENT_TYPE.to_owned(),
            inference_idle_timeout_secs: None,
            max_retries: None,
            hidden: false,
            supported_in_api: true,
            supports_backend_search: false,
            compactions_remaining: None,
            compaction_at_tokens: None,
            show_model_fingerprint: false,
            stream_tool_calls: None,
            laziness_detector: config::LazinessDetectorPerModelConfig::default(),
        });
        let key = entry
            .info
            .id
            .clone()
            .unwrap_or_else(|| entry.info.model.clone());
        entries.insert(key, entry);
    }
    if entries.is_empty() {
        return Err(ProviderCatalogError::EmptyCatalog);
    }
    Ok(entries)
}

fn opencode_backend_for(model: &OpenCodeGoModel) -> ApiBackend {
    let model_id = model.id.to_ascii_lowercase();
    let mut hints = Vec::new();
    if let Some(endpoint) = &model.endpoint {
        hints.push(endpoint.to_ascii_lowercase());
    }
    hints.push(model.capabilities.to_string().to_ascii_lowercase());

    if OPENCODE_GO_MESSAGES_FAMILIES
        .iter()
        .any(|needle| model_id.contains(needle))
    {
        return ApiBackend::Messages;
    }

    let has_responses_hint = hints
        .iter()
        .any(|hint| hint.contains("responses") || hint.contains("/responses"));
    if model_id.starts_with("gpt-") {
        return if has_responses_hint {
            ApiBackend::Responses
        } else {
            ApiBackend::ChatCompletions
        };
    }
    if has_responses_hint {
        ApiBackend::Responses
    } else if hints
        .iter()
        .any(|hint| hint.contains("messages") || hint.contains("anthropic"))
    {
        ApiBackend::Messages
    } else {
        ApiBackend::ChatCompletions
    }
}

fn model_entry_from_config(config: ModelEntryConfig) -> ModelEntry {
    ModelEntry {
        info: config::ModelInfo::from_config(&config),
        api_key: config.api_key,
        env_key: config.env_key,
        auth_provider: None,
        api_base_url: config.api_base_url,
    }
}

fn nonzero_context(value: Option<u64>) -> NonZeroU64 {
    value
        .and_then(NonZeroU64::new)
        .unwrap_or_else(|| NonZeroU64::new(200_000).expect("200000 is non-zero"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn openai_fixture() -> Value {
        serde_json::json!({
            "openai": {
                "models": {
                    "gpt-5.4": {
                        "id": "gpt-5.4",
                        "name": "GPT-5.4",
                        "reasoning": true,
                        "reasoning_options": [{ "type": "effort", "values": ["low", "medium", "high"] }],
                        "limit": { "context": 1050000, "output": 128000 }
                    },
                    "gpt-5.4-pro": {
                        "id": "gpt-5.4-pro",
                        "experimental": { "modes": { "pro": { "provider": { "body": { "reasoning": { "mode": "pro" }}}}}}
                    },
                    "gpt-5.5": {
                        "id": "gpt-5.5",
                        "limit": { "context": 1050000 }
                    },
                    "gpt-5.5-pro": {
                        "id": "gpt-5.5-pro",
                        "limit": { "context": 1050000 }
                    },
                    "gpt-5.6-sol": {
                        "id": "gpt-5.6-sol",
                        "limit": { "context": 1050000 }
                    },
                    "gpt-5.7-terra": {
                        "id": "gpt-5.7-terra",
                        "limit": { "context": 1050000 }
                    },
                    "gpt-5.10": {
                        "id": "gpt-5.10",
                        "limit": { "context": 1050000 }
                    },
                    "gpt-5.3-codex-spark": {
                        "id": "gpt-5.3-codex-spark",
                        "limit": { "context": 128000 }
                    }
                }
            }
        })
    }

    #[test]
    fn provider_id_namespaces_external_models_and_keeps_legacy_xai_unqualified() {
        assert_eq!(ProviderId::OpenAi.catalog_key("gpt-5.5"), "openai:gpt-5.5");
        assert_eq!(
            ProviderId::OpencodeGo.catalog_key("grok-4.5"),
            "opencode-go:grok-4.5"
        );
        assert_eq!(ProviderId::Xai.catalog_key("grok-4.5"), "grok-4.5");
        assert_eq!(
            ProviderId::parse_catalog_key("xai:grok-4.5"),
            (ProviderId::Xai, "grok-4.5")
        );
        assert_eq!(
            ProviderId::parse_catalog_key("grok-4.5"),
            (ProviderId::Xai, "grok-4.5")
        );
        let custom = ProviderId::Custom("partner:gateway".to_owned());
        assert_eq!(
            ProviderId::parse_catalog_key(&custom.catalog_key("grok-4.5")),
            (custom, "grok-4.5")
        );
    }

    #[test]
    fn openai_catalog_keeps_only_opencode_compatible_models() {
        let entries = parse_openai_models_dev_catalog(&openai_fixture()).unwrap();
        assert!(entries.contains_key("openai:gpt-5.4"));
        assert!(entries.contains_key("openai:gpt-5.5"));
        assert!(entries.contains_key("openai:gpt-5.3-codex-spark"));
        assert!(entries.contains_key("openai:gpt-5.7-terra"));
        assert!(entries.contains_key("openai:gpt-5.10"));
        assert!(!entries.contains_key("openai:gpt-5.4-pro"));
        assert!(!entries.contains_key("openai:gpt-5.5-pro"));
        assert!(!entries.contains_key("openai:gpt-5.6-sol"));

        let gpt54 = &entries["openai:gpt-5.4"];
        assert_eq!(gpt54.info.provider_id, Some(ProviderId::OpenAi));
        assert_eq!(gpt54.info.model, "gpt-5.4");
        assert_eq!(gpt54.info.api_backend, ApiBackend::Responses);
        assert_eq!(gpt54.info.context_window.get(), 1_050_000);
        assert!(gpt54.info.supports_reasoning_effort);
    }

    #[test]
    fn opencode_go_catalog_namespaces_entries_and_selects_backend_from_hints() {
        let wire = serde_json::json!({
            "object": "list",
            "data": [{
                "id": "glm-5.2",
                "name": "GLM 5.2",
                "endpoint": "/v1/responses",
                "limit": { "context": 1000000, "output": 131072 }
            }, {
                "id": "claudeish",
                "capabilities": { "api": "messages", "vendor": "anthropic" }
            }, {
                "id": "qwen-2.5",
                "capabilities": { "api": "chat-completions", "vendor": "qwen" },
                "limit": { "context": 1024, "output": 1024 }
            }, {
                "id": "gpt-4o",
                "endpoint": "/v1/responses",
                "limit": { "context": 8192, "output": 1024 }
            }, {
                "id": "gpt-4o-no-responses",
                "endpoint": "/v1/chat/completions",
                "limit": { "context": 8192, "output": 1024 }
            }, {
                "id": "plain-chat"
            }]
        });
        let entries = parse_opencode_go_catalog(&wire).unwrap();
        assert_eq!(
            entries["opencode-go:glm-5.2"].info.provider_id,
            Some(ProviderId::OpencodeGo)
        );
        assert_eq!(
            entries["opencode-go:glm-5.2"].info.api_backend,
            ApiBackend::Responses
        );
        assert_eq!(
            entries["opencode-go:claudeish"].info.api_backend,
            ApiBackend::Messages
        );
        assert_eq!(
            entries["opencode-go:qwen-2.5"].info.api_backend,
            ApiBackend::Messages
        );
        assert_eq!(
            entries["opencode-go:gpt-4o"].info.api_backend,
            ApiBackend::Responses
        );
        assert_eq!(
            entries["opencode-go:gpt-4o-no-responses"].info.api_backend,
            ApiBackend::ChatCompletions
        );
        assert_eq!(
            entries["opencode-go:plain-chat"].info.api_backend,
            ApiBackend::ChatCompletions
        );
    }

    #[test]
    fn provider_catalog_cache_validates_origin_and_allows_stale_disk_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let cache = ProviderCatalogCache::new(temp.path(), ProviderId::OpenAi, "https://origin");
        let entries = parse_openai_models_dev_catalog(&openai_fixture()).unwrap();
        cache.persist(&entries);
        assert!(cache.load_fresh().is_some());

        let mut disk: ProviderCatalogDiskCache =
            serde_json::from_slice(&std::fs::read(&cache.path).unwrap()).unwrap();
        disk.fetched_at = Utc::now() - ChronoDuration::minutes(10);
        std::fs::write(&cache.path, serde_json::to_vec(&disk).unwrap()).unwrap();
        assert!(cache.load_fresh().is_none());
        assert!(cache.load_valid().is_some());

        let wrong_origin =
            ProviderCatalogCache::new(temp.path(), ProviderId::OpenAi, "https://other-origin");
        assert!(wrong_origin.load_valid().is_none());
    }
}
