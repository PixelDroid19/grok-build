//! Provider rows and provider-specific login intent for the in-session `/login` flow.

use xai_grok_shell::agent::model_providers::ProviderId;

/// A provider that can be connected from the pager without leaving the current
/// conversation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderLoginProvider {
    Xai,
    OpenAi,
    OpencodeZen,
    OpencodeGo,
}

impl ProviderLoginProvider {
    pub const ALL: [Self; 4] = [Self::Xai, Self::OpenAi, Self::OpencodeZen, Self::OpencodeGo];

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "xai" => Some(Self::Xai),
            "openai" => Some(Self::OpenAi),
            "opencode" | "opencode-zen" | "zen" => Some(Self::OpencodeZen),
            "opencode-go" | "opencodego" | "opengo" => Some(Self::OpencodeGo),
            _ => None,
        }
    }

    pub fn provider_id(self) -> ProviderId {
        match self {
            Self::Xai => ProviderId::Xai,
            Self::OpenAi => ProviderId::OpenAi,
            Self::OpencodeZen => ProviderId::OpencodeZen,
            Self::OpencodeGo => ProviderId::OpencodeGo,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::Xai => "xai",
            Self::OpenAi => "openai",
            Self::OpencodeZen => "opencode-zen",
            Self::OpencodeGo => "opencode-go",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Xai => "xAI",
            Self::OpenAi => "OpenAI",
            Self::OpencodeZen => "OpenCode Zen (Free models)",
            Self::OpencodeGo => "OpenCode Go",
        }
    }
}

/// A render-ready provider row. It deliberately contains no credential data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderLoginRow {
    pub provider: ProviderLoginProvider,
    pub label: &'static str,
    pub connected: bool,
}

pub fn provider_rows(
    mut is_connected: impl FnMut(ProviderLoginProvider) -> bool,
) -> Vec<ProviderLoginRow> {
    ProviderLoginProvider::ALL
        .into_iter()
        .map(|provider| ProviderLoginRow {
            label: provider.label(),
            connected: is_connected(provider),
            provider,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_keep_the_opencode_connect_order_and_connection_state() {
        let rows = provider_rows(|provider| provider == ProviderLoginProvider::OpenAi);

        assert_eq!(
            rows,
            vec![
                ProviderLoginRow {
                    provider: ProviderLoginProvider::Xai,
                    label: "xAI",
                    connected: false,
                },
                ProviderLoginRow {
                    provider: ProviderLoginProvider::OpenAi,
                    label: "OpenAI",
                    connected: true,
                },
                ProviderLoginRow {
                    provider: ProviderLoginProvider::OpencodeZen,
                    label: "OpenCode Zen (Free models)",
                    connected: false,
                },
                ProviderLoginRow {
                    provider: ProviderLoginProvider::OpencodeGo,
                    label: "OpenCode Go",
                    connected: false,
                },
            ]
        );
    }

    #[test]
    fn accepts_provider_ids_used_by_the_cli() {
        assert_eq!(
            ProviderLoginProvider::parse("opencode-zen"),
            Some(ProviderLoginProvider::OpencodeZen)
        );
        assert_eq!(
            ProviderLoginProvider::parse("xai"),
            Some(ProviderLoginProvider::Xai)
        );
        assert_eq!(
            ProviderLoginProvider::parse("openai"),
            Some(ProviderLoginProvider::OpenAi)
        );
        assert_eq!(
            ProviderLoginProvider::parse("opencode-go"),
            Some(ProviderLoginProvider::OpencodeGo)
        );
        assert_eq!(ProviderLoginProvider::parse("unknown"), None);
    }
}
