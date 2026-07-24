//! `/login` -- log in or re-authenticate with your account.

use crate::app::actions::Action;
use crate::provider_login::{ProviderLoginProvider, provider_rows};
use crate::slash::command::{AppCtx, ArgItem, CommandExecCtx, CommandResult, SlashCommand};

pub struct LoginCommand;

impl SlashCommand for LoginCommand {
    fn name(&self) -> &str {
        "login"
    }

    fn description(&self) -> &str {
        "Connect or re-authenticate a model provider"
    }

    fn usage(&self) -> &str {
        "/login [xai|openai|opencode-go]"
    }

    fn takes_args(&self) -> bool {
        true
    }

    fn suggest_args(&self, _ctx: &AppCtx, _args_query: &str) -> Option<Vec<ArgItem>> {
        Some(
            provider_rows(|provider| match provider {
                ProviderLoginProvider::Xai => false,
                ProviderLoginProvider::OpenAi => {
                    xai_grok_shell::auth::provider_cli::provider_is_authenticated("openai")
                }
                ProviderLoginProvider::OpencodeGo => {
                    xai_grok_shell::auth::provider_cli::provider_is_authenticated("opencode-go")
                }
            })
            .into_iter()
            .map(|row| ArgItem {
                display: if row.connected {
                    format!("{} (connected)", row.label)
                } else {
                    row.label.to_owned()
                },
                match_text: format!("{} {}", row.label, row.provider.id()),
                insert_text: row.provider.id().to_owned(),
                description: if row.connected {
                    "Re-authenticate".to_owned()
                } else {
                    "Connect provider".to_owned()
                },
            })
            .collect(),
        )
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        let trimmed = args.trim();
        if trimmed.is_empty() {
            return CommandResult::Action(Action::OpenProviderLogin);
        }
        match ProviderLoginProvider::parse(trimmed) {
            Some(provider) => CommandResult::Action(Action::ConnectProvider(provider)),
            None => CommandResult::Error(format!("Unknown provider: {trimmed}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::model_state::ModelState;

    fn context<'a>(models: &'a ModelState) -> CommandExecCtx<'a> {
        static EMPTY_BUNDLE: crate::app::bundle::BundleState = crate::app::bundle::BundleState {
            has_cache: false,
            version: String::new(),
            personas: Vec::new(),
            roles: Vec::new(),
            agents: Vec::new(),
            skills: Vec::new(),
            persona_details: Vec::new(),
            role_details: Vec::new(),
        };
        CommandExecCtx {
            models,
            session_id: None,
            bundle_state: &EMPTY_BUNDLE,
            screen_mode: crate::app::ScreenMode::Inline,
            billing_surface_visible: true,
            pager_state: crate::settings::PagerLocalSnapshot::default(),
        }
    }

    #[test]
    fn empty_login_opens_provider_picker() {
        let models = ModelState::default();
        let mut ctx = context(&models);
        assert!(matches!(
            LoginCommand.run(&mut ctx, ""),
            CommandResult::Action(Action::OpenProviderLogin)
        ));
    }

    #[test]
    fn provider_id_starts_its_specific_login_flow() {
        let models = ModelState::default();
        let mut ctx = context(&models);
        assert!(matches!(
            LoginCommand.run(&mut ctx, "opencode-go"),
            CommandResult::Action(Action::ConnectProvider(ProviderLoginProvider::OpencodeGo))
        ));
    }
}
