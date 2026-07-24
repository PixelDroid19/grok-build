#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitialProviderChoice {
    OpenAi,
    OpencodeGo,
    Xai,
    Quit,
}

pub(crate) fn parse_initial_provider_choice(input: &str) -> Option<InitialProviderChoice> {
    match input.trim().to_ascii_lowercase().as_str() {
        "1" | "openai" => Some(InitialProviderChoice::OpenAi),
        "2" | "opencode-go" | "opengo" => Some(InitialProviderChoice::OpencodeGo),
        "3" | "xai" => Some(InitialProviderChoice::Xai),
        "q" | "quit" | "salir" => Some(InitialProviderChoice::Quit),
        _ => None,
    }
}

pub(crate) fn needs_initial_provider_selection(xai: bool, openai: bool, opencode_go: bool) -> bool {
    !xai && !openai && !opencode_go
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_names_numbers_and_quit() {
        assert_eq!(
            parse_initial_provider_choice("1"),
            Some(InitialProviderChoice::OpenAi)
        );
        assert_eq!(
            parse_initial_provider_choice("opengo"),
            Some(InitialProviderChoice::OpencodeGo)
        );
        assert_eq!(
            parse_initial_provider_choice("xAI"),
            Some(InitialProviderChoice::Xai)
        );
        assert_eq!(
            parse_initial_provider_choice("salir"),
            Some(InitialProviderChoice::Quit)
        );
        assert_eq!(parse_initial_provider_choice("unknown"), None);
    }

    #[test]
    fn selection_is_required_only_when_every_provider_is_disconnected() {
        assert!(needs_initial_provider_selection(false, false, false));
        assert!(!needs_initial_provider_selection(false, true, false));
        assert!(!needs_initial_provider_selection(true, false, false));
        assert!(!needs_initial_provider_selection(true, true, false));
        assert!(!needs_initial_provider_selection(false, false, true));
    }
}
