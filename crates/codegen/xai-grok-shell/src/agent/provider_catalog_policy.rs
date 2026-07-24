const EXPLICIT_ALLOW: &[&str] = &["gpt-5.5", "gpt-5.3-codex-spark", "gpt-5.4", "gpt-5.4-mini"];
const EXPLICIT_DENY: &[&str] = &["gpt-5.5-pro", "gpt-5.6"];
const DYNAMIC_MIN_VERSION: (u32, u32, u32) = (5, 4, 0);

/// Mirrors OpenCode's ChatGPT subscription model filter.
///
/// Keep the order aligned with `packages/opencode/src/plugin/openai/codex.ts`:
/// `reasoningMode=pro` wins over the explicit allow-list, then explicit model
/// exceptions, then newer numeric GPT versions.
pub(crate) fn openai_model_is_opencode_compatible(id: &str, reasoning_mode_pro: bool) -> bool {
    if reasoning_mode_pro {
        return false;
    }
    if EXPLICIT_ALLOW.contains(&id) {
        return true;
    }
    if EXPLICIT_DENY.contains(&id) {
        return false;
    }
    openai_gpt_numeric_version(id).is_some_and(|version| version > DYNAMIC_MIN_VERSION)
}

fn openai_gpt_numeric_version(id: &str) -> Option<(u32, u32, u32)> {
    let suffix = id.strip_prefix("gpt-")?;
    let versions = suffix
        .split(|character: char| !(character.is_ascii_digit() || character == '.'))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_current_opencode_allow_deny_and_dynamic_version_policy() {
        assert!(openai_model_is_opencode_compatible("gpt-5.4", false));
        assert!(openai_model_is_opencode_compatible(
            "gpt-5.3-codex-spark",
            false
        ));
        assert!(!openai_model_is_opencode_compatible("gpt-5.5-pro", false));
        assert!(!openai_model_is_opencode_compatible("gpt-5.6", false));
        assert!(openai_model_is_opencode_compatible("gpt-5.6-sol", false));
        assert!(openai_model_is_opencode_compatible("gpt-5.10", false));
        assert!(!openai_model_is_opencode_compatible("gpt-5.3", false));
        assert!(!openai_model_is_opencode_compatible("o3", false));
    }

    #[test]
    fn pro_reasoning_mode_overrides_explicit_allow_list() {
        assert!(!openai_model_is_opencode_compatible("gpt-5.4", true));
    }
}
