# TUI provider login design

## Goal

Make `/login` the in-session entry point for connecting xAI, OpenAI, and
OpenCode Go. The flow follows OpenCode's `/connect` interaction while retaining
grok-build's existing provider-specific authentication and canonical
conversation.

## User flow

1. Running `/login` opens a centered picker titled `Connect a provider`.
2. The picker lists xAI, OpenAI, and OpenCode Go in that order.
3. Each connected provider has a visible connected indicator. Providers remain
   selectable so users can re-authenticate them.
4. Selecting a provider starts its existing authentication method:
   - xAI uses the existing browser OAuth flow.
   - OpenAI uses the existing ChatGPT subscription OAuth flow.
   - OpenCode Go opens a masked API-key input inside the TUI.
5. Successful authentication refreshes that provider's model catalog and opens
   the model picker filtered to the authenticated provider.
6. Selecting a model activates it immediately in the current conversation.
7. Running `/login` again allows another provider to be connected without
   disconnecting providers that are already connected.
8. Escape or authentication failure returns to the current conversation,
   preserves the draft and conversation, and does not change other providers'
   credentials or the active model.

## Architecture

### Provider connection state

A provider-login view model owns the three supported providers, display names,
connection status, and authentication kind. Status is read from the existing
provider-specific credential stores rather than inferred from the active model.
The view model contains no credentials.

### TUI

The provider list and OpenCode Go key input reuse the existing modal picker and
prompt infrastructure. The key field must render as masked input, must never be
placed in scrollback, and must be cleared from memory when the modal closes or
submission completes.

The modal state records the caller's active view. Closing any step restores that
view and its prompt draft. A successful connection transitions directly to the
existing model picker with a provider filter rather than creating a second
model-selection implementation.

### Authentication boundary

Each provider keeps its current authentication implementation and independent
credential storage:

- xAI authentication remains owned by the existing ACP/xAI login path.
- OpenAI authentication remains owned by the ChatGPT subscription OAuth manager.
- OpenCode Go key validation and storage remain owned by the provider auth
  module.

The TUI dispatch layer starts these operations asynchronously and receives typed
completion results. It does not read or persist tokens itself.

### Model activation

After authentication succeeds, the provider catalog is refreshed before the
filtered model picker opens. The existing model-switch action activates the
selected qualified model ID. Provider-private reasoning metadata is sanitized by
the existing provider-switch path, while conversation messages, tool results,
files, and prompt draft remain intact.

## Error and cancellation behavior

- Escape cancels the active step and restores the conversation.
- OAuth cancellation or failure shows a provider-specific actionable error and
  restores the conversation.
- An invalid or empty OpenCode Go key remains in the masked input for correction;
  it is never logged or copied into an error message.
- A catalog refresh failure shows the existing visible catalog warning. If a
  validated cached catalog exists, the filtered picker uses it; otherwise the
  conversation is restored and the provider remains connected.
- Authentication failure for one provider never clears or changes another
  provider's credentials.
- Late results from a cancelled authentication attempt are ignored using the
  existing request sequencing and cancellation mechanism.

## Compatibility

- `/login` remains the command name; no separate `/connect` command is required.
- Command-line `grok login --provider ...`, logout, and auth-status behavior stay
  unchanged.
- Existing xAI-only installations continue to work.
- Already-connected providers can be selected to re-authenticate.
- The flow works while another provider is the active model.

## Verification

Automated tests cover:

- provider rows and connected indicators;
- routing each provider to its correct authentication method;
- masked OpenCode Go key entry and secret redaction;
- cancellation at provider selection, OAuth, and API-key entry;
- successful authentication opening a provider-filtered model picker;
- model selection switching providers without losing conversation state;
- failures and stale completion results leaving unrelated providers unchanged.

PTY validation exercises:

1. `/login` from an active conversation;
2. connecting OpenCode Go with a test credential;
3. choosing an OpenCode Go model;
4. reopening `/login` and connecting OpenAI;
5. selecting an OpenAI model;
6. reopening `/login` and confirming xAI is still connected;
7. cancelling and confirming the conversation and draft are preserved.

The final local build is installed only after Rust tests, formatting, linting,
compilation, and the PTY workflow pass.
