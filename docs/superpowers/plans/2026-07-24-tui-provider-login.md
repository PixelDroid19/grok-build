# TUI Provider Login Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `/login` connect xAI, OpenAI, or OpenCode Go from the active TUI session and then select a model from that provider.

**Architecture:** `/login` becomes a provider picker that reports independent connection state. A dedicated provider-login controller owns provider choice, cancellation, and secure key entry, while existing provider authentication/storage functions remain the sole owners of credentials. On success the controller refreshes the provider catalog and delegates model activation to the existing model switch path.

**Tech Stack:** Rust, ratatui/crossterm, existing pager action/effect/task-result loop, xAI/OpenAI/OpenCode Go auth managers.

## Global Constraints

- Keep `/login` as the public command; do not add a competing login command.
- Use independent existing credential stores; never place credentials in scrollback or logs.
- Preserve the current conversation, draft, tools, and connected providers on cancel or failure.
- Use the existing qualified provider model IDs and model-switch sanitization.
- Do not invoke external CLIs.

---

### Task 1: Provider picker domain and slash entry point

**Files:**
- Create: `crates/codegen/xai-grok-pager/src/provider_login.rs`
- Modify: `crates/codegen/xai-grok-pager/src/slash/commands/login.rs`
- Modify: `crates/codegen/xai-grok-pager/src/app/actions.rs`
- Test: `crates/codegen/xai-grok-pager/src/provider_login.rs`

**Interfaces:**
- Produces `ProviderLoginProvider::{Xai, OpenAi, OpencodeGo}` and `provider_rows()`.
- Produces `Action::OpenProviderLogin` and `Action::SelectProviderLogin(ProviderLoginProvider)`.

- [ ] **Step 1: Write failing tests** for stable xAI/OpenAI/OpenCode Go row order, labels, and connected state from credential probes.
- [ ] **Step 2: Run the focused test** with `cargo test -p xai-grok-pager provider_login --lib`; expect compilation failure because the module and action do not exist.
- [ ] **Step 3: Implement the typed provider rows and route `/login` to `OpenProviderLogin`** instead of beginning xAI authentication immediately.
- [ ] **Step 4: Run the focused test again**; expect all provider-row tests to pass.

### Task 2: Modal rendering and secure OpenCode Go key entry

**Files:**
- Modify: `crates/codegen/xai-grok-pager/src/views/modal.rs`
- Modify: `crates/codegen/xai-grok-pager/src/app/modals.rs`
- Modify: `crates/codegen/xai-grok-pager/src/app/agent_view/render.rs`
- Test: `crates/codegen/xai-grok-pager/src/app/modals.rs`

**Interfaces:**
- Produces `ActiveModal::ProviderLogin` with picker and masked-key phases.
- Produces `Action::SubmitOpencodeGoKey(String)` and `Action::CancelProviderLogin`.

- [ ] **Step 1: Write failing modal tests** proving Escape restores the underlying session and the rendered API key contains no middle key characters.
- [ ] **Step 2: Run the focused test** with `cargo test -p xai-grok-pager provider_login_modal --lib`; expect failure because the modal does not exist.
- [ ] **Step 3: Implement the modal using the existing picker and masked-token rendering primitive.** Clear the temporary key on submit and close.
- [ ] **Step 4: Run the focused test again**; expect pass.

### Task 3: Async provider authentication and provider-filtered model selection

**Files:**
- Modify: `crates/codegen/xai-grok-pager/src/app/actions.rs`
- Modify: `crates/codegen/xai-grok-pager/src/app/dispatch/auth.rs`
- Modify: `crates/codegen/xai-grok-pager/src/app/dispatch/router.rs`
- Modify: `crates/codegen/xai-grok-pager/src/app/dispatch/task_result.rs`
- Modify: `crates/codegen/xai-grok-pager/src/app/event_loop.rs`
- Modify: `crates/codegen/xai-grok-pager/src/app/modals.rs`
- Test: `crates/codegen/xai-grok-pager/src/app/dispatch/tests/auth.rs`

**Interfaces:**
- Produces `Effect::AuthenticateProvider` and `TaskResult::ProviderLoginComplete`.
- On success opens `/model` with only the authenticated provider's catalog rows.

- [ ] **Step 1: Write failing dispatch tests** for correct xAI/OpenAI/OpenCode Go effect routing, stale result rejection, success opening a provider-filtered model picker, and failure preserving the active model.
- [ ] **Step 2: Run the focused test** with `cargo test -p xai-grok-pager provider_login --lib`; expect failure because these effects/results do not exist.
- [ ] **Step 3: Implement provider-specific effects using the existing xAI ACP path and existing OpenAI/OpenCode Go auth functions.** Refresh only the selected provider catalog before opening the filtered picker.
- [ ] **Step 4: Run the focused test again**; expect pass.

### Task 4: End-to-end regression validation

**Files:**
- Modify: `crates/codegen/xai-grok-pager/docs/user-guide/02-authentication.md`
- Test: existing pager dispatch and PTY suites

- [ ] **Step 1: Add a regression test** that connects OpenCode Go, chooses a model, cancels a subsequent `/login`, and proves the original draft/model remain.
- [ ] **Step 2: Run targeted tests** with `cargo test -p xai-grok-pager provider_login --lib` and `cargo test -p xai-grok-pager --lib app::dispatch::tests::auth`.
- [ ] **Step 3: Run quality checks** with `cargo fmt --check`, `cargo clippy -p xai-grok-pager --lib -- -D warnings`, and `cargo check -p xai-grok-pager-bin`.
- [ ] **Step 4: Run the PTY flow** for `/login`, provider selection, Escape, and model picker opening; inspect that secrets are absent from transcript output.
- [ ] **Step 5: Commit** implementation and tests with `git commit -m "Add in-session provider login"`.
