// SPDX-License-Identifier: Apache-2.0

//! The reference monitor's guarantees: default deny, fail closed, `Deny > Ask > Allow`, strict
//! loading, time-bounded grants, and per-action slicing that never changes a decision.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::collections::BTreeSet;

use proptest::prelude::*;
use uaos_contracts::id::{CredentialId, GrantId, PocketId, TypedId};
use uaos_contracts::operation::RiskTier;
use uaos_policy::{Action, Basis, Effect, Grant, Name, PolicyEngine, PolicyError, Principal, Request, Resource};

const NOW: u64 = 1_760_000_000_000;

fn agent(n: u8) -> Principal {
    Principal::Agent(CredentialId::from_parts(u64::from(n), [n; 10]))
}

fn pocket(n: u8) -> PocketId {
    PocketId::from_parts(u64::from(n), [n; 10])
}

fn model(provider: &str, model: &str) -> Resource {
    Resource::Model {
        provider: Name::new(provider).unwrap(),
        model: Name::new(model).unwrap(),
    }
}

fn request(principal: Principal, action: Action, resource: Resource) -> Request {
    Request {
        principal,
        action,
        resource,
        pocket: pocket(1),
        risk_tier: RiskTier::new(1).unwrap(),
        data_classes: BTreeSet::new(),
        now_ms: NOW,
    }
}

fn engine(policies: &str) -> PolicyEngine {
    PolicyEngine::load(policies, &[], NOW).unwrap()
}

const ALLOW_ANTHROPIC: &str = r#"
@id("anthropic-for-agents")
permit(principal is Uaos::Agent, action == Uaos::Action::"model.call", resource in Uaos::Provider::"anthropic");
"#;

#[test]
fn nothing_is_allowed_by_default() {
    let d = engine("").authorize(&request(agent(1), Action::ModelCall, model("anthropic", "m")));
    assert_eq!((d.effect, d.basis), (Effect::Deny, Basis::NoMatchingPermit));
}

#[test]
fn a_permit_allows_and_explains_itself() {
    let d = engine(ALLOW_ANTHROPIC).authorize(&request(agent(1), Action::ModelCall, model("anthropic", "m")));
    assert_eq!((d.effect, d.basis), (Effect::Allow, Basis::Permitted));
    assert_eq!(d.policies, ["anthropic-for-agents"]);
    assert_eq!(d.explain(), "allowed by anthropic-for-agents");
    let other = engine(ALLOW_ANTHROPIC).authorize(&request(agent(1), Action::ModelCall, model("openai", "m")));
    assert_eq!(other.effect, Effect::Deny, "the provider hierarchy scopes the permit");
}

#[test]
fn forbid_wins_over_permit() {
    let policies = format!(
        "{ALLOW_ANTHROPIC}\n@id(\"no-aws-secrets\")\nforbid(principal, action == Uaos::Action::\"model.call\", resource) when {{ context.data_classes.contains(\"secret.aws\") }};"
    );
    let mut req = request(agent(1), Action::ModelCall, model("anthropic", "m"));
    req.data_classes.insert(Name::new("secret.aws").unwrap());
    let d = engine(&policies).authorize(&req);
    assert_eq!((d.effect, d.basis), (Effect::Deny, Basis::Forbidden));
    assert_eq!(d.policies, ["no-aws-secrets"]);
}

#[test]
fn ask_outranks_allow_and_deny_outranks_ask() {
    let ask = r#"
@id("exec-needs-approval") @effect("ask") @reason("exec is high risk")
permit(principal is Uaos::Agent, action == Uaos::Action::"exec", resource);
@id("exec-git-ok")
permit(principal is Uaos::Agent, action == Uaos::Action::"exec", resource == Uaos::Tool::"git");
"#;
    let git = request(agent(1), Action::Exec, Resource::Tool(Name::new("git").unwrap()));
    let d = engine(ask).authorize(&git);
    assert_eq!((d.effect, d.basis), (Effect::Ask, Basis::ApprovalRequired));
    assert_eq!(d.policies, ["exec-needs-approval"]);

    let with_forbid =
        format!("{ask}\n@id(\"no-exec\")\nforbid(principal, action == Uaos::Action::\"exec\", resource);");
    assert_eq!(engine(&with_forbid).authorize(&git).effect, Effect::Deny);
}

/// Cedar skips a policy whose evaluation errors. This forbid overflows at runtime, so plain
/// Cedar would answer Allow; UAOS must answer Deny.
#[test]
fn an_erroring_forbid_fails_closed() {
    let policies = format!(
        "{ALLOW_ANTHROPIC}\n@id(\"overflowing-forbid\")\nforbid(principal, action == Uaos::Action::\"model.call\", resource) when {{ context.risk_tier * 9223372036854775807 > 0 }};"
    );
    // Risk tier 2: 2 × i64::MAX overflows at evaluation time.
    let mut req = request(agent(1), Action::ModelCall, model("anthropic", "m"));
    req.risk_tier = RiskTier::new(2).unwrap();
    let d = engine(&policies).authorize(&req);
    assert_eq!((d.effect, d.basis), (Effect::Deny, Basis::EvaluationError));
    assert_eq!(d.errors.len(), 1);
    assert!(
        d.errors[0].starts_with("policy overflowing-forbid: "),
        "errors name the policy by @id: {:?}",
        d.errors
    );
    assert!(d.explain().starts_with("denied: evaluation failed"));
}

#[test]
fn loading_rules_are_strict() {
    let reject = |src: &str| PolicyEngine::load(src, &[], NOW).unwrap_err();
    assert!(
        matches!(reject("permit(principal, action, resource);"), PolicyError::Rule { .. }),
        "missing @id"
    );
    assert!(matches!(
        reject("@id(\"a\") permit(principal, action, resource);\n@id(\"a\") forbid(principal, action, resource);"),
        PolicyError::Rule { .. }
    ));
    assert!(matches!(
        reject("@id(\"a\") @efect(\"ask\") permit(principal, action, resource);"),
        PolicyError::Rule { .. }
    ));
    assert!(matches!(
        reject("@id(\"a\") @effect(\"ask\") forbid(principal, action, resource);"),
        PolicyError::Rule { .. }
    ));
    assert!(matches!(
        reject("@id(\"a\") @effect(\"allow\") permit(principal, action, resource);"),
        PolicyError::Rule { .. }
    ));
    assert!(matches!(
        reject("@id(\"grant:x\") permit(principal, action, resource);"),
        PolicyError::Rule { .. }
    ));
    assert!(matches!(
        reject("@id(\"a\") permit(principal, action, resource) when { context.no_such_field == 1 };"),
        PolicyError::Invalid(_)
    ));
    assert!(matches!(
        reject("@id(\"a\") permit(principal, action, resource"),
        PolicyError::Parse(_)
    ));
}

#[test]
fn grants_are_scoped_and_expire() {
    let grant = Grant {
        id: GrantId::from_parts(1, [1; 10]),
        principal: agent(1),
        action: Action::Exec,
        resource: Resource::Tool(Name::new("git").unwrap()),
        pocket: pocket(1),
        expires_at_ms: NOW + 60_000,
    };
    let e = PolicyEngine::load("", std::slice::from_ref(&grant), NOW).unwrap();
    let git = request(agent(1), Action::Exec, Resource::Tool(Name::new("git").unwrap()));
    let d = e.authorize(&git);
    assert_eq!(d.effect, Effect::Allow);
    assert_eq!(d.policies, [format!("grant:{}", grant.id)]);

    let mut later = git.clone();
    later.now_ms = NOW + 60_000;
    assert_eq!(
        e.authorize(&later).effect,
        Effect::Deny,
        "inert at expiry even if never removed"
    );
    let mut elsewhere = git.clone();
    elsewhere.pocket = pocket(2);
    assert_eq!(e.authorize(&elsewhere).effect, Effect::Deny, "scoped to its pocket");
    let mut someone_else = git.clone();
    someone_else.principal = agent(2);
    assert_eq!(
        e.authorize(&someone_else).effect,
        Effect::Deny,
        "scoped to its principal"
    );
    let curl = request(agent(1), Action::Exec, Resource::Tool(Name::new("curl").unwrap()));
    assert_eq!(e.authorize(&curl).effect, Effect::Deny, "scoped to its resource");

    let expired = PolicyEngine::load("", &[grant], NOW + 60_000).unwrap();
    assert_eq!(
        expired.authorize(&git).effect,
        Effect::Deny,
        "already expired grants are not loaded"
    );
}

#[test]
fn names_cannot_inject_policy_text() {
    assert!(Name::new("git\" ) || true //").is_err());
    assert!(Name::new("").is_err());
    assert!(Name::new("a".repeat(129)).is_err());
    assert!(Name::new("anthropic/claude-sonnet-5.5:latest").is_ok());
}

// ── Properties ───────────────────────────────────────────────────────────────────────────

/// Building blocks for random policy sets.
fn policy_piece(i: usize, kind: u8, action: u8, flag: u8) -> String {
    let actions = ["model.call", "exec", "tool.call", "budget.transfer"];
    let a = actions[usize::from(action) % actions.len()];
    let action_clause = match flag % 3 {
        0 => format!("action == Uaos::Action::\"{a}\""),
        1 => "action".to_owned(),
        _ => format!("action in [Uaos::Action::\"{a}\", Uaos::Action::\"model.call\"]"),
    };
    let cond = if flag.is_multiple_of(2) {
        ""
    } else {
        " when { context.risk_tier > 1 }"
    };
    match kind % 4 {
        0 => format!("@id(\"p{i}\") permit(principal, {action_clause}, resource){cond};"),
        1 => format!("@id(\"f{i}\") forbid(principal, {action_clause}, resource){cond};"),
        2 => format!("@id(\"a{i}\") @effect(\"ask\") permit(principal, {action_clause}, resource){cond};"),
        _ => format!(
            "@id(\"e{i}\") forbid(principal, {action_clause}, resource) when {{ context.risk_tier * 9223372036854775807 > 0 }};"
        ),
    }
}

fn random_request(action: u8, tier: u8) -> Request {
    let (action, resource) = match action % 4 {
        0 => (Action::ModelCall, model("anthropic", "m")),
        1 => (Action::Exec, Resource::Tool(Name::new("git").unwrap())),
        2 => (Action::ToolCall, Resource::Tool(Name::new("fs").unwrap())),
        _ => (
            Action::BudgetTransfer,
            Resource::Pool(uaos_contracts::id::PoolId::from_parts(1, [1; 10])),
        ),
    };
    let mut r = request(agent(1), action, resource);
    r.risk_tier = RiskTier::new(tier % 4).unwrap();
    r
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Slicing by action never changes any decision.
    #[test]
    fn slicing_preserves_decisions(
        pieces in prop::collection::vec((any::<u8>(), any::<u8>(), any::<u8>()), 0..12),
        req in (any::<u8>(), any::<u8>()),
    ) {
        let text: Vec<String> = pieces.iter().enumerate().map(|(i, (k, a, f))| policy_piece(i, *k, *a, *f)).collect();
        let e = PolicyEngine::load(&text.join("\n"), &[], NOW).unwrap();
        let r = random_request(req.0, req.1);
        prop_assert_eq!(e.authorize(&r), e.authorize_unsliced(&r));
    }

    /// Whenever an applicable policy errors, the answer is Deny — never Allow or Ask.
    #[test]
    fn evaluation_errors_never_allow(
        pieces in prop::collection::vec((any::<u8>(), any::<u8>(), any::<u8>()), 1..12),
        req in (any::<u8>(), any::<u8>()),
    ) {
        let text: Vec<String> = pieces.iter().enumerate().map(|(i, (k, a, f))| policy_piece(i, *k, *a, *f)).collect();
        let e = PolicyEngine::load(&text.join("\n"), &[], NOW).unwrap();
        let d = e.authorize(&random_request(req.0, req.1));
        if !d.errors.is_empty() {
            prop_assert_eq!(d.effect, Effect::Deny);
        }
        if d.effect != Effect::Deny {
            prop_assert!(d.errors.is_empty());
        }
    }
}
