// SPDX-License-Identifier: Apache-2.0

//! The policy engine: Cedar evaluation with UAOS semantics layered on top (plan D8, §2.5).
//!
//! * **Default deny.** Nothing is allowed unless a permit matches.
//! * **Fail closed.** Cedar skips a policy whose evaluation errors (for example an integer
//!   overflow), so an erroring `forbid` would silently stop forbidding. UAOS turns any
//!   evaluation error into `Deny`, as it does a request or entity set that fails validation.
//! * **Deny > Ask > Allow.** A permit annotated `@effect("ask")` that matches turns an Allow into
//!   an approval request; a forbid still wins over both.
//! * **Strict loading.** Every policy carries a unique `@id`, only known annotations are
//!   accepted (a typo such as `@efect("ask")` would otherwise silently mean Allow), and the set
//!   is validated against the UAOS schema in strict mode. A policy set that fails any check
//!   never loads.
//! * **Grants** compile to permits that match one principal, action, resource and pocket, and
//!   only while `context.now_ms` is before their expiry, so even a grant that is never removed
//!   stops applying on time.
//! * **Per-action slicing.** Policies are partitioned by their action constraint at load, so a
//!   decision evaluates only policies that could apply. A property test proves slicing never
//!   changes a decision.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use cedar_policy::{
    ActionConstraint, AuthorizationError, Authorizer, Context, Decision as CedarDecision, Effect as CedarEffect,
    Entities, Entity, EntityId, EntityTypeName, EntityUid, Policy, PolicyId, PolicySet, Request as CedarRequest,
    RestrictedExpression, Schema, ValidationMode, Validator,
};

use crate::model::{Action, Basis, Decision, Effect, Grant, Principal, Request, Resource};

const SCHEMA_SRC: &str = include_str!("uaos.cedarschema");
const NAMESPACE: &str = "Uaos";

/// Annotations a policy may carry.
const ANNOTATION_ID: &str = "id";
const ANNOTATION_EFFECT: &str = "effect";
const ANNOTATION_REASON: &str = "reason";
const EFFECT_ASK: &str = "ask";
/// Prefix reserved for generated grant policies.
const GRANT_PREFIX: &str = "grant:";

/// Why a policy set could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The built-in schema failed to parse (a build defect, never user input).
    #[error("authorization schema is invalid: {0}")]
    Schema(String),
    /// The policy text does not parse.
    #[error("policy text does not parse: {0}")]
    Parse(String),
    /// A policy violates a UAOS loading rule (ids, annotations).
    #[error("policy {policy}: {problem}")]
    Rule {
        /// The policy's `@id`, or its position if it has none.
        policy: String,
        /// What is wrong.
        problem: String,
    },
    /// The set does not validate against the schema in strict mode.
    #[error("policies do not validate against the UAOS schema: {0}")]
    Invalid(String),
}

/// A loaded, immutable policy set. Build a new engine to change policies or grants.
#[derive(Debug)]
pub struct PolicyEngine {
    schema: Schema,
    authorizer: Authorizer,
    by_action: BTreeMap<Action, PolicySet>,
    /// Cedar policy id → UAOS `@id`.
    labels: BTreeMap<String, String>,
    /// Cedar policy ids of permits annotated `@effect("ask")`.
    asks: BTreeSet<String>,
}

fn schema() -> Result<Schema, PolicyError> {
    Schema::from_cedarschema_str(SCHEMA_SRC)
        .map(|(schema, _warnings)| schema)
        .map_err(|e| PolicyError::Schema(e.to_string()))
}

fn uid(entity_type: &str, id: &str) -> Result<EntityUid, String> {
    let ty = EntityTypeName::from_str(&format!("{NAMESPACE}::{entity_type}")).map_err(|e| e.to_string())?;
    Ok(EntityUid::from_type_name_and_id(ty, EntityId::new(id)))
}

fn principal_uid(p: &Principal) -> Result<EntityUid, String> {
    match p {
        Principal::Agent(cred) => uid("Agent", &cred.to_string()),
        Principal::Human => uid("Human", "human"),
        Principal::Module(name) => uid("Module", name.as_str()),
        Principal::System => uid("System", "system"),
    }
}

fn resource_uid(r: &Resource) -> Result<EntityUid, String> {
    match r {
        Resource::Model { provider, model } => uid("Model", &format!("{provider}/{model}")),
        Resource::Tool(name) => uid("Tool", name.as_str()),
        Resource::Pool(pool) => uid("Pool", &pool.to_string()),
        Resource::ConfigKey(name) => uid("ConfigKey", name.as_str()),
    }
}

fn action_uid(action: Action) -> Result<EntityUid, String> {
    uid("Action", action.cedar_id())
}

/// Cedar source text of an entity reference, e.g. `Uaos::Tool::"git"`. Safe to embed: every
/// component is a validated name or a typed identifier.
fn cedar_ref(entity: &EntityUid) -> String {
    format!("{}::\"{}\"", entity.type_name(), entity.id().unescaped())
}

impl Grant {
    fn to_policy(&self) -> Result<Policy, PolicyError> {
        let label = format!("{GRANT_PREFIX}{}", self.id);
        let rule = |problem: String| PolicyError::Rule {
            policy: label.clone(),
            problem,
        };
        let principal = principal_uid(&self.principal).map_err(rule)?;
        let resource = resource_uid(&self.resource).map_err(rule)?;
        let action = action_uid(self.action).map_err(rule)?;
        let expires = i64::try_from(self.expires_at_ms).map_err(|_| rule("expiry out of range".to_owned()))?;
        let text = format!(
            "@id(\"{label}\")\npermit(principal == {}, action == {}, resource == {})\nwhen {{ context.pocket == \"{}\" && context.now_ms < {expires} }};",
            cedar_ref(&principal),
            cedar_ref(&action),
            cedar_ref(&resource),
            self.pocket,
        );
        Policy::parse(Some(PolicyId::new(&label)), text).map_err(|e| PolicyError::Parse(e.to_string()))
    }
}

impl PolicyEngine {
    /// Loads `policies` (Cedar text) plus `grants`. Grants already expired at `now_ms` are
    /// left out; the rest stay inert after expiry anyway.
    ///
    /// # Errors
    /// [`PolicyError`] if anything fails to parse, breaks a loading rule, or fails strict
    /// schema validation. Nothing is partially loaded.
    pub fn load(policies: &str, grants: &[Grant], now_ms: u64) -> Result<Self, PolicyError> {
        let schema = schema()?;
        let parsed = PolicySet::from_str(policies).map_err(|e| PolicyError::Parse(e.to_string()))?;

        let mut all = PolicySet::new();
        let mut labels = BTreeMap::new();
        let mut asks = BTreeSet::new();
        let mut seen_ids = BTreeSet::new();
        for policy in parsed.policies() {
            let label = check_rules(policy, &mut seen_ids)?;
            if policy.annotation(ANNOTATION_EFFECT) == Some(EFFECT_ASK) {
                asks.insert(policy.id().to_string());
            }
            labels.insert(policy.id().to_string(), label);
            all.add(policy.clone()).map_err(|e| PolicyError::Parse(e.to_string()))?;
        }
        for grant in grants.iter().filter(|g| g.expires_at_ms > now_ms) {
            let policy = grant.to_policy()?;
            labels.insert(policy.id().to_string(), policy.id().to_string());
            all.add(policy).map_err(|e| PolicyError::Parse(e.to_string()))?;
        }

        let validation = Validator::new(schema.clone()).validate(&all, ValidationMode::Strict);
        if !validation.validation_passed() {
            let errors: Vec<String> = validation.validation_errors().map(ToString::to_string).collect();
            return Err(PolicyError::Invalid(errors.join("; ")));
        }

        let mut by_action = BTreeMap::new();
        for action in Action::ALL {
            let action_id = action_uid(action).map_err(PolicyError::Schema)?;
            let mut slice = PolicySet::new();
            for policy in all.policies() {
                let applies = match policy.action_constraint() {
                    ActionConstraint::Any => true,
                    ActionConstraint::Eq(a) => a == action_id,
                    ActionConstraint::In(list) => list.contains(&action_id),
                };
                if applies {
                    slice
                        .add(policy.clone())
                        .map_err(|e| PolicyError::Parse(e.to_string()))?;
                }
            }
            by_action.insert(action, slice);
        }

        Ok(Self {
            schema,
            authorizer: Authorizer::new(),
            by_action,
            labels,
            asks,
        })
    }

    /// Answers one authorization question. Never panics; every failure is a `Deny`.
    #[must_use]
    pub fn authorize(&self, request: &Request) -> Decision {
        let Some(policies) = self.by_action.get(&request.action) else {
            return Decision::deny_error("unknown action");
        };
        self.authorize_with(request, policies)
    }

    /// Like [`PolicyEngine::authorize`] but against the full, unsliced policy set. Used to
    /// prove that slicing never changes a decision.
    #[doc(hidden)]
    #[must_use]
    pub fn authorize_unsliced(&self, request: &Request) -> Decision {
        let mut all = PolicySet::new();
        let mut seen = BTreeSet::new();
        for slice in self.by_action.values() {
            for policy in slice.policies() {
                if seen.insert(policy.id().to_string()) && all.add(policy.clone()).is_err() {
                    return Decision::deny_error("policy set could not be rebuilt");
                }
            }
        }
        self.authorize_with(request, &all)
    }

    fn authorize_with(&self, request: &Request, policies: &PolicySet) -> Decision {
        let (cedar_request, entities) = match self.build(request) {
            Ok(built) => built,
            Err(e) => return Decision::deny_error(e),
        };
        let response = self.authorizer.is_authorized(&cedar_request, policies, &entities);
        let diagnostics = response.diagnostics();
        let label = |id: &String| self.labels.get(id).cloned().unwrap_or_else(|| id.clone());
        // Cedar reports errors in hash order and by internal id; name them by `@id` and sort,
        // so the same question always gets the same explanation.
        let mut errors: Vec<String> = diagnostics
            .errors()
            .map(|e| match e {
                AuthorizationError::PolicyEvaluationError(e) => {
                    format!("policy {}: {}", label(&e.policy_id().to_string()), e.inner())
                }
                #[allow(unreachable_patterns, reason = "future Cedar error kinds still fail closed")]
                other => other.to_string(),
            })
            .collect();
        errors.sort();
        if !errors.is_empty() {
            return Decision {
                effect: Effect::Deny,
                basis: Basis::EvaluationError,
                policies: Vec::new(),
                errors,
            };
        }
        let mut reasons: Vec<String> = diagnostics.reason().map(ToString::to_string).collect();
        reasons.sort();
        match response.decision() {
            CedarDecision::Deny if reasons.is_empty() => Decision {
                effect: Effect::Deny,
                basis: Basis::NoMatchingPermit,
                policies: Vec::new(),
                errors: Vec::new(),
            },
            CedarDecision::Deny => Decision {
                effect: Effect::Deny,
                basis: Basis::Forbidden,
                policies: reasons.iter().map(label).collect(),
                errors: Vec::new(),
            },
            CedarDecision::Allow => {
                let asking: Vec<String> = reasons.iter().filter(|id| self.asks.contains(*id)).map(label).collect();
                if asking.is_empty() {
                    Decision {
                        effect: Effect::Allow,
                        basis: Basis::Permitted,
                        policies: reasons.iter().map(label).collect(),
                        errors: Vec::new(),
                    }
                } else {
                    Decision {
                        effect: Effect::Ask,
                        basis: Basis::ApprovalRequired,
                        policies: asking,
                        errors: Vec::new(),
                    }
                }
            }
        }
    }

    #[allow(
        clippy::disallowed_types,
        reason = "Cedar's entity API takes a HashSet of parents; membership, not iteration order, matters"
    )]
    fn build(&self, request: &Request) -> Result<(CedarRequest, Entities), String> {
        use std::collections::HashSet;

        let principal = principal_uid(&request.principal)?;
        let resource = resource_uid(&request.resource)?;
        let action = action_uid(request.action)?;

        let mut entities = vec![Entity::new_no_attrs(principal.clone(), HashSet::new())];
        if let Resource::Model { provider, .. } = &request.resource {
            let provider = uid("Provider", provider.as_str())?;
            entities.push(Entity::new_no_attrs(provider.clone(), HashSet::new()));
            entities.push(Entity::new_no_attrs(resource.clone(), HashSet::from([provider])));
        } else {
            entities.push(Entity::new_no_attrs(resource.clone(), HashSet::new()));
        }
        let entities = Entities::from_entities(entities, Some(&self.schema)).map_err(|e| e.to_string())?;

        let now = i64::try_from(request.now_ms).map_err(|_| "time out of range".to_owned())?;
        let classes = request
            .data_classes
            .iter()
            .map(|c| RestrictedExpression::new_string(c.to_string()));
        let context = Context::from_pairs([
            (
                "pocket".to_owned(),
                RestrictedExpression::new_string(request.pocket.to_string()),
            ),
            (
                "risk_tier".to_owned(),
                RestrictedExpression::new_long(i64::from(request.risk_tier.get())),
            ),
            ("data_classes".to_owned(), RestrictedExpression::new_set(classes)),
            ("now_ms".to_owned(), RestrictedExpression::new_long(now)),
        ])
        .map_err(|e| e.to_string())?;

        let cedar_request =
            CedarRequest::new(principal, action, resource, context, Some(&self.schema)).map_err(|e| e.to_string())?;
        Ok((cedar_request, entities))
    }
}

/// Enforces the UAOS loading rules on one policy; returns its `@id`.
fn check_rules(policy: &Policy, seen: &mut BTreeSet<String>) -> Result<String, PolicyError> {
    let position = policy.id().to_string();
    let Some(id) = policy.annotation(ANNOTATION_ID) else {
        return Err(PolicyError::Rule {
            policy: position,
            problem: "missing @id(\"…\") annotation".to_owned(),
        });
    };
    let rule = |problem: &str| PolicyError::Rule {
        policy: id.to_owned(),
        problem: problem.to_owned(),
    };
    if id.is_empty() || id.starts_with(GRANT_PREFIX) {
        return Err(rule(
            "@id must be non-empty and must not use the reserved `grant:` prefix",
        ));
    }
    if !seen.insert(id.to_owned()) {
        return Err(rule("duplicate @id"));
    }
    for (key, value) in policy.annotations() {
        match key {
            ANNOTATION_ID | ANNOTATION_REASON => {}
            ANNOTATION_EFFECT if value == EFFECT_ASK && policy.effect() == CedarEffect::Permit => {}
            ANNOTATION_EFFECT if value == EFFECT_ASK => {
                return Err(rule("@effect(\"ask\") is only meaningful on permit"));
            }
            ANNOTATION_EFFECT => return Err(rule("@effect only accepts \"ask\"")),
            _ => {
                return Err(rule(&format!(
                    "unknown annotation @{key} (allowed: @id, @effect, @reason)"
                )));
            }
        }
    }
    Ok(id.to_owned())
}
