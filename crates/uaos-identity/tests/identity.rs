// SPDX-License-Identifier: Apache-2.0

//! Behaviour of scoped credentials (ADR-0011, plan v2 WP2.4).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests: failures should be loud and immediate"
)]

use std::path::Path;
use std::sync::Arc;

use proptest::prelude::*;
use uaos_contracts::credential::{
    ActionName, CredentialKind, PatternMatch, PatternValue, ResourceKind, ResourcePattern, Scope, ScopeSet,
};
use uaos_contracts::error::codes;
use uaos_contracts::event::Actor;
use uaos_contracts::id::{CorrelationId, CredentialId, PocketId, TypedId};
use uaos_contracts::limits::{self, Millis};
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::{ConfigVersion, RevocationSeq};
use uaos_identity::scope::{ScopeRequest, scope_covers, scope_within};
use uaos_identity::{
    Identity, IdentityError, IdentityKeys, IssueRequest, Issued, JournalSink, MemorySink, entries_from_journal,
};
use uaos_platform::fs::Fs;
use uaos_platform::keychain::Keychain;
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::keychain::SimKeychain;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, Rng};
use uaos_state::journal::{FlushPolicy, JOURNAL_DIR, Journal, read_verified};

const INSTALLATION: &str = "inst-test";
const T0: i128 = 1_760_000_000_000_000_000;
const HOUR: i128 = 3_600_000_000_000;

fn at(offset_hours: i128) -> WallTime {
    WallTime::from_unix_nanos(T0 + offset_hours * HOUR).unwrap()
}

fn cred(n: u8) -> CredentialId {
    CredentialId::from_parts(1, [n; 10])
}

fn pocket(n: u8) -> PocketId {
    PocketId::from_parts(1, [n; 10])
}

fn action(name: &str) -> ActionName {
    ActionName::new(name).unwrap()
}

fn models(prefix: &str) -> ResourcePattern {
    ResourcePattern {
        kind: ResourceKind::Model,
        matching: PatternMatch::Prefix,
        value: PatternValue::new(prefix).unwrap(),
    }
}

fn master_scope() -> Scope {
    Scope {
        actions: ScopeSet::Any,
        resources: ScopeSet::Any,
        pockets: ScopeSet::Any,
        pools: ScopeSet::Any,
        expires_at: None,
    }
}

fn sub_scope(expires_hours: i128) -> Scope {
    Scope {
        actions: ScopeSet::Only([action("model.call"), action("model.count_tokens")].into()),
        resources: ScopeSet::Only([models("claude-")].into()),
        pockets: ScopeSet::Only([pocket(1)].into()),
        pools: ScopeSet::Any,
        expires_at: Some(at(expires_hours)),
    }
}

struct World {
    keychain: Arc<SimKeychain>,
    keys: IdentityKeys,
    rng: SimRng,
    identity: Identity,
    sink: MemorySink,
}

impl World {
    fn new() -> Self {
        let keychain = Arc::new(SimKeychain::new());
        let rng = SimRng::new(11);
        let keys = IdentityKeys::open(keychain.clone(), &rng, INSTALLATION).unwrap();
        Self {
            keychain,
            keys,
            rng,
            identity: Identity::default(),
            sink: MemorySink::default(),
        }
    }

    fn issue(&mut self, id: CredentialId, parent: Option<CredentialId>, scope: Scope) -> Result<Issued, IdentityError> {
        self.identity.issue(
            &mut self.sink,
            &self.keys,
            &self.rng,
            IssueRequest {
                id,
                parent,
                label: None,
                scope,
            },
            at(0),
        )
    }

    fn verify(&self, issued: &Issued, now: WallTime) -> Result<uaos_identity::Verified, IdentityError> {
        self.identity.verify(&self.keys, &issued.text, now)
    }
}

#[test]
fn issued_credentials_verify_with_their_chain_and_scope() {
    let mut w = World::new();
    let master = w.issue(cred(1), None, master_scope()).unwrap();
    let sub = w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap();
    assert_eq!(sub.record.kind, CredentialKind::Sub);
    let verified = w.verify(&sub, at(1)).unwrap();
    assert_eq!(verified.credential, cred(2));
    assert_eq!(verified.chain, vec![cred(2), cred(1)]);
    assert!(scope_covers(
        &verified.scope,
        &ScopeRequest {
            action: "model.call",
            resource: Some((ResourceKind::Model, "claude-sonnet-5-5")),
            pocket: Some(pocket(1)),
            pool: None,
        }
    ));
    assert!(!scope_covers(
        &verified.scope,
        &ScopeRequest {
            action: "model.call",
            resource: Some((ResourceKind::Model, "gpt-5")),
            pocket: Some(pocket(1)),
            pool: None,
        }
    ));
    assert_eq!(w.verify(&master, at(1)).unwrap().kind, CredentialKind::Master);
}

#[test]
fn a_child_can_never_exceed_its_parent() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap();
    let mut wider = sub_scope(12);
    wider.resources = ScopeSet::Any;
    let err = w.issue(cred(3), Some(cred(2)), wider).unwrap_err();
    assert_eq!(err.code(), codes::IDENTITY_SCOPE_EXCEEDS_PARENT);
    let mut later = sub_scope(48);
    later.resources = ScopeSet::Only([models("claude-opus")].into());
    assert!(matches!(
        w.issue(cred(4), Some(cred(2)), later),
        Err(IdentityError::ScopeExceedsParent(_))
    ));
    // Narrower in every dimension is accepted, and its kind is Child.
    let mut narrower = sub_scope(12);
    narrower.actions = ScopeSet::Only([action("model.call")].into());
    narrower.resources = ScopeSet::Only([models("claude-opus")].into());
    assert_eq!(
        w.issue(cred(5), Some(cred(2)), narrower).unwrap().record.kind,
        CredentialKind::Child
    );
    // Refused issuances were never recorded.
    assert_eq!(w.sink.entries.len(), 3);
}

#[test]
fn the_chain_is_bounded() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    for depth in 1..limits::MAX_CREDENTIAL_DEPTH {
        let n = u8::try_from(depth).unwrap() + 1;
        w.issue(cred(n), Some(cred(n - 1)), sub_scope(24)).unwrap();
    }
    let last = u8::try_from(limits::MAX_CREDENTIAL_DEPTH).unwrap();
    let err = w.issue(cred(last + 1), Some(cred(last)), sub_scope(24)).unwrap_err();
    assert_eq!(err.code(), codes::IDENTITY_DEPTH_EXCEEDED);
}

#[test]
fn revocation_takes_effect_on_the_next_verify_for_every_descendant() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    let sub_a = w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap();
    let child = w.issue(cred(3), Some(cred(2)), sub_scope(12)).unwrap();
    let sub_b = w.issue(cred(4), Some(cred(1)), sub_scope(24)).unwrap();
    w.identity.revoke(&mut w.sink, &mut w.keys, cred(2)).unwrap();
    assert_eq!(w.verify(&sub_a, at(1)).unwrap_err(), IdentityError::Revoked(cred(2)));
    assert_eq!(w.verify(&child, at(1)).unwrap_err(), IdentityError::Revoked(cred(2)));
    assert!(w.verify(&sub_b, at(1)).is_ok(), "a sibling is unaffected");
    // A revoked parent cannot issue.
    assert_eq!(
        w.issue(cred(5), Some(cred(2)), sub_scope(12)).unwrap_err(),
        IdentityError::Revoked(cred(2))
    );
    assert!(
        w.identity.revoke(&mut w.sink, &mut w.keys, cred(2)).is_err(),
        "revoking twice is refused"
    );
}

#[test]
fn an_epoch_bump_revokes_descendants_but_not_the_credential() {
    let mut w = World::new();
    let master = w.issue(cred(1), None, master_scope()).unwrap();
    let old_sub = w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap();
    let old_child = w.issue(cred(3), Some(cred(2)), sub_scope(12)).unwrap();
    w.identity.bump_epoch(&mut w.sink, &mut w.keys, cred(1)).unwrap();
    assert!(w.verify(&master, at(1)).is_ok());
    assert!(
        w.verify(&old_sub, at(1)).is_err(),
        "descendant still verifies after epoch bump"
    );
    assert!(w.verify(&old_child, at(1)).is_err());
    let new_sub = w.issue(cred(4), Some(cred(1)), sub_scope(24)).unwrap();
    assert!(w.verify(&new_sub, at(1)).is_ok(), "issued under the new epoch");
}

#[test]
fn expiry_is_checked_up_the_chain() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    w.issue(cred(2), Some(cred(1)), sub_scope(10)).unwrap();
    let child = w.issue(cred(3), Some(cred(2)), sub_scope(5)).unwrap();
    assert!(w.verify(&child, at(4)).is_ok());
    assert_eq!(w.verify(&child, at(5)).unwrap_err(), IdentityError::Expired(cred(3)));
    let mut sub_scope_no_expiry = sub_scope(10);
    sub_scope_no_expiry.expires_at = None;
    assert!(
        w.issue(cred(4), Some(cred(1)), sub_scope_no_expiry).is_err(),
        "sub keys must expire"
    );
}

#[test]
fn malformed_and_unknown_credentials_are_refused_without_echo() {
    let mut w = World::new();
    let issued = w.issue(cred(1), None, master_scope()).unwrap();
    let err = w.identity.verify(&w.keys, "uaos_sk_not-a-key", at(1)).unwrap_err();
    assert_eq!(err.code(), codes::IDENTITY_MALFORMED);
    assert!(!err.to_string().contains("not-a-key"));
    // A well-formed key from another installation (other identity key) is unknown here.
    let other = World::new();
    let foreign_keys = IdentityKeys::open(Arc::new(SimKeychain::new()), &SimRng::new(99), "other").unwrap();
    let foreign = Identity::default().verify(&foreign_keys, &issued.text, at(1));
    assert_eq!(foreign.unwrap_err().code(), codes::IDENTITY_UNKNOWN);
    drop(other);
}

#[test]
fn the_secret_never_appears_in_records_entries_or_debug_output() {
    let mut w = World::new();
    let issued = w.issue(cred(1), None, master_scope()).unwrap();
    let text = issued.text.as_str().to_owned();
    let body = &text[uaos_identity::PREFIX.len()..];
    let journaled = serde_json::to_string(&w.sink.entries).unwrap();
    assert!(!journaled.contains(body), "the secret reached the journal entry");
    assert!(!format!("{issued:?}").contains(body));
    assert!(!format!("{:?}", w.keys).contains(body));
    assert!(!format!("{:?}", w.identity).contains(body));
}

#[test]
fn the_identity_key_persists_in_the_keychain() {
    let mut w = World::new();
    let issued = w.issue(cred(1), None, master_scope()).unwrap();
    let reopened = IdentityKeys::open(w.keychain.clone(), &SimRng::new(12345), INSTALLATION).unwrap();
    assert!(w.identity.verify(&reopened, &issued.text, at(1)).is_ok());
    // Losing the identity key invalidates every credential: fail closed.
    w.keychain.delete(&format!("{INSTALLATION}/identity/hmac")).unwrap();
    let fresh = IdentityKeys::open(w.keychain.clone(), &SimRng::new(5), INSTALLATION).unwrap();
    assert_eq!(
        w.identity.verify(&fresh, &issued.text, at(1)).unwrap_err(),
        IdentityError::Unknown
    );
}

#[test]
fn a_restored_data_directory_fails_closed_until_recovered() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    let sub = w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap();
    // Backup taken here (entries so far), then the sub key is revoked.
    let backup = w.sink.entries.clone();
    w.identity.revoke(&mut w.sink, &mut w.keys, cred(2)).unwrap();
    assert_eq!(w.keys.guard(), RevocationSeq(1));

    // Restore the old data directory: the journal no longer knows about the revocation.
    let mut restored = Identity::replay(&backup).unwrap();
    let err = restored.verify(&w.keys, &sub.text, at(1)).unwrap_err();
    assert_eq!(
        err.code(),
        codes::IDENTITY_STALE_DATA_DIR,
        "the revoked key must not resurrect"
    );

    let mut sink = MemorySink::default();
    let revoked = restored.recover_after_restore(&mut sink, &mut w.keys).unwrap();
    assert_eq!(revoked, 1);
    assert_eq!(
        restored.verify(&w.keys, &sub.text, at(1)).unwrap_err(),
        IdentityError::Revoked(cred(1))
    );
    assert!(restored.state().revocation_seq() >= w.keys.guard());

    // A new master issued after recovery works.
    let new_master = restored
        .issue(
            &mut sink,
            &w.keys,
            &w.rng,
            IssueRequest {
                id: cred(9),
                parent: None,
                label: None,
                scope: master_scope(),
            },
            at(2),
        )
        .unwrap();
    assert!(restored.verify(&w.keys, &new_master.text, at(3)).is_ok());
}

#[test]
fn a_recording_failure_poisons_until_replayed() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    w.sink.fail_next = Some("disk full".to_owned());
    let err = w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap_err();
    assert_eq!(err.code(), codes::IDENTITY_UNAVAILABLE);
    assert!(w.identity.is_poisoned());
    assert!(w.issue(cred(3), Some(cred(1)), sub_scope(24)).is_err());
    let rebuilt = Identity::replay(&w.sink.entries).unwrap();
    assert!(!rebuilt.is_poisoned());
    assert!(rebuilt.state().node(cred(1)).is_some());
    assert!(
        rebuilt.state().node(cred(2)).is_none(),
        "the failed entry was not recorded"
    );
}

#[test]
fn an_oversized_record_is_refused_without_poisoning() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    let long = |p: &str, i: usize| format!("{p}{i:0>60}");
    let mut scope = sub_scope(24);
    scope.resources = ScopeSet::Only(
        (0..limits::MAX_SCOPE_ITEMS)
            .map(|i| ResourcePattern {
                kind: ResourceKind::Tool,
                matching: PatternMatch::Exact,
                value: PatternValue::new(long("t", i)).unwrap(),
            })
            .collect(),
    );
    scope.actions = ScopeSet::Only((0..limits::MAX_SCOPE_ITEMS).map(|i| action(&long("a", i))).collect());
    let err = w.issue(cred(2), Some(cred(1)), scope).unwrap_err();
    assert_eq!(err.code(), codes::IDENTITY_RECORD_TOO_LARGE);
    assert!(!w.identity.is_poisoned());
}

// ---------------------------------------------------------------------------------------------
// Random derivation trees
// ---------------------------------------------------------------------------------------------

fn arb_scope() -> impl Strategy<Value = Scope> {
    let actions = prop_oneof![
        Just(ScopeSet::Any),
        proptest::sample::subsequence(vec!["model.call", "model.count_tokens", "tool.call"], 0..=3)
            .prop_map(|v| ScopeSet::Only(v.into_iter().map(action).collect())),
    ];
    let resources = prop_oneof![
        Just(ScopeSet::Any),
        proptest::collection::btree_set(
            (
                prop_oneof![Just(PatternMatch::Exact), Just(PatternMatch::Prefix)],
                "[ab]{1,3}"
            )
                .prop_map(|(m, v)| {
                    ResourcePattern {
                        kind: ResourceKind::Model,
                        matching: m,
                        value: PatternValue::new(v).unwrap(),
                    }
                }),
            0..3,
        )
        .prop_map(ScopeSet::Only),
    ];
    let pockets = prop_oneof![
        Just(ScopeSet::Any),
        proptest::collection::btree_set(1u8..4, 0..3).prop_map(|s| ScopeSet::Only(s.into_iter().map(pocket).collect())),
    ];
    (actions, resources, pockets, 1i128..48).prop_map(|(actions, resources, pockets, hours)| Scope {
        actions,
        resources,
        pockets,
        pools: ScopeSet::Any,
        expires_at: Some(at(hours)),
    })
}

/// Property cases: 256 per merge; the nightly lane raises it with `UAOS_IDENTITY_CASES`.
#[allow(clippy::disallowed_methods, reason = "test configuration knob, read once")]
fn cases() -> u32 {
    std::env::var("UAOS_IDENTITY_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// No sequence of issuance requests produces a verifiable credential that escapes any
    /// ancestor, and issuance accepts exactly the requests that are within the parent.
    #[test]
    fn no_derivation_escapes_its_ancestors(
        requests in proptest::collection::vec((0usize..8, arb_scope()), 1..12),
        bumps in proptest::collection::vec(0usize..8, 0..3),
    ) {
        let mut w = World::new();
        w.issue(cred(0), None, master_scope()).unwrap();
        let mut issued = vec![(cred(0), None::<CredentialId>, master_scope(), Some(w.identity.state().node(cred(0)).unwrap().clone()))];
        let mut texts = vec![None];
        for (i, (parent_pick, scope)) in requests.into_iter().enumerate() {
            let parent = issued[parent_pick % issued.len()].0;
            let id = cred(u8::try_from(i + 1).unwrap());
            let parent_scope = w.identity.state().node(parent).unwrap().record.scope.clone();
            let within = scope_within(&scope, &parent_scope);
            match w.issue(id, Some(parent), scope.clone()) {
                Ok(done) => {
                    prop_assert!(within, "issuance accepted a scope outside its parent");
                    issued.push((id, Some(parent), scope, None));
                    texts.push(Some(done));
                }
                Err(IdentityError::ScopeExceedsParent(_)) => prop_assert!(!within),
                Err(IdentityError::DepthExceeded { .. }) => {}
                Err(other) => prop_assert!(false, "unexpected refusal: {other}"),
            }
        }
        for b in bumps {
            let target = issued[b % issued.len()].0;
            w.identity.bump_epoch(&mut w.sink, &mut w.keys, target).unwrap();
        }
        // Every credential that still verifies is within each ancestor, and a replay of the
        // recorded entries reaches the same state.
        for (n, text) in texts.iter().enumerate() {
            let Some(text) = text else { continue };
            if let Ok(v) = w.verify(text, at(0)) {
                for pair in v.chain.windows(2) {
                    let child = &w.identity.state().node(pair[0]).unwrap().record.scope;
                    let parent = &w.identity.state().node(pair[1]).unwrap().record.scope;
                    prop_assert!(scope_within(child, parent), "credential #{n} escapes an ancestor");
                }
            }
        }
        let replayed = Identity::replay(&w.sink.entries).unwrap();
        prop_assert_eq!(replayed.state(), w.identity.state());
    }
}

// ---------------------------------------------------------------------------------------------
// Journal round trip
// ---------------------------------------------------------------------------------------------

#[test]
fn journal_entries_survive_a_crash_and_replay_to_the_live_state() {
    let fs = SimFs::new();
    fs.create_dir_all(Path::new("/data")).unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SimClock::new(at(0)));
    let rng: Arc<dyn Rng> = Arc::new(SimRng::new(7));
    let open = || {
        Journal::open(
            Arc::new(fs.clone()),
            clock.clone(),
            rng.clone(),
            Path::new("/data"),
            FlushPolicy::Balanced { window: Millis(60_000) },
        )
        .unwrap()
    };
    let mut w = World::new();
    let mut journal = open();
    let live = {
        let mut sink = JournalSink::new(
            &mut journal,
            CorrelationId::from_parts(1, [3; 10]),
            Actor::System,
            ConfigVersion(1),
        );
        let keys = &mut w.keys;
        let id = &mut w.identity;
        id.issue(
            &mut sink,
            keys,
            &w.rng,
            IssueRequest {
                id: cred(1),
                parent: None,
                label: None,
                scope: master_scope(),
            },
            at(0),
        )
        .unwrap();
        id.issue(
            &mut sink,
            keys,
            &w.rng,
            IssueRequest {
                id: cred(2),
                parent: Some(cred(1)),
                label: None,
                scope: sub_scope(24),
            },
            at(0),
        )
        .unwrap();
        id.revoke(&mut sink, keys, cred(2)).unwrap();
        id.state().clone()
    };
    fs.crash();
    drop(journal);
    let _reopened = open();
    let (records, _) = read_verified(&fs, &Path::new("/data").join(JOURNAL_DIR)).unwrap();
    let entries = entries_from_journal(&records).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(
        Identity::replay(&entries).unwrap().state(),
        &live,
        "every critical entry survived"
    );
}
