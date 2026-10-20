// SPDX-License-Identifier: Apache-2.0

//! The module socket's rules (`docs/adr/appendix/0010-module-socket.md` §3 to §7), one test per
//! rule: a manifest is refused whole, admission compares features as a set, state is bounded and
//! all-or-nothing, a cursor only moves forward, declarations are checked against the manifest
//! and the point, selectors resolve to tape ids in document order, and nothing a `Debug` prints
//! carries content.

#![allow(
    clippy::unwrap_used,
    reason = "test harness: a helper's failure fails the test that called it"
)]

use std::collections::BTreeSet;

use uaos_contracts::event::ModuleName;
use uaos_contracts::id::{OperationId, PocketId, TypedId};
use uaos_contracts::operation::{OperationKind, RiskTier};
use uaos_contracts::wire::Seq;
use uaos_json::{Limits, NodeId, parse};
use uaos_module_api::{
    ChildBody, ChildKind, ChildOpRequest, Code, ConfigSchema, Decl, DeclError, Decls, EventClass, EventDecl, EventView,
    GrantDecl, HookCx, HookDecl, HookMode, HookPoint, KernelFeature, KernelOffer, MAX_DECLS, MAX_MODULE_TEXT,
    MAX_STATE_BYTES, Manifest, ManifestBuilder, ManifestError, Module, ModuleApiVersion, ModuleEvent, ModuleState,
    ModuleText, ModuleVersion, OpMeta, PathPattern, PocketCursor, Predicate, Refusal, Role, RoleMap, Selector,
    SelectorError, Step, Strike, StructuralView, TextError, ViewText, check_decls,
};

const V1: ModuleVersion = ModuleVersion {
    major: 1,
    minor: 0,
    patch: 0,
};

fn code(s: &str) -> Code {
    Code::new(s).unwrap()
}

fn builder() -> ManifestBuilder {
    Manifest::builder(ModuleName::new("mod-notes").unwrap(), V1)
}

fn pocket(n: u8) -> PocketId {
    PocketId::from_parts(u64::from(n), [n; 10])
}

fn set<T: Ord>(items: impl IntoIterator<Item = T>) -> BTreeSet<T> {
    items.into_iter().collect()
}

#[test]
fn a_manifest_is_refused_whole_for_each_reason() {
    use HookPoint as P;
    let many = (0..=64).fold(builder(), |b, i| b.reason(code(&format!("r{i}"))));
    let noted = || EventDecl {
        code: code("noted"),
        class: EventClass::Ephemeral,
    };
    let cases: Vec<(ManifestBuilder, ManifestError)> = vec![
        (
            builder()
                .hook(HookDecl::new(P::Classify, HookMode::Observe))
                .hook(HookDecl::new(P::Classify, HookMode::Act)),
            ManifestError::DuplicateHook(P::Classify),
        ),
        (
            builder().hook(HookDecl::new(P::Classify, HookMode::Act).deadline_us(0)),
            ManifestError::Deadline {
                point: P::Classify,
                ceiling_us: 200,
            },
        ),
        (
            builder().hook(HookDecl::new(P::Classify, HookMode::Act).deadline_us(201)),
            ManifestError::Deadline {
                point: P::Classify,
                ceiling_us: 200,
            },
        ),
        (
            builder().hook(HookDecl::new(P::StreamObserve, HookMode::Observe)),
            ManifestError::FeatureNotRequired(KernelFeature::StreamObserve),
        ),
        (
            builder()
                .requires(KernelFeature::ChildOperations)
                .action(ChildKind::MemoryRead),
            ManifestError::FeatureNotRequired(KernelFeature::CrossPocketRead),
        ),
        (
            builder().grant(GrantDecl {
                kind: ChildKind::ModelCall,
                why: code("rewrite"),
            }),
            ManifestError::GrantWithoutAction,
        ),
        (
            builder().state_bytes(MAX_STATE_BYTES + 1),
            ManifestError::StateTooLarge { max: MAX_STATE_BYTES },
        ),
        (builder().max_decls(0), ManifestError::Decls { max: MAX_DECLS }),
        (
            builder().max_decls(MAX_DECLS + 1),
            ManifestError::Decls { max: MAX_DECLS },
        ),
        (many, ManifestError::TooManyCodes { max: 64 }),
        (
            builder().event(noted()).event(noted()),
            ManifestError::DuplicateEvent(code("noted")),
        ),
        (
            builder()
                .requires(KernelFeature::ChildOperations)
                .action(ChildKind::ModelCall)
                .default_enabled(true),
            ManifestError::DefaultOnReachesOutside,
        ),
    ];
    for (b, expected) in cases {
        assert_eq!(b.build(), Err(expected));
    }
}

#[test]
fn the_bounds_themselves_are_accepted() {
    let m = builder()
        .hook(HookDecl::new(HookPoint::ResponsePost, HookMode::Observe).deadline_us(5_000))
        .state_bytes(MAX_STATE_BYTES)
        .max_decls(MAX_DECLS)
        .build()
        .unwrap();
    assert_eq!(m.state_bytes(), MAX_STATE_BYTES);
    assert!(!m.default_enabled(), "a manifest is off by default");
    assert_eq!(
        ModuleState::new(u32::MAX).limit(),
        MAX_STATE_BYTES,
        "the state bound is clamped"
    );
}

#[test]
fn a_config_schema_is_one_bounded_json_object() {
    assert!(ConfigSchema::new(r#"{"type":"object"}"#).is_ok());
    for bad in ["[]", "\"x\"", "{", "{} {}"] {
        assert_eq!(ConfigSchema::new(bad), Err(ManifestError::ConfigSchema), "{bad}");
    }
    let big = format!(r#"{{"k":"{}"}}"#, "x".repeat(16 * 1024));
    assert_eq!(ConfigSchema::new(big), Err(ManifestError::ConfigSchema));
}

#[test]
fn admission_compares_every_required_feature() {
    let m = builder()
        .requires(KernelFeature::StreamAssert)
        .hook(HookDecl::new(HookPoint::StreamAssert, HookMode::Act))
        .build()
        .unwrap();
    let full = KernelOffer::new(ModuleApiVersion::CURRENT, set(KernelFeature::ALL));
    assert_eq!(full.admit(&m), Ok(()));

    let degraded = KernelOffer::new(ModuleApiVersion::CURRENT, set([KernelFeature::StreamObserve]));
    assert_eq!(
        degraded.admit(&m),
        Err(Refusal::FeatureMissing(KernelFeature::StreamAssert))
    );

    let modules_off = KernelOffer::new(ModuleApiVersion::CURRENT, BTreeSet::new());
    assert_eq!(
        modules_off.admit(&builder().build().unwrap()),
        Ok(()),
        "a module that requires nothing"
    );
    assert!(modules_off.admit(&m).is_err());
}

#[test]
fn admission_refuses_another_major() {
    let m = builder().build().unwrap();
    for major in [0, 2] {
        let offer = KernelOffer::new(ModuleApiVersion::new(major, 9), set(KernelFeature::ALL));
        let refusal = offer.admit(&m).unwrap_err();
        assert_eq!(refusal.code(), "api_major");
    }
    let newer_kernel = KernelOffer::new(ModuleApiVersion::new(1, 3), set(KernelFeature::ALL));
    assert_eq!(
        newer_kernel.admit(&m),
        Ok(()),
        "a newer minor kernel admits an older module"
    );
}

#[test]
fn state_is_bounded_and_unchanged_on_refusal() {
    let mut state = ModuleState::new(8);
    state.replace(b"abcd").unwrap();
    assert_eq!(state.append(b"efghi").unwrap_err().wanted, 9);
    assert_eq!(state.as_bytes(), b"abcd");
    assert!(state.replace(b"123456789").is_err());
    assert_eq!(state.as_bytes(), b"abcd");
    state.append(b"efgh").unwrap();
    assert_eq!(state.as_bytes(), b"abcdefgh");
    assert!(
        ModuleState::restore(8, vec![0; 9]).is_err(),
        "a checkpoint never restores past the bound"
    );
    assert_eq!(ModuleState::restore(8, b"abcdefgh".to_vec()).unwrap(), state);
}

#[test]
fn a_cursor_only_moves_forward() {
    let mut cursor = PocketCursor::start(pocket(1));
    assert!(cursor.is_after(Seq(0)));
    cursor.advance(Seq(5)).unwrap();
    assert!(cursor.advance(Seq(5)).is_err(), "an event is delivered once");
    assert!(cursor.advance(Seq(3)).is_err(), "events arrive in journal order");
    cursor.advance(Seq(6)).unwrap();
    assert_eq!(cursor.through(), Some(Seq(6)));
    assert_eq!(cursor.pocket(), pocket(1));
}

fn acting_manifest() -> Manifest {
    builder()
        .hook(HookDecl::new(HookPoint::ToolResult, HookMode::Act))
        .hook(HookDecl::new(HookPoint::Classify, HookMode::Observe))
        .reason(code("secret_found"))
        .label(code("risky"))
        .event(EventDecl {
            code: code("noted"),
            class: EventClass::Journaled,
        })
        .max_decls(2)
        .build()
        .unwrap()
}

#[test]
fn declarations_are_checked_against_the_manifest_and_the_point() {
    use HookPoint as P;
    let m = acting_manifest();
    let veto = Decl::Veto(code("secret_found"));
    let emit = Decl::Emit(ModuleEvent::new(code("noted")));
    let ok: [(Option<P>, &[Decl]); 3] = [
        (Some(P::ToolResult), std::slice::from_ref(&veto)),
        (Some(P::Classify), std::slice::from_ref(&emit)),
        (None, std::slice::from_ref(&emit)),
    ];
    for (point, decls) in ok {
        assert_eq!(check_decls(&m, point, decls), Ok(()), "{point:?}");
    }
    let request = Decl::Request(
        ChildOpRequest::new(
            ChildKind::ModelCall,
            ChildBody::Prompt(ModuleText::new("x").unwrap()),
            code("c1"),
        )
        .unwrap(),
    );
    let strikes: [(Option<P>, Vec<Decl>, Strike); 8] = [
        (
            Some(P::ToolResult),
            vec![Decl::Veto(code("other"))],
            Strike::UndeclaredCode,
        ),
        (
            Some(P::Classify),
            vec![Decl::Label(code("risky"))],
            Strike::NotAllowedHere,
        ),
        (
            Some(P::ContextAssemble),
            vec![Decl::Strip(sel(vec![Step::Each]))],
            Strike::NotAllowedHere,
        ),
        (None, vec![veto.clone()], Strike::NotAllowedHere),
        (
            Some(P::ToolResult),
            vec![Decl::Emit(ModuleEvent::new(code("unseen")))],
            Strike::UndeclaredCode,
        ),
        (
            Some(P::ToolResult),
            vec![emit.clone(), emit.clone(), emit],
            Strike::TooMany,
        ),
        (Some(P::ToolResult), vec![request], Strike::UndeclaredAction),
        (Some(P::ToolResult), vec![Decl::Checkpoint], Strike::NotAllowedHere),
    ];
    for (point, decls, strike) in strikes {
        assert_eq!(check_decls(&m, point, &decls), Err(strike), "{point:?}");
    }
}

#[test]
fn a_checkpoint_needs_its_feature() {
    let m = builder()
        .hook(HookDecl::new(HookPoint::ResponsePost, HookMode::Observe))
        .build()
        .unwrap();
    assert_eq!(
        check_decls(&m, Some(HookPoint::ResponsePost), &[Decl::Checkpoint]),
        Err(Strike::FeatureNotRequired(KernelFeature::StateCheckpoints))
    );
    let m = builder()
        .requires(KernelFeature::StateCheckpoints)
        .hook(HookDecl::new(HookPoint::ResponsePost, HookMode::Observe))
        .build()
        .unwrap();
    assert_eq!(
        check_decls(&m, Some(HookPoint::ResponsePost), &[Decl::Checkpoint]),
        Ok(())
    );
}

#[test]
fn the_collector_stops_at_its_bound() {
    let mut out = Decls::new(1);
    out.push(Decl::Checkpoint).unwrap();
    assert_eq!(out.push(Decl::Checkpoint), Err(DeclError { max: 1 }));
    assert_eq!(out.as_slice().len(), 1);
    assert_eq!(format!("{out:?}"), "Decls { len: 1, max: 1 }");
}

#[test]
fn a_child_body_must_fit_its_kind() {
    let prompt = || ChildBody::Prompt(ModuleText::new("hello").unwrap());
    assert!(ChildOpRequest::new(ChildKind::CountTokens, prompt(), code("c1")).is_ok());
    assert_eq!(
        ChildOpRequest::new(ChildKind::MemoryRead, prompt(), code("c1")),
        Err(prompt())
    );
    assert_eq!(ChildKind::MemoryRead.cedar_action(), "memory.read");
    assert!(
        ChildKind::MemoryRead
            .required_features()
            .contains(&KernelFeature::CrossPocketRead)
    );
}

#[test]
fn codes_paths_and_text_have_their_shapes() {
    for good in ["ab", "a_1", "secret_found"] {
        assert!(Code::new(good).is_ok(), "{good}");
    }
    for bad in ["", "a", "A1", "1a", "ab-c", "ab c", &"a".repeat(33)] {
        assert!(Code::new(bad).is_err(), "{bad}");
    }
    let exact = PathPattern::new("/v1/messages").unwrap();
    assert!(exact.matches("/v1/messages") && !exact.matches("/v1/messages/count_tokens"));
    let prefix = PathPattern::new("/v1/*").unwrap();
    assert!(prefix.matches("/v1/messages") && !prefix.matches("/v2/x"));
    for bad in [
        "v1",
        "/v1?x",
        "/v1#x",
        "/a*b",
        "/a**",
        "/a b",
        &format!("/{}", "a".repeat(128)),
    ] {
        assert!(PathPattern::new(bad).is_err(), "{bad}");
    }
    assert!(ModuleText::new("a\n\tb").is_ok());
    assert_eq!(ModuleText::new("bell\u{7}"), Err(TextError::Control));
    assert_eq!(
        ModuleText::new("x".repeat(MAX_MODULE_TEXT + 1)),
        Err(TextError::TooLong)
    );
    assert!(ModuleText::new("x".repeat(MAX_MODULE_TEXT)).is_ok());
}

const DOC: &str = r#"{"system":[{"type":"text","text":"s0"}],"messages":[
{"role":"user","content":"hi"},
{"role":"assistant","content":[{"type":"thinking","thinking":"t","signature":"sig"},{"type":"text","text":"a"}]},
{"role":"user","content":[{"type":"tool_result","content":"r"},{"type":"text","text":"q"}]}]}"#;

fn sel(steps: Vec<Step>) -> Selector {
    Selector::new(steps).unwrap()
}

fn messages() -> Vec<Step> {
    vec![Step::Key("messages".into()), Step::Each]
}

fn role_in(values: &[&str]) -> Predicate {
    Predicate::MemberIn {
        key: "role".into(),
        values: values.iter().map(|v| (*v).to_owned()).collect(),
    }
}

fn texts(view: &StructuralView<'_, '_>, ids: &[NodeId]) -> Vec<String> {
    ids.iter()
        .map(|id| match view.node(*id).unwrap().text().unwrap() {
            Some(ViewText::Plain(t)) => t.into_owned(),
            Some(ViewText::Masked) => "<masked>".to_owned(),
            None => "<not a string>".to_owned(),
        })
        .collect()
}

#[test]
fn selectors_resolve_in_document_order() {
    let tape = parse(DOC.as_bytes(), &Limits::DEFAULT).unwrap();
    let none = BTreeSet::new();
    let view = StructuralView::new(&tape, &none);
    assert_eq!(sel(messages()).resolve(&view).unwrap().len(), 3);

    let mut users = messages();
    users.push(Step::Where(role_in(&["user"])));
    assert_eq!(sel(users.clone()).resolve(&view).unwrap().len(), 2);
    users.extend([
        Step::Last,
        Step::Key("content".into()),
        Step::Each,
        Step::Key("type".into()),
    ]);
    assert_eq!(
        texts(&view, &sel(users).resolve(&view).unwrap()),
        ["tool_result", "text"]
    );

    let mut others = messages();
    others.push(Step::Where(Predicate::MemberNotIn {
        key: "role".into(),
        values: set(["user".to_owned()]),
    }));
    others.push(Step::Key("role".into()));
    assert_eq!(texts(&view, &sel(others).resolve(&view).unwrap()), ["assistant"]);

    let signatures = sel(vec![Step::AnyDepthKey("signature".into())]).resolve(&view).unwrap();
    assert_eq!(texts(&view, &signatures), ["sig"]);

    let mut with_tool_result = messages();
    with_tool_result.push(Step::Where(Predicate::StringOrArrayWith {
        key: "content".into(),
        element: Box::new(Predicate::MemberIn {
            key: "type".into(),
            values: set(["tool_result".to_owned()]),
        }),
    }));
    with_tool_result.push(Step::Key("role".into()));
    assert_eq!(
        texts(&view, &sel(with_tool_result).resolve(&view).unwrap()),
        ["user", "user"]
    );
}

#[test]
fn a_selector_is_bounded() {
    assert_eq!(Selector::new(vec![Step::Each; 17]), Err(SelectorError::TooLong));
    assert_eq!(Selector::new(vec![Step::Key(String::new())]), Err(SelectorError::Key));
    assert_eq!(
        Selector::new(vec![Step::AnyDepthKey("k".repeat(65))]),
        Err(SelectorError::Key)
    );
    let deep = (0..4).fold(role_in(&["user"]), |inner, _| Predicate::StringOrArrayWith {
        key: "content".into(),
        element: Box::new(inner),
    });
    assert_eq!(Selector::new(vec![Step::Where(deep)]), Err(SelectorError::TooDeep));
}

#[test]
fn a_masked_value_cannot_be_probed() {
    let tape = parse(DOC.as_bytes(), &Limits::DEFAULT).unwrap();
    let none = BTreeSet::new();
    let plain = StructuralView::new(&tape, &none);
    let mut first = messages();
    first.push(Step::Key("content".into()));
    let hi = sel(first).resolve(&plain).unwrap()[0];

    let masked = set([hi]);
    let view = StructuralView::new(&tape, &masked);
    assert_eq!(view.node(hi).unwrap().text().unwrap(), Some(ViewText::Masked));
    let mut probe = messages();
    probe.push(Step::Where(Predicate::MemberIn {
        key: "content".into(),
        values: set(["hi".to_owned()]),
    }));
    assert_eq!(sel(probe.clone()).resolve(&plain).unwrap().len(), 1);
    assert!(
        sel(probe).resolve(&view).unwrap().is_empty(),
        "MemberIn never matches a masked value"
    );
}

#[test]
fn roles_govern_their_subtree() {
    let tape = parse(DOC.as_bytes(), &Limits::DEFAULT).unwrap();
    let none = BTreeSet::new();
    let view = StructuralView::new(&tape, &none);
    let mut thinking = messages();
    thinking.extend([
        Step::Key("content".into()),
        Step::Each,
        Step::Where(Predicate::MemberIn {
            key: "type".into(),
            values: set(["thinking".to_owned()]),
        }),
    ]);
    let mut roles = RoleMap::new();
    assert_eq!(roles.assign(&view, &sel(thinking), Role::Signed).unwrap(), 1);
    let signature = sel(vec![Step::AnyDepthKey("signature".into())]).resolve(&view).unwrap()[0];
    assert!(roles.roles_of(signature).is_empty());
    assert!(roles.governing(&view, signature).contains(&Role::Signed));
    let system = sel(vec![Step::AnyDepthKey("text".into())]).resolve(&view).unwrap()[0];
    assert!(roles.governing(&view, system).is_empty());
}

#[test]
fn debug_output_carries_no_content() {
    let tape = parse(DOC.as_bytes(), &Limits::DEFAULT).unwrap();
    let none = BTreeSet::new();
    let view = StructuralView::new(&tape, &none);
    let mut state = ModuleState::new(64);
    state.replace(b"secret-state").unwrap();
    let shown = [
        format!("{view:?}"),
        format!("{:?}", view.root()),
        format!("{:?}", ViewText::Plain("secret-text".into())),
        format!("{:?}", ModuleText::new("secret-text").unwrap()),
        format!("{state:?}"),
        format!("{:?}", ConfigSchema::new(r#"{"secret":1}"#).unwrap()),
    ];
    for text in shown {
        assert!(
            !text.contains("secret") && !text.contains("sig") && !text.contains("\"hi\""),
            "{text}"
        );
    }
}

/// A paper module: observes classification and remembers how many requests it saw per pocket.
struct Counter(Manifest);

impl Module for Counter {
    fn manifest(&self) -> &Manifest {
        &self.0
    }

    fn on_hook(&self, cx: &HookCx<'_>, state: &mut ModuleState, out: &mut Decls) {
        let seen = state.as_bytes().len();
        if state.append(&[1]).is_ok() && seen % 2 == 1 && cx.view().is_none() {
            out.push(Decl::Emit(ModuleEvent::new(code("noted")))).unwrap();
        }
    }
}

#[test]
fn a_module_runs_behind_the_trait_object() {
    let manifest = builder()
        .hook(HookDecl::new(HookPoint::Classify, HookMode::Observe))
        .event(EventDecl {
            code: code("noted"),
            class: EventClass::Ephemeral,
        })
        .state_bytes(4)
        .build()
        .unwrap();
    let module: Box<dyn Module> = Box::new(Counter(manifest));
    let op = OpMeta {
        operation: OperationId::from_parts(1, [1; 10]),
        kind: OperationKind::ModelCall,
        pocket: pocket(1),
        risk_tier: RiskTier::new(1).unwrap(),
        agent: None,
    };
    let cx = HookCx::new(HookPoint::Classify, op);
    let mut state = ModuleState::new(module.manifest().state_bytes());
    let mut emitted = 0;
    for _ in 0..6 {
        let mut out = Decls::new(module.manifest().max_decls());
        module.on_hook(&cx, &mut state, &mut out);
        assert_eq!(
            check_decls(module.manifest(), Some(HookPoint::Classify), out.as_slice()),
            Ok(())
        );
        emitted += out.as_slice().len();
    }
    assert_eq!(state.as_bytes().len(), 4, "the state stopped at its bound");
    assert_eq!(emitted, 2);

    let mut out = Decls::new(8);
    let event = EventView {
        pocket: pocket(1),
        seq: Seq(1),
        event_type: &uaos_contracts::event::EventType::new("op.created").unwrap(),
        operation: None,
    };
    module.on_event(&event, &mut state, &mut out);
    assert!(out.is_empty(), "the default on_event declares nothing");
}
