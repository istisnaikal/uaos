// SPDX-License-Identifier: Apache-2.0

//! The redacted view, selectors, roles and endpoint paths (contract §2 rule 5, §7; ADR-0014):
//! a mask covers values and keys, a predicate's answer never depends on masked text, selectors
//! resolve to tape ids in document order and are bounded, roles govern their subtree and fail
//! closed outside the view, path patterns match canonical paths by segment, and nothing a `Debug`
//! prints carries content. The tests named in `xtask` seeded violations carry the words their
//! negative expects in their failure message.

#![allow(
    clippy::unwrap_used,
    reason = "test harness: a helper's failure fails the test that called it"
)]

use std::collections::BTreeSet;

use proptest::prelude::*;
use uaos_json::{Kind, Limits, NodeId, parse};
use uaos_module_api::{
    ConfigSchema, MAX_PREDICATE_VALUES, MAX_SELECTOR_TEXT, Mask, ModuleState, ModuleText, PathPattern, Predicate, Role,
    RoleMap, Selector, SelectorError, SseEvent, Step, StructuralView, ViewText,
};

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

fn strings(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}

fn member_in(key: &str, values: &[&str]) -> Predicate {
    Predicate::MemberIn {
        key: key.into(),
        values: strings(values),
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
    let mask = Mask::new();
    let view = StructuralView::new(&tape, &mask);
    assert_eq!(sel(messages()).resolve(&view).unwrap().len(), 3);

    let mut users = messages();
    users.push(Step::Where(member_in("role", &["user"])));
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
        values: strings(&["user"]),
    }));
    others.push(Step::Key("role".into()));
    assert_eq!(texts(&view, &sel(others).resolve(&view).unwrap()), ["assistant"]);

    let signatures = sel(vec![Step::AnyDepthKey("signature".into())]).resolve(&view).unwrap();
    assert_eq!(texts(&view, &signatures), ["sig"]);

    let mut with_tool_result = messages();
    with_tool_result.push(Step::Where(Predicate::StringOrArrayWith {
        key: "content".into(),
        element: Box::new(member_in("type", &["tool_result"])),
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
    let long = "k".repeat(MAX_SELECTOR_TEXT + 1);
    assert_eq!(
        Selector::new(vec![Step::AnyDepthKey(long.clone())]),
        Err(SelectorError::Key)
    );
    let deep = (0..4).fold(member_in("role", &["user"]), |inner, _| Predicate::StringOrArrayWith {
        key: "content".into(),
        element: Box::new(inner),
    });
    assert_eq!(Selector::new(vec![Step::Where(deep)]), Err(SelectorError::TooDeep));
    let many: Vec<String> = (0..=MAX_PREDICATE_VALUES).map(|i| format!("v{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(
        Selector::new(vec![Step::Where(member_in("type", &many))]),
        Err(SelectorError::TooManyValues),
        "an unbounded predicate was accepted"
    );
    assert_eq!(
        Selector::new(vec![Step::Where(member_in("type", &[long.as_str()]))]),
        Err(SelectorError::Key)
    );
    let nested = Predicate::StringOrArrayWith {
        key: "content".into(),
        element: Box::new(member_in("type", &many)),
    };
    assert_eq!(
        Selector::new(vec![Step::Where(nested)]),
        Err(SelectorError::TooManyValues)
    );
}

/// `{"messages":[{"role":"user","content":<content>}]}` with its content string masked.
fn masked_message(content: &str) -> (bool, bool, bool) {
    let body = format!(r#"{{"messages":[{{"role":"user","content":"{content}"}}]}}"#);
    let tape = parse(body.as_bytes(), &Limits::DEFAULT).unwrap();
    let plain = Mask::new();
    let mut content_path = messages();
    content_path.push(Step::Key("content".into()));
    let id = sel(content_path).resolve(&StructuralView::new(&tape, &plain)).unwrap()[0];
    let mut mask = Mask::new();
    mask.value(id);
    let view = StructuralView::new(&tape, &mask);
    let count = |p: Predicate| {
        let mut steps = messages();
        steps.push(Step::Where(p));
        sel(steps).resolve(&view).unwrap().len()
    };
    let is_in = count(member_in("content", &["hi", "secret"]));
    let not_in = count(Predicate::MemberNotIn {
        key: "content".into(),
        values: strings(&["hi", "secret"]),
    });
    let string = count(Predicate::StringOrArrayWith {
        key: "content".into(),
        element: Box::new(member_in("type", &["x1"])),
    });
    (is_in == 1, not_in == 1, string == 1)
}

#[test]
fn a_masked_value_cannot_be_probed() {
    // Whatever the masked text is, every predicate answers the same: it is unknown, never equal.
    let answers = [masked_message("hi"), masked_message("secret"), masked_message("other")];
    assert!(
        answers.iter().all(|a| *a == answers[0]),
        "a predicate's answer depended on masked text"
    );
    assert_eq!(answers[0], (false, true, true));
}

#[test]
fn masked_keys_and_numbers_read_as_masked() {
    let body = br#"{"ghp_secretkey":{"a":1},"n":12345,"k":"v"}"#;
    let tape = parse(body, &Limits::DEFAULT).unwrap();
    let plain = Mask::new();
    let open = StructuralView::new(&tape, &plain);
    let root = open.root();
    let secret = root.member("ghp_secretkey").unwrap().unwrap();
    let number = root.member("n").unwrap().unwrap();
    let mut mask = Mask::new();
    mask.key(secret.id());
    mask.value(number.id());
    let view = StructuralView::new(&tape, &mask);
    let node = view.node(secret.id()).unwrap();
    assert_eq!(node.key().unwrap(), Some(ViewText::Masked), "a masked key was readable");
    assert!(!node.key_is("ghp_secretkey").unwrap(), "a masked key matched its name");
    assert!(
        view.root().member("ghp_secretkey").unwrap().is_none(),
        "a masked key was found by name"
    );
    let any_depth = sel(vec![Step::AnyDepthKey("ghp_secretkey".into())])
        .resolve(&view)
        .unwrap();
    assert!(any_depth.is_empty(), "a masked key was found at any depth");
    assert_eq!(view.node(number.id()).unwrap().number_text(), Some(ViewText::Masked));
    assert_eq!(
        view.root().member("k").unwrap().unwrap().key().unwrap(),
        Some(ViewText::Plain("k".into()))
    );
    let first = view.root().children().next().unwrap();
    assert_eq!(first.kind(), Kind::Object, "structure stays visible");
}

#[test]
fn roles_govern_their_subtree_and_fail_closed_outside_the_view() {
    let tape = parse(DOC.as_bytes(), &Limits::DEFAULT).unwrap();
    let mask = Mask::new();
    let view = StructuralView::new(&tape, &mask);
    let mut thinking = messages();
    thinking.extend([
        Step::Key("content".into()),
        Step::Each,
        Step::Where(member_in("type", &["thinking"])),
    ]);
    let mut roles = RoleMap::new();
    assert_eq!(roles.assign(&view, &sel(thinking), Role::Signed).unwrap(), 1);
    let signature = sel(vec![Step::AnyDepthKey("signature".into())]).resolve(&view).unwrap()[0];
    assert!(roles.roles_of(signature).is_empty());
    assert!(roles.governing(&view, signature).unwrap().contains(&Role::Signed));
    let system = sel(vec![Step::AnyDepthKey("text".into())]).resolve(&view).unwrap()[0];
    assert_eq!(roles.governing(&view, system), Some(BTreeSet::new()));

    let small = parse(b"[1]", &Limits::DEFAULT).unwrap();
    let small_view = StructuralView::new(&small, &mask);
    assert!(small_view.node(signature).is_none());
    assert_eq!(
        roles.governing(&small_view, signature),
        None,
        "a node outside the view got roles"
    );
}

#[test]
fn path_patterns_match_canonical_paths_by_segment() {
    let exact = PathPattern::new("/v1/messages").unwrap();
    assert!(exact.matches("/v1/messages") && !exact.matches("/v1/messages/count_tokens"));
    let models = PathPattern::new("/v1/models*").unwrap();
    for (path, expected) in [
        ("/v1/models", true),
        ("/v1/models/claude", true),
        ("/v1/models-x", false),
        ("/v1/models/../messages", false),
        ("/v1/models/%2e%2e/messages", false),
        ("/v1/models//x", false),
        ("/v1/models/.", false),
        ("/v1\\models", false),
    ] {
        assert_eq!(
            models.matches(path),
            expected,
            "path {path} matched a pattern it should not"
        );
    }
    let prefix = PathPattern::new("/v1/*").unwrap();
    assert!(prefix.matches("/v1/messages") && !prefix.matches("/v2/x"));
    for bad in [
        "v1",
        "/v1?x",
        "/v1#x",
        "/a*b",
        "/a**",
        "/a b",
        "/a/../b",
        "/a%2f",
        "//a",
        &format!("/{}", "a".repeat(128)),
    ] {
        assert!(PathPattern::new(bad).is_err(), "{bad}");
    }
}

#[test]
fn debug_output_carries_no_content() {
    let tape = parse(DOC.as_bytes(), &Limits::DEFAULT).unwrap();
    let mask = Mask::new();
    let view = StructuralView::new(&tape, &mask);
    let mut state = ModuleState::new(64);
    state.replace(b"secret-state").unwrap();
    let selector = sel(vec![
        Step::Key("secret-key".into()),
        Step::Where(member_in("secret-member", &["secret-value"])),
    ]);
    let frame = SseEvent {
        event: Some("secret-event"),
        data: b"{\"secret\":1}",
    };
    let shown = [
        format!("{view:?}"),
        format!("{:?}", view.root()),
        format!("{:?}", ViewText::Plain("secret-text".into())),
        format!("{:?}", ModuleText::new("secret-text").unwrap()),
        format!("{state:?}"),
        format!("{:?}", ConfigSchema::new(r#"{"secret":1}"#).unwrap()),
        format!("{selector:?}"),
        format!("{frame:?}"),
    ];
    for text in shown {
        assert!(
            !text.contains("secret") && !text.contains("sig") && !text.contains("\"hi\""),
            "{text}"
        );
    }
}

/// A JSON value of bounded size: objects with keys from a small set, so names repeat across
/// levels and selectors find several matches.
fn json() -> impl Strategy<Value = String> {
    let key = prop::sample::select(vec!["a", "b", "role", "type", "content"]);
    let leaf = prop_oneof![
        Just("null".to_owned()),
        (0u32..1000).prop_map(|n| n.to_string()),
        prop::sample::select(vec!["\"user\"", "\"text\"", "\"x\""]).prop_map(str::to_owned),
    ];
    leaf.prop_recursive(4, 64, 6, move |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(|items| format!("[{}]", items.join(","))),
            prop::collection::btree_map(key.clone(), inner, 0..5).prop_map(|members| {
                let members: Vec<String> = members.into_iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
                format!("{{{}}}", members.join(","))
            }),
        ]
    })
}

fn steps() -> impl Strategy<Value = Vec<Step>> {
    let key = prop::sample::select(vec!["a", "b", "role", "type", "content"]).prop_map(str::to_owned);
    let step = prop_oneof![
        key.clone().prop_map(Step::Key),
        Just(Step::Each),
        key.clone().prop_map(Step::AnyDepthKey),
        Just(Step::Last),
        key.prop_map(|k| Step::Where(member_in(&k, &["user", "text"]))),
    ];
    prop::collection::vec(step, 0..6)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// On generated tapes, a selector names only nodes of the view, in document order, without
    /// repeats; a key step names only members with that key; a role map names only nodes it was
    /// given.
    #[test]
    fn selectors_stay_inside_the_view(doc in json(), steps in steps()) {
        let tape = parse(doc.as_bytes(), &Limits::DEFAULT).unwrap();
        let mask = Mask::new();
        let view = StructuralView::new(&tape, &mask);
        let last_is_key = match steps.last() {
            Some(Step::Key(k) | Step::AnyDepthKey(k)) => Some(k.clone()),
            _ => None,
        };
        let selector = Selector::new(steps).unwrap();
        let ids = selector.resolve(&view).unwrap();
        prop_assert!(ids.windows(2).all(|w| w[0] < w[1]), "not in document order, or repeated");
        for id in &ids {
            let node = view.node(*id);
            prop_assert!(node.is_some(), "a selector named a node outside the view");
            if let (Some(node), Some(key)) = (node, &last_is_key) {
                prop_assert!(node.key_is(key).unwrap());
            }
        }
        let mut roles = RoleMap::new();
        let assigned = roles.assign(&view, &selector, Role::Opaque).unwrap();
        prop_assert_eq!(assigned, ids.len());
        let named: Vec<NodeId> = roles.nodes().map(|(id, _)| id).collect();
        prop_assert_eq!(named, ids);
    }
}
