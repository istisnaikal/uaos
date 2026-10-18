// SPDX-License-Identifier: Apache-2.0

//! The grammar of the tape contract (§3, §4, §8), one test per rule, each checking the error's
//! kind and offset. The tests named in `xtask` seeded violations carry the words their
//! negative case expects in their failure message.

use std::fmt::Write as _;

use uaos_json::{ErrorKind, Kind, Limits, LimitsError, MAX_KEY_LEN, parse, parse_i64, parse_u64};

fn refused(input: &[u8]) -> (ErrorKind, u32) {
    refused_under(input, &Limits::DEFAULT)
}

fn refused_under(input: &[u8], limits: &Limits) -> (ErrorKind, u32) {
    match parse(input, limits) {
        Ok(_) => (ErrorKind::OutOfMemory, u32::MAX), // a sentinel no rule produces here
        Err(e) => (e.kind(), e.offset()),
    }
}

fn accepted(input: &[u8]) -> bool {
    parse(input, &Limits::DEFAULT).is_ok()
}

/// A fixture with `~u` standing for a backslash-u escape, so the source never spells one.
fn j(text: &str) -> Vec<u8> {
    text.replace("~u", "\\u").into_bytes()
}

fn nested(open: &str, close: &str, levels: usize) -> String {
    format!("{}{}", open.repeat(levels), close.repeat(levels))
}

#[test]
fn plain_duplicate_keys_are_rejected() {
    for (input, offset) in [
        (&br#"{"a":1,"b":2,"a":3}"#[..], 13),
        (br#"{"x":{"a":1,"a":2}}"#, 12),
        (br#"[{"k":true},{"k":1,"k":2}]"#, 19),
        (br#"{"a":1,"a":2,"a":3}"#, 7),
    ] {
        assert_eq!(
            refused(input),
            (ErrorKind::DuplicateKey, offset),
            "duplicate key accepted, or reported elsewhere: {}",
            String::from_utf8_lossy(input)
        );
    }
    // Past the size where a pairwise check would end: 40 members, the repeat last.
    let mut wide = String::from("{");
    for i in 0..40 {
        write!(wide, "\"k{i}\":{i},").unwrap();
    }
    let at = u32::try_from(wide.len()).unwrap();
    wide.push_str("\"k7\":0}");
    assert_eq!(
        refused(wide.as_bytes()),
        (ErrorKind::DuplicateKey, at),
        "duplicate key accepted"
    );
    assert!(
        accepted(br#"{"a":1,"b":{"a":2},"c":[{"a":3}]}"#),
        "same key in different objects"
    );
}

#[test]
fn escaped_duplicate_keys_are_rejected() {
    for (input, offset) in [
        (j(r#"{"a":1,"~u0061":2}"#), 7),
        (j(r#"{"~u0061":1,"a":2}"#), 12),
        (j(r#"{"a/b":1,"a\/b":2}"#), 9),
        (j(r#"{"~u00e9":1,"é":2}"#), 12),
        (j(r#"{"~u00E9":1,"~u00e9":2}"#), 12),
        (j(r#"{"😀":1,"~ud83d~ude00":2}"#), 10),
        (j(r#"{"q\"":1,"q~u0022":2}"#), 9),
    ] {
        assert_eq!(
            refused(&input),
            (ErrorKind::DuplicateKey, offset),
            "escaped duplicate key accepted, or reported elsewhere: {}",
            String::from_utf8_lossy(&input)
        );
    }
    let distinct = j(r#"{"a":1,"~u0062":2,"~u00e9":3,"e":4}"#);
    assert!(accepted(&distinct), "distinct keys refused");
}

#[test]
fn depth_limit_is_exact() {
    for (open, close) in [("[", "]"), ("{\"a\":", "}")] {
        let deepest = nested(open, close, 128).replace("{\"a\":}", "{}");
        assert!(accepted(deepest.as_bytes()), "depth 128 refused");
        let too_deep = nested(open, close, 129).replace("{\"a\":}", "{}");
        let (kind, offset) = refused(too_deep.as_bytes());
        assert_eq!(kind, ErrorKind::DepthExceeded, "depth 129 accepted");
        assert_eq!(offset, u32::try_from(open.len() * 128).unwrap());
    }
    let mixed = "[{\"a\":".repeat(64) + "0" + &"}]".repeat(64);
    assert!(accepted(mixed.as_bytes()), "mixed depth 128 refused");
    let mixed = "[{\"a\":".repeat(64) + "[]" + &"}]".repeat(64);
    assert_eq!(
        refused(mixed.as_bytes()).0,
        ErrorKind::DepthExceeded,
        "depth 129 accepted"
    );
    let five = nested("[", "]", 5);
    let tape = parse(five.as_bytes(), &Limits::DEFAULT).unwrap();
    assert_eq!(tape.stats().max_depth, 5);
}

#[test]
fn lone_surrogates_are_rejected() {
    for (input, offset) in [
        (j(r#""~ud800""#), 1),
        (j(r#""~udc00""#), 1),
        (j(r#""~uDBFF~u0041""#), 1),
        (j(r#""x~ud800y""#), 2),
        (j(r#""~ud800~ud800""#), 1),
        (j(r#""~ud800\""#), 1),
        (j(r#"{"~udfff":1}"#), 2),
        (j(r#"["~ude00~ud83d"]"#), 2),
    ] {
        assert_eq!(
            refused(&input),
            (ErrorKind::LoneSurrogate, offset),
            "lone surrogate accepted, or reported elsewhere: {}",
            String::from_utf8_lossy(&input)
        );
    }
    let pairs = j(r#""~ud83d~ude00~uD800~uDC00""#);
    assert!(accepted(&pairs), "a surrogate pair refused");
}

#[test]
fn trailing_data_is_rejected() {
    for (input, offset) in [
        (&b"1 2"[..], 2),
        (b"{} {}", 3),
        (b"[]x", 2),
        (br#""a" "b""#, 4),
        (b"null,", 4),
        (b"true\n\t false", 7),
        (b"0 \x00", 2),
    ] {
        assert_eq!(
            refused(input),
            (ErrorKind::TrailingData, offset),
            "trailing data accepted, or reported elsewhere: {}",
            String::from_utf8_lossy(input)
        );
    }
    assert!(accepted(b" \t\r\n[1] \r\n\t "), "surrounding whitespace refused");
}

#[test]
fn bom_is_rejected() {
    for input in [&b"\xEF\xBB\xBF{}"[..], b"\xEF\xBB\xBF1", b"\xEF\xBB\xBF \"a\""] {
        assert_eq!(refused(input), (ErrorKind::ByteOrderMark, 0), "BOM accepted");
    }
    // Inside a string it is just a character.
    assert!(
        accepted("\"\u{feff}\"".as_bytes()),
        "a BOM character in a string refused"
    );
}

#[test]
fn leading_zeros_are_rejected() {
    for (input, offset) in [
        (&b"01"[..], 0),
        (b"-01", 0),
        (b"[00]", 1),
        (br#"{"a":012}"#, 5),
        (b"00.5", 0),
    ] {
        assert_eq!(
            refused(input),
            (ErrorKind::InvalidNumber, offset),
            "leading zero accepted, or reported elsewhere: {}",
            String::from_utf8_lossy(input)
        );
    }
    for valid in ["0", "-0", "0.5", "0e1", "10", "100"] {
        assert!(accepted(valid.as_bytes()), "{valid} refused");
    }
}

#[test]
fn size_limit_is_exact() {
    let limits = Limits::new(5, 128, 16).unwrap();
    assert!(parse(b"[1,2]", &limits).is_ok());
    assert_eq!(refused_under(b"[1,22]", &limits), (ErrorKind::TooLarge, 5));
    // The size check comes first: an oversized input is refused before anything is read.
    assert_eq!(
        refused_under(b"\xff\xff\xff\xff\xff\xff", &limits),
        (ErrorKind::TooLarge, 5)
    );
}

#[test]
fn node_limit_is_exact() {
    let limits = Limits::new(1 << 20, 128, 3).unwrap();
    assert!(parse(b"[1,2]", &limits).is_ok());
    assert_eq!(refused_under(b"[1,2,3]", &limits), (ErrorKind::TooManyNodes, 5));
    // At the default: an array of 2^20 - 1 values is 2^20 nodes.
    let values = (1 << 20) - 1;
    let mut full = String::with_capacity(2 * values + 2);
    full.push('[');
    for i in 0..values {
        if i > 0 {
            full.push(',');
        }
        full.push('0');
    }
    full.push(']');
    let tape = parse(full.as_bytes(), &Limits::DEFAULT).unwrap();
    assert_eq!(tape.stats().nodes, 1 << 20);
    assert!(tape.stats().heap_bytes <= 24 << 20, "tape heap over 24 MiB");
    full.insert_str(1, "0,");
    assert_eq!(refused(full.as_bytes()).0, ErrorKind::TooManyNodes);
}

#[test]
fn key_length_limit_is_exact() {
    let longest = format!("{{\"{}\":1}}", "k".repeat(MAX_KEY_LEN));
    let tape = parse(longest.as_bytes(), &Limits::DEFAULT).unwrap();
    let member = tape.root().children().next().unwrap();
    assert_eq!(member.key_raw().map(str::len), Some(MAX_KEY_LEN));
    let too_long = format!("{{\"{}\":1}}", "k".repeat(MAX_KEY_LEN + 1));
    assert_eq!(refused(too_long.as_bytes()), (ErrorKind::KeyTooLong, 1));
    // A long string value is not a key and has no such limit.
    let value = format!("{{\"k\":\"{}\"}}", "v".repeat(MAX_KEY_LEN * 2));
    assert!(accepted(value.as_bytes()));
}

#[test]
fn limits_are_bounded() {
    assert_eq!(Limits::new(0, 1, 1), Err(LimitsError::MaxBytes));
    assert_eq!(Limits::new((1 << 30) + 1, 1, 1), Err(LimitsError::MaxBytes));
    assert_eq!(Limits::new(1, 0, 1), Err(LimitsError::MaxDepth));
    assert_eq!(Limits::new(1, 1025, 1), Err(LimitsError::MaxDepth));
    assert_eq!(Limits::new(1, 1, 0), Err(LimitsError::MaxNodes));
    assert_eq!(Limits::new(1, 1, (1 << 24) + 1), Err(LimitsError::MaxNodes));
    let ceiling = Limits::new(1 << 30, 1024, 1 << 24).unwrap();
    assert_eq!(
        (ceiling.max_bytes(), ceiling.max_depth(), ceiling.max_nodes()),
        (1 << 30, 1024, 1 << 24)
    );
    assert_eq!(Limits::default(), Limits::DEFAULT);
    let default = Limits::DEFAULT;
    assert_eq!(
        (default.max_bytes(), default.max_depth(), default.max_nodes()),
        (32 << 20, 128, 1 << 20)
    );
}

#[test]
fn utf8_is_validated_everywhere() {
    for (input, offset) in [
        (&b"[\"\xff\"]"[..], 2),
        (b"\"\xC0\xAF\"", 1),
        (b"\"\xED\xA0\x80\"", 1),
        (b"\"\xF4\x90\x80\x80\"", 1),
        (b"\"ok\xE2\x82\"", 3),
        (b"[1]\xff", 3),
    ] {
        assert_eq!(refused(input), (ErrorKind::InvalidUtf8, offset), "{input:?}");
    }
}

#[test]
fn empty_and_whitespace() {
    assert_eq!(refused(b""), (ErrorKind::Empty, 0));
    assert_eq!(refused(b" \n\t\r"), (ErrorKind::Empty, 4));
    // Only the four JSON whitespace characters count as whitespace.
    assert_eq!(refused(b"\x0C1"), (ErrorKind::ExpectedValue, 0));
    assert_eq!(refused("\u{a0}1".as_bytes()), (ErrorKind::ExpectedValue, 0));
    assert_eq!(refused(b"[1,\x0B2]"), (ErrorKind::ExpectedValue, 3));
}

#[test]
fn strings() {
    assert_eq!(refused(b"\"a\x01b\""), (ErrorKind::ControlCharacter, 2));
    assert_eq!(refused(b"\"a\tb\""), (ErrorKind::ControlCharacter, 2));
    assert_eq!(refused(b"\"\x00\""), (ErrorKind::ControlCharacter, 1));
    assert!(accepted(b"\"\x7f\""), "DEL refused");
    assert_eq!(refused(br#""\x""#), (ErrorKind::InvalidEscape, 1));
    assert_eq!(refused(br#""\U0041""#), (ErrorKind::InvalidEscape, 1));
    assert_eq!(refused(br#""\'""#), (ErrorKind::InvalidEscape, 1));
    assert_eq!(refused(br#""\u12""#), (ErrorKind::InvalidUnicodeEscape, 1));
    assert_eq!(refused(br#""\uZZZZ""#), (ErrorKind::InvalidUnicodeEscape, 1));
    assert_eq!(refused(br#""\u+123""#), (ErrorKind::InvalidUnicodeEscape, 1));
    assert_eq!(refused(br#""abc"#), (ErrorKind::UnterminatedString, 0));
    assert_eq!(refused(br#""abc\"#), (ErrorKind::UnterminatedString, 0));
    assert_eq!(refused(br#"{"a"#), (ErrorKind::UnterminatedString, 1));
    let input = j(r#"["~u0000","~u00E9~u00e9","\"\\\/\b\f\n\r\t"]"#);
    let tape = parse(&input, &Limits::DEFAULT).unwrap();
    let values: Vec<String> = tape
        .root()
        .children()
        .map(|node| node.str_value().unwrap().unwrap().into_owned())
        .collect();
    assert_eq!(values, ["\0", "éé", "\"\\/\u{8}\u{c}\n\r\t"]);
}

#[test]
fn numbers() {
    for valid in [
        "0",
        "-0",
        "1",
        "-1",
        "1.5",
        "-0.25",
        "1e5",
        "1E+5",
        "1e-5",
        "0.0",
        "2.5E-3",
        "123456789012345678901234567890",
        "1E9661",
        "-1e-9661",
    ] {
        let tape = parse(valid.as_bytes(), &Limits::DEFAULT).unwrap();
        assert_eq!(tape.root().kind(), Kind::Number);
        assert_eq!(tape.root().number_text(), Some(valid), "number text changed");
    }
    for (input, kind, offset) in [
        ("-", ErrorKind::InvalidNumber, 0),
        ("1.", ErrorKind::InvalidNumber, 0),
        ("1.e5", ErrorKind::InvalidNumber, 0),
        ("1e", ErrorKind::InvalidNumber, 0),
        ("1e+", ErrorKind::InvalidNumber, 0),
        ("-Infinity", ErrorKind::InvalidNumber, 0),
        ("[1.]", ErrorKind::InvalidNumber, 1),
        ("- 1", ErrorKind::InvalidNumber, 0),
        (".5", ErrorKind::ExpectedValue, 0),
        ("+1", ErrorKind::ExpectedValue, 0),
        ("NaN", ErrorKind::ExpectedValue, 0),
        ("Infinity", ErrorKind::ExpectedValue, 0),
        ("0x10", ErrorKind::TrailingData, 1),
        ("1.5.2", ErrorKind::TrailingData, 3),
    ] {
        assert_eq!(refused(input.as_bytes()), (kind, offset), "{input}");
    }
}

#[test]
fn literals() {
    let tape = parse(b"[true,false,null]", &Limits::DEFAULT).unwrap();
    let kinds: Vec<Kind> = tape.root().children().map(|node| node.kind()).collect();
    assert_eq!(kinds, [Kind::True, Kind::False, Kind::Null]);
    assert_eq!(refused(b"tru"), (ErrorKind::InvalidLiteral, 0));
    assert_eq!(refused(b"nul"), (ErrorKind::InvalidLiteral, 0));
    assert_eq!(refused(b"fals"), (ErrorKind::InvalidLiteral, 0));
    assert_eq!(refused(b"True"), (ErrorKind::ExpectedValue, 0));
    assert_eq!(refused(b"[nulll]"), (ErrorKind::ExpectedCommaOrClose, 5));
    assert_eq!(refused(b"trueish"), (ErrorKind::TrailingData, 4));
}

#[test]
fn structure() {
    for (input, kind, offset) in [
        (&b"[1,]"[..], ErrorKind::ExpectedValue, 3),
        (br#"{"a":1,}"#, ErrorKind::ExpectedKey, 7),
        (br#"{"a" 1}"#, ErrorKind::ExpectedColon, 5),
        (b"[1 2]", ErrorKind::ExpectedCommaOrClose, 3),
        (b"[1}", ErrorKind::ExpectedCommaOrClose, 2),
        (br#"{"a":1]"#, ErrorKind::ExpectedCommaOrClose, 6),
        (b"{1:2}", ErrorKind::ExpectedKey, 1),
        (b"{,}", ErrorKind::ExpectedKey, 1),
        (b"[,1]", ErrorKind::ExpectedValue, 1),
        (br#"{"a":}"#, ErrorKind::ExpectedValue, 5),
        (b"[", ErrorKind::UnexpectedEnd, 1),
        (b"[1,", ErrorKind::UnexpectedEnd, 3),
        (br#"{"a":"#, ErrorKind::UnexpectedEnd, 5),
        (br#"{"a""#, ErrorKind::UnexpectedEnd, 4),
        (b"{", ErrorKind::UnexpectedEnd, 1),
        (b"]", ErrorKind::ExpectedValue, 0),
        (b":", ErrorKind::ExpectedValue, 0),
    ] {
        assert_eq!(refused(input), (kind, offset), "{}", String::from_utf8_lossy(input));
    }
    for scalar in [&b"1"[..], b"\"a\"", b"true", b"null", b"[]", b"{}", b" [ ] "] {
        assert!(accepted(scalar), "{}", String::from_utf8_lossy(scalar));
    }
}

#[test]
fn error_display_holds_no_input() {
    let error = parse(br#"{"secret-value":1,"secret-value":2}"#, &Limits::DEFAULT).unwrap_err();
    assert_eq!(error.to_string(), "json: duplicate key at byte 18");
    assert_eq!(error.kind().code(), "duplicate_key");
    assert!(!format!("{error:?}").contains("secret"));
}

#[test]
fn the_parser_does_not_recurse() {
    // 1,024 levels on a 64 KiB stack: recursion would need far more.
    let limits = Limits::new(1 << 20, 1024, 1 << 20).unwrap();
    let input = nested("[", "]", 1024);
    #[allow(clippy::disallowed_methods, reason = "a test thread with a small, fixed stack")]
    let worker = std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(move || parse(input.as_bytes(), &limits).map(|tape| tape.stats().max_depth))
        .unwrap();
    assert_eq!(worker.join().unwrap(), Ok(1024));
}

#[test]
fn serde_json_depth_boundary_is_pinned() {
    // The differential oracle stops at its own depth; the tape's limit is its own (128), and the
    // generated documents stay far below both.
    let shallow = nested("[", "]", 127);
    let deep = nested("[", "]", 128);
    assert!(serde_json::from_str::<serde_json::Value>(&shallow).is_ok());
    assert!(serde_json::from_str::<serde_json::Value>(&deep).is_err());
}

#[test]
fn typed_integers() {
    assert_eq!(parse_u64("0"), Some(0));
    assert_eq!(parse_u64("18446744073709551615"), Some(u64::MAX));
    assert_eq!(parse_u64("18446744073709551616"), None);
    for refused_text in ["-1", "01", "1e3", "1.0", "", "+1", " 1"] {
        assert_eq!(parse_u64(refused_text), None, "{refused_text}");
    }
    assert_eq!(parse_i64("-9223372036854775808"), Some(i64::MIN));
    assert_eq!(parse_i64("9223372036854775807"), Some(i64::MAX));
    assert_eq!(parse_i64("9223372036854775808"), None);
    assert_eq!(parse_i64("-9223372036854775809"), None);
    for refused_text in ["-0", "-", "1e3", "-1.0", "--1", "-01"] {
        assert_eq!(parse_i64(refused_text), None, "{refused_text}");
    }
    let tape = parse(br#"{"max_tokens":4096,"t":1.5,"n":-7}"#, &Limits::DEFAULT).unwrap();
    let root = tape.root();
    assert_eq!(root.member("max_tokens").unwrap().unwrap().as_u64(), Some(4096));
    assert_eq!(root.member("t").unwrap().unwrap().as_u64(), None);
    assert_eq!(root.member("n").unwrap().unwrap().as_i64(), Some(-7));
}
