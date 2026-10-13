// SPDX-License-Identifier: Apache-2.0

//! Schema-agnostic JSON access: every string token (keys and values, known and unknown fields)
//! is found in the raw bytes and decoded, with a map from decoded offsets back to raw offsets so
//! edits are spliced into the original bytes and everything else stays byte-identical.
//!
//! This is not a validating parser; the dialect codec validates structure. It is strict where
//! scanning depends on it: an unterminated string, a malformed escape or a lone surrogate is an
//! error, and every error blocks the content (fail closed).

use std::borrow::Cow;
use std::fmt;
use std::ops::Range;

use crate::RedactError;

/// The raw byte ranges of every string's contents (between its quotes), in order.
pub(crate) fn strings(raw: &[u8]) -> Strings<'_> {
    Strings { raw, pos: 0 }
}

pub(crate) struct Strings<'a> {
    raw: &'a [u8],
    pos: usize,
}

impl fmt::Debug for Strings<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Raw bytes may be secrets: lengths only.
        f.debug_struct("Strings")
            .field("len", &self.raw.len())
            .field("pos", &self.pos)
            .finish()
    }
}

impl Iterator for Strings<'_> {
    type Item = Result<Range<usize>, RedactError>;

    fn next(&mut self) -> Option<Self::Item> {
        let open = self.pos + memchr::memchr(b'"', self.raw.get(self.pos..)?)?;
        let start = open + 1;
        let mut i = start;
        loop {
            // Jump to the next quote or backslash; everything in between is plain content.
            let next = self
                .raw
                .get(i..)
                .and_then(|rest| memchr::memchr2(b'"', b'\\', rest))
                .map(|at| i + at);
            match next.and_then(|at| self.raw.get(at).map(|&b| (at, b))) {
                None => {
                    self.pos = self.raw.len();
                    return Some(Err(RedactError::MalformedJson("unterminated string")));
                }
                Some((at, b'"')) => {
                    self.pos = at + 1;
                    return Some(Ok(start..at));
                }
                Some((at, _)) => i = at + 2,
            }
        }
    }
}

/// A decoded string and the way back to its raw bytes.
pub(crate) struct Decoded<'a> {
    pub(crate) text: Cow<'a, str>,
    /// For each decoded byte, the raw offset of the character or escape that produced it, plus
    /// one final entry for the raw length. `None` when decoded and raw bytes coincide.
    map: Option<Vec<usize>>,
}

impl fmt::Debug for Decoded<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The decoded text may be a secret: length only.
        f.debug_struct("Decoded")
            .field("len", &self.text.len())
            .finish_non_exhaustive()
    }
}

impl Decoded<'_> {
    /// Raw offset of decoded offset `i` (`i` may equal the decoded length).
    pub(crate) fn raw(&self, i: usize) -> Result<usize, RedactError> {
        match &self.map {
            None => Ok(i),
            Some(map) => map
                .get(i)
                .copied()
                .ok_or(RedactError::DetectorFailure("span outside the decoded string")),
        }
    }
}

/// Decodes the contents of one JSON string, for scanning only (no offset map).
pub(crate) fn decode(raw: &[u8]) -> Result<Decoded<'_>, RedactError> {
    decode_with(raw, false)
}

/// Decodes the contents of one JSON string with the map back to raw offsets, for splicing.
pub(crate) fn decode_mapped(raw: &[u8]) -> Result<Decoded<'_>, RedactError> {
    decode_with(raw, true)
}

fn decode_with(raw: &[u8], mapped: bool) -> Result<Decoded<'_>, RedactError> {
    if !raw.contains(&b'\\') {
        let text = std::str::from_utf8(raw).map_err(|_| RedactError::InvalidUtf8)?;
        return Ok(Decoded {
            text: Cow::Borrowed(text),
            map: None,
        });
    }
    let mut out = Vec::with_capacity(raw.len());
    // The map costs eight bytes per byte; scanning never needs it.
    let mut map = Vec::with_capacity(if mapped { raw.len() + 1 } else { 0 });
    let note = |map: &mut Vec<usize>, at: usize| {
        if mapped {
            map.push(at);
        }
    };
    let mut i = 0;
    while let Some(&b) = raw.get(i) {
        if b != b'\\' {
            // Copy the whole run up to the next escape at once.
            let rest = raw.get(i..).unwrap_or_default();
            let run = memchr::memchr(b'\\', rest).unwrap_or(rest.len());
            out.extend_from_slice(rest.get(..run).unwrap_or_default());
            if mapped {
                map.extend(i..i + run);
            }
            i += run;
            continue;
        }
        let escape = raw.get(i + 1).ok_or(RedactError::MalformedJson("dangling escape"))?;
        let simple = match escape {
            b'"' => Some(b'"'),
            b'\\' => Some(b'\\'),
            b'/' => Some(b'/'),
            b'b' => Some(0x08),
            b'f' => Some(0x0C),
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            b'u' => None,
            _ => return Err(RedactError::MalformedJson("invalid escape")),
        };
        if let Some(byte) = simple {
            out.push(byte);
            note(&mut map, i);
            i += 2;
            continue;
        }
        let high = hex4(raw, i + 2)?;
        let (code, consumed) = if (0xD800..0xDC00).contains(&high) {
            let low = (raw.get(i + 6) == Some(&b'\\') && raw.get(i + 7) == Some(&b'u'))
                .then(|| hex4(raw, i + 8))
                .transpose()?
                .filter(|low| (0xDC00..0xE000).contains(low))
                .ok_or(RedactError::MalformedJson("lone surrogate"))?;
            (0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00), 12)
        } else if (0xDC00..0xE000).contains(&high) {
            return Err(RedactError::MalformedJson("lone surrogate"));
        } else {
            (high, 6)
        };
        let ch = char::from_u32(code).ok_or(RedactError::MalformedJson("invalid code point"))?;
        let mut buf = [0u8; 4];
        for &byte in ch.encode_utf8(&mut buf).as_bytes() {
            out.push(byte);
            note(&mut map, i);
        }
        i += consumed;
    }
    note(&mut map, raw.len());
    let text = String::from_utf8(out).map_err(|_| RedactError::InvalidUtf8)?;
    Ok(Decoded {
        text: Cow::Owned(text),
        map: mapped.then_some(map),
    })
}

fn hex4(raw: &[u8], at: usize) -> Result<u32, RedactError> {
    let digits = raw
        .get(at..at + 4)
        .ok_or(RedactError::MalformedJson("short unicode escape"))?;
    digits.iter().try_fold(0u32, |acc, &d| {
        char::from(d)
            .to_digit(16)
            .map(|v| (acc << 4) | v)
            .ok_or(RedactError::MalformedJson("invalid unicode escape"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_keys_and_values_and_skips_escaped_quotes() {
        let raw = br#"{"a":"x\"y","b":[1,"z"]}"#;
        let found: Vec<_> = strings(raw).map(|r| &raw[r.unwrap()]).collect();
        assert_eq!(found, [&b"a"[..], br#"x\"y"#, b"b", b"z"]);
    }

    #[test]
    fn decoding_maps_back_to_raw_offsets() {
        let raw = br"A\u0042\nC\ud83d\ude00D";
        let d = decode_mapped(raw).unwrap();
        assert_eq!(d.text, "AB\nC\u{1F600}D");
        assert_eq!(d.raw(1).unwrap(), 1, "B came from the \\u0042 escape");
        assert_eq!(d.raw(3).unwrap(), 9, "C");
        assert_eq!(
            d.raw(4).unwrap(),
            10,
            "the emoji's first byte came from the surrogate pair"
        );
        assert_eq!(d.raw(d.text.len()).unwrap(), raw.len());
    }

    #[test]
    fn malformed_input_is_an_error() {
        assert!(strings(br#"{"a":"open"#).any(|r| r.is_err()));
        assert!(decode(br"\x").is_err());
        assert!(decode(br"\ud83d").is_err());
        assert!(decode(br"\ude00").is_err());
        assert!(decode(br"\u12").is_err());
    }
}
