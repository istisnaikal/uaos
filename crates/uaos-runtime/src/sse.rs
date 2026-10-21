// SPDX-License-Identifier: Apache-2.0

//! The event-stream splitter (contract §7.2).
//!
//! It finds where each event ends in a stream that arrives in arbitrary pieces, and reads an
//! event's fields. It follows WHATWG `text/event-stream`:
//! - a line ends in CRLF, LF or CR;
//! - a CRLF split across two pieces is one line ending;
//! - an event ends at a blank line;
//! - a leading byte-order mark is not part of the first line.
//!
//! Each segment it emits is one event's exact bytes, its final line ending included, so the
//! bytes forwarded are the bytes received.

use std::borrow::Cow;

use bytes::{Bytes, BytesMut};

/// UTF-8 byte-order mark.
const BOM: &[u8] = b"\xEF\xBB\xBF";

/// One event's exact bytes. `skip` bytes at the front (the stream's byte-order mark) are
/// forwarded but not parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Segment {
    pub(crate) bytes: Bytes,
    pub(crate) skip: usize,
}

impl Segment {
    /// The bytes an event-stream parser reads.
    pub(crate) fn parsed(&self) -> &[u8] {
        self.bytes.get(self.skip..).unwrap_or_default()
    }
}

/// An event longer than the bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TooLarge;

/// Splits a byte stream into events.
#[derive(Debug)]
pub(crate) struct Splitter {
    /// The start of an event whose end has not arrived yet.
    pending: BytesMut,
    /// The first bytes of the stream, held until three have arrived, to tell a byte-order mark.
    prelude: Option<BytesMut>,
    /// Bytes at the front of `pending` the parser skips (the byte-order mark).
    skip: usize,
    /// Nothing is on the current line yet.
    at_line_start: bool,
    /// The last byte seen was a CR with nothing after it yet: an LF next belongs to it. Holds
    /// whether the line it ended was blank.
    pending_cr: Option<bool>,
    max_event: usize,
}

impl Splitter {
    pub(crate) fn new(max_event: usize) -> Self {
        Self {
            pending: BytesMut::new(),
            prelude: Some(BytesMut::new()),
            skip: 0,
            at_line_start: true,
            pending_cr: None,
            max_event,
        }
    }

    /// Splits `chunk`: every event that ends in it goes to `out`, in order. What remains is kept
    /// for the next chunk.
    ///
    /// # Errors
    /// [`TooLarge`] once an event passes the bound; the events before it are in `out`.
    pub(crate) fn push(&mut self, chunk: &Bytes, out: &mut Vec<Segment>) -> Result<(), TooLarge> {
        if let Some(prelude) = &mut self.prelude {
            prelude.extend_from_slice(chunk);
            if prelude.len() < BOM.len() {
                return if prelude.len() > self.max_event {
                    Err(TooLarge)
                } else {
                    Ok(())
                };
            }
            let first = prelude.split().freeze();
            self.prelude = None;
            let from = if first.starts_with(BOM) { BOM.len() } else { 0 };
            self.skip = from;
            return self.split(&first, from, out);
        }
        self.split(chunk, 0, out)
    }

    /// At the end of the stream: whatever remains, as one last segment. A lenient client may act
    /// on an event that no blank line ended, so the relay classifies it too.
    pub(crate) fn finish(&mut self) -> Option<Segment> {
        if let Some(prelude) = self.prelude.take() {
            // Fewer than three bytes ever arrived: no byte-order mark fits.
            return (!prelude.is_empty()).then(|| Segment {
                bytes: prelude.freeze(),
                skip: 0,
            });
        }
        self.pending_cr = None;
        if self.pending.is_empty() {
            return None;
        }
        let skip = std::mem::take(&mut self.skip);
        Some(Segment {
            bytes: self.pending.split().freeze(),
            skip,
        })
    }

    fn split(&mut self, chunk: &Bytes, from: usize, out: &mut Vec<Segment>) -> Result<(), TooLarge> {
        // `start` is where the chunk's not yet emitted bytes begin; `scan` is where to look.
        let mut start = 0;
        let mut scan = from;
        loop {
            let Some(end) = self.find_end(chunk, scan) else {
                let held = self.pending.len() + (chunk.len() - start);
                if held > self.max_event {
                    return Err(TooLarge);
                }
                self.pending.extend_from_slice(&chunk[start..]);
                return Ok(());
            };
            if self.pending.len() + (end - start) > self.max_event {
                return Err(TooLarge);
            }
            let bytes = if self.pending.is_empty() {
                chunk.slice(start..end)
            } else {
                self.pending.extend_from_slice(&chunk[start..end]);
                self.pending.split().freeze()
            };
            out.push(Segment {
                bytes,
                skip: std::mem::take(&mut self.skip),
            });
            start = end;
            scan = end;
        }
    }

    /// The offset just past the blank line that ends the current event, looking from `from`, or
    /// `None` if `bytes` ends first. Carries the line state across calls.
    fn find_end(&mut self, bytes: &[u8], from: usize) -> Option<usize> {
        let mut i = from;
        if let Some(blank) = self.pending_cr {
            let next = *bytes.get(i)?;
            self.pending_cr = None;
            if next == b'\n' {
                i += 1;
            }
            self.at_line_start = true;
            if blank {
                return Some(i);
            }
        }
        loop {
            let rest = bytes.get(i..)?;
            let Some(k) = memchr::memchr2(b'\n', b'\r', rest) else {
                if !rest.is_empty() {
                    self.at_line_start = false;
                }
                return None;
            };
            let at = i + k;
            let blank = self.at_line_start && k == 0;
            self.at_line_start = true;
            let end = if bytes[at] == b'\r' {
                match bytes.get(at + 1) {
                    // Whether an LF follows is not known yet.
                    None => {
                        self.pending_cr = Some(blank);
                        return None;
                    }
                    Some(b'\n') => at + 2,
                    Some(_) => at + 1,
                }
            } else {
                at + 1
            };
            if blank {
                return Some(end);
            }
            i = end;
        }
    }
}

/// The fields of one event that the relay reads.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Fields<'a> {
    /// The last `event` field's value, if any.
    pub(crate) event: Option<&'a [u8]>,
    /// The `data` lines joined with LF, if there is at least one. Without one, no event is
    /// dispatched.
    pub(crate) data: Option<Cow<'a, [u8]>>,
}

/// Reads one event's fields from its bytes (the byte-order mark already skipped).
pub(crate) fn fields(raw: &[u8]) -> Fields<'_> {
    let mut event = None;
    let mut data: Option<Cow<'_, [u8]>> = None;
    let mut rest = raw;
    while !rest.is_empty() {
        let (line, next) = match memchr::memchr2(b'\n', b'\r', rest) {
            Some(at) => {
                let len = if rest[at] == b'\r' && rest.get(at + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                (&rest[..at], &rest[at + len..])
            }
            None => (rest, &rest[rest.len()..]),
        };
        rest = next;
        if line.is_empty() {
            break;
        }
        if line[0] == b':' {
            continue;
        }
        let (name, value) = match memchr::memchr(b':', line) {
            Some(colon) => {
                let value = &line[colon + 1..];
                (&line[..colon], value.strip_prefix(b" ").unwrap_or(value))
            }
            None => (line, &line[line.len()..]),
        };
        match name {
            b"event" => event = Some(value),
            b"data" => {
                data = Some(match data.take() {
                    None => Cow::Borrowed(value),
                    Some(earlier) => {
                        let mut joined = earlier.into_owned();
                        joined.push(b'\n');
                        joined.extend_from_slice(value);
                        Cow::Owned(joined)
                    }
                });
            }
            _ => {}
        }
    }
    Fields { event, data }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split_all(pieces: &[&[u8]]) -> Vec<Vec<u8>> {
        let mut s = Splitter::new(1 << 20);
        let mut out = Vec::new();
        for p in pieces {
            s.push(&Bytes::copy_from_slice(p), &mut out).unwrap();
        }
        out.extend(s.finish());
        out.into_iter().map(|seg| seg.bytes.to_vec()).collect()
    }

    #[test]
    fn events_end_at_blank_lines_in_every_line_ending() {
        let events = split_all(&[b"data: a\n\ndata: b\r\n\r\ndata: c\r\rdata: d"]);
        assert_eq!(
            events,
            vec![
                b"data: a\n\n".to_vec(),
                b"data: b\r\n\r\n".to_vec(),
                b"data: c\r\r".to_vec(),
                b"data: d".to_vec()
            ]
        );
    }

    #[test]
    fn a_crlf_split_across_pieces_is_one_line_ending() {
        // `\r` | `\n\r` | `\ndata` : one line "data: a", then a CRLF blank line.
        assert_eq!(
            split_all(&[b"data: a\r", b"\n\r", b"\ndata: b\n\n"]),
            vec![b"data: a\r\n\r\n".to_vec(), b"data: b\n\n".to_vec()]
        );
        // A blank line ended by a lone CR at the end of a piece waits for the next byte.
        assert_eq!(
            split_all(&[b"data: a\r\r", b"\ndata: b\n\n"]),
            vec![b"data: a\r\r\n".to_vec(), b"data: b\n\n".to_vec()]
        );
    }

    #[test]
    fn a_byte_order_mark_is_not_line_content() {
        let events = split_all(&[b"\xEF", b"\xBB\xBF\ndata: a\n\n"]);
        assert_eq!(events, vec![b"\xEF\xBB\xBF\n".to_vec(), b"data: a\n\n".to_vec()]);
    }

    #[test]
    fn fields_follow_the_event_stream_rules() {
        let f = fields(b": comment\nevent: usage\ndata: {\"a\":\ndata:1}\nid: 7\n\n");
        assert_eq!(f.event, Some(&b"usage"[..]));
        assert_eq!(f.data.as_deref(), Some(&b"{\"a\":\n1}"[..]));
        assert_eq!(fields(b": ping\n\n").data, None);
        assert_eq!(fields(b"data\n\n").data.as_deref(), Some(&b""[..]));
        assert_eq!(
            fields(b"data:  two spaces\n\n").data.as_deref(),
            Some(&b" two spaces"[..])
        );
    }

    #[test]
    fn an_event_past_the_bound_is_refused() {
        let mut s = Splitter::new(12);
        let mut out = Vec::new();
        assert_eq!(
            s.push(&Bytes::from_static(b"data: 1\n\ndata: 123456789"), &mut out),
            Err(TooLarge)
        );
        assert_eq!(out.len(), 1, "the event before the oversized one was kept");
    }
}
