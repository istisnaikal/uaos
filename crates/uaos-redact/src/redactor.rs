// SPDX-License-Identifier: Apache-2.0

//! Redaction: every detected secret is replaced by a placeholder keyed to the pocket.
//!
//! A placeholder is `[REDACTED:<class>:<tag>]`, where `tag` is the first 64 bits of
//! HMAC-SHA-256 under the pocket's placeholder key over the class and the secret. It is therefore
//! the same on every turn and after every restart (prefix stability), differs between pockets,
//! and reveals nothing about the secret without the key.
//!
//! Each JSON string is redacted to a fixpoint: after the replacements it is scanned again, so
//! the output contains no detection and `redact(redact(x)) == redact(x)`. Content without a
//! detection is returned borrowed, byte for byte.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Range;

use uaos_platform::crypto::{SecretKey, hmac_sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::RedactError;
use crate::class::DataClass;
use crate::detect::{DetectorSet, DetectorVersion, Finding, PLACEHOLDER_PREFIX};
use crate::json::{decode, decode_mapped, strings};

/// Rounds after which redaction that still finds something gives up (and blocks).
const MAX_ROUNDS: usize = 4;
/// Domain separation for placeholder tags.
const PLACEHOLDER_DOMAIN: &[u8] = b"uaos.redact.placeholder/1\0";

/// One secret that was replaced. The secret is wiped from memory when this is dropped and never
/// appears in `Debug` output.
pub struct Replacement {
    class: DataClass,
    placeholder: String,
    secret: Zeroizing<String>,
}

impl Replacement {
    /// The class.
    #[must_use]
    pub fn class(&self) -> DataClass {
        self.class
    }

    /// The placeholder that replaced the secret.
    #[must_use]
    pub fn placeholder(&self) -> &str {
        &self.placeholder
    }

    /// The secret, for rehydration toward the client that supplied it. Never log or persist it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.secret
    }
}

impl fmt::Debug for Replacement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Replacement")
            .field("class", &self.class)
            .field("placeholder", &self.placeholder)
            .finish_non_exhaustive()
    }
}

/// The result of redacting text (`T = str`) or a JSON body (`T = [u8]`).
pub struct Redaction<'a, T: ?Sized + ToOwned> {
    output: Cow<'a, T>,
    replacements: Vec<Replacement>,
}

impl<'a, T: ?Sized + ToOwned> Redaction<'a, T> {
    /// The redacted content.
    #[must_use]
    pub fn output(&self) -> &T {
        &self.output
    }

    /// The redacted content, borrowed from the input when nothing was replaced.
    #[must_use]
    pub fn into_output(self) -> Cow<'a, T> {
        self.output
    }

    /// The distinct secrets replaced, by placeholder.
    #[must_use]
    pub fn replacements(&self) -> &[Replacement] {
        &self.replacements
    }

    /// The classes found (the policy context's `data_classes`).
    #[must_use]
    pub fn classes(&self) -> BTreeSet<DataClass> {
        self.replacements.iter().map(|r| r.class).collect()
    }

    /// Whether nothing was replaced (the output is the input, byte for byte).
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.replacements.is_empty()
    }
}

impl<T: ?Sized + ToOwned> fmt::Debug for Redaction<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Content never appears in Debug output, redacted or not.
        f.debug_struct("Redaction")
            .field("replacements", &self.replacements)
            .finish_non_exhaustive()
    }
}

/// Distinct replacements keyed by placeholder.
#[derive(Default)]
struct Replacements(BTreeMap<String, Replacement>);

impl Replacements {
    fn record(&mut self, class: DataClass, placeholder: &str, secret: &str) -> Result<(), RedactError> {
        match self.0.get(placeholder) {
            Some(existing) if existing.expose_secret() != secret => Err(RedactError::PlaceholderCollision),
            Some(_) => Ok(()),
            None => {
                self.0.insert(
                    placeholder.to_owned(),
                    Replacement {
                        class,
                        placeholder: placeholder.to_owned(),
                        secret: Zeroizing::new(secret.to_owned()),
                    },
                );
                Ok(())
            }
        }
    }

    fn into_vec(self) -> Vec<Replacement> {
        self.0.into_values().collect()
    }
}

/// Redacts content for one pocket under one pinned detector set.
pub struct Redactor {
    detectors: DetectorSet,
    key: SecretKey,
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor")
            .field("version", &self.detectors.version())
            .finish_non_exhaustive()
    }
}

impl Redactor {
    /// A redactor using detector set `version` (pinned by the session) and the pocket's
    /// placeholder key.
    ///
    /// # Errors
    /// [`RedactError::UnknownDetectorVersion`] or a detector compilation failure.
    pub fn new(version: DetectorVersion, placeholder_key: SecretKey) -> Result<Self, RedactError> {
        Ok(Self {
            detectors: DetectorSet::new(version)?,
            key: placeholder_key,
        })
    }

    /// The pinned detector set version.
    #[must_use]
    pub fn version(&self) -> DetectorVersion {
        self.detectors.version()
    }

    /// Secrets in `text`, without redacting.
    ///
    /// # Errors
    /// A detector failure.
    pub fn detect(&self, text: &str) -> Result<Vec<Finding>, RedactError> {
        self.detectors.scan(text.as_bytes())
    }

    /// The placeholder for `secret` of `class` in this pocket.
    #[must_use]
    pub fn placeholder(&self, class: DataClass, secret: &str) -> String {
        let mut message = Vec::with_capacity(PLACEHOLDER_DOMAIN.len() + 32 + secret.len());
        message.extend_from_slice(PLACEHOLDER_DOMAIN);
        message.extend_from_slice(class.as_str().as_bytes());
        message.push(0);
        message.extend_from_slice(secret.as_bytes());
        let tag = hmac_sha256(&self.key, &message);
        message.zeroize();
        let mut out = String::with_capacity(PLACEHOLDER_PREFIX.len() + class.as_str().len() + 18);
        out.push_str("[REDACTED:");
        out.push_str(class.as_str());
        out.push(':');
        for byte in tag.iter().take(8) {
            out.extend(char::from_digit(u32::from(byte >> 4), 16));
            out.extend(char::from_digit(u32::from(byte & 0x0F), 16));
        }
        out.push(']');
        out
    }

    /// Redacts plain text.
    ///
    /// # Errors
    /// Any detector failure: the caller must block the content.
    pub fn redact_text<'a>(&self, text: &'a str) -> Result<Redaction<'a, str>, RedactError> {
        let mut replacements = Replacements::default();
        let mut current: Option<String> = None;
        for _ in 0..MAX_ROUNDS {
            let s = current.as_deref().unwrap_or(text);
            let findings = self.detectors.scan(s.as_bytes())?;
            if findings.is_empty() {
                return Ok(Redaction {
                    output: current.map_or(Cow::Borrowed(text), Cow::Owned),
                    replacements: replacements.into_vec(),
                });
            }
            let mut next = String::with_capacity(s.len());
            let mut last = 0;
            for f in &findings {
                next.push_str(slice(s, last..f.range.start)?);
                let secret = slice(s, f.range.clone())?;
                let placeholder = self.placeholder(f.class, secret);
                replacements.record(f.class, &placeholder, secret)?;
                next.push_str(&placeholder);
                last = f.range.end;
            }
            next.push_str(slice(s, last..s.len())?);
            current = Some(next);
        }
        Err(RedactError::Unconverged)
    }

    /// Redacts every string of a JSON body (keys and values, at any depth, in any field) and
    /// splices placeholders into the original bytes.
    ///
    /// # Errors
    /// Invalid UTF-8, malformed JSON strings or any detector failure: the caller must block.
    pub fn redact_json<'a>(&self, json: &'a [u8]) -> Result<Redaction<'a, [u8]>, RedactError> {
        std::str::from_utf8(json).map_err(|_| RedactError::InvalidUtf8)?;
        let mut replacements = Replacements::default();
        let mut out: Option<Vec<u8>> = None;
        let mut copied = 0;
        for range in strings(json) {
            let range = range?;
            let content = json.get(range.clone()).ok_or(OUT_OF_BOUNDS)?;
            if let Some(redacted) = self.redact_json_string(content, &mut replacements)? {
                let buf = out.get_or_insert_with(|| Vec::with_capacity(json.len()));
                buf.extend_from_slice(json.get(copied..range.start).ok_or(OUT_OF_BOUNDS)?);
                buf.extend_from_slice(&redacted);
                copied = range.end;
            }
        }
        let output = match out {
            None => Cow::Borrowed(json),
            Some(mut buf) => {
                buf.extend_from_slice(json.get(copied..).ok_or(OUT_OF_BOUNDS)?);
                Cow::Owned(buf)
            }
        };
        Ok(Redaction {
            output,
            replacements: replacements.into_vec(),
        })
    }

    /// Redacts the raw contents of one JSON string to a fixpoint; `None` if nothing was found.
    fn redact_json_string(
        &self,
        content: &[u8],
        replacements: &mut Replacements,
    ) -> Result<Option<Vec<u8>>, RedactError> {
        let mut current: Option<Vec<u8>> = None;
        for _ in 0..MAX_ROUNDS {
            let raw = current.as_deref().unwrap_or(content);
            let findings = self.detectors.scan(decode(raw)?.text.as_bytes())?;
            if findings.is_empty() {
                return Ok(current);
            }
            let decoded = decode_mapped(raw)?;
            let mut next = Vec::with_capacity(raw.len());
            let mut last = 0;
            for f in &findings {
                let (start, end) = (decoded.raw(f.range.start)?, decoded.raw(f.range.end)?);
                next.extend_from_slice(raw.get(last..start).ok_or(OUT_OF_BOUNDS)?);
                let secret = slice(&decoded.text, f.range.clone())?;
                let placeholder = self.placeholder(f.class, secret);
                replacements.record(f.class, &placeholder, secret)?;
                next.extend_from_slice(placeholder.as_bytes());
                last = end;
            }
            next.extend_from_slice(raw.get(last..).ok_or(OUT_OF_BOUNDS)?);
            current = Some(next);
        }
        Err(RedactError::Unconverged)
    }
}

const OUT_OF_BOUNDS: RedactError = RedactError::DetectorFailure("span outside the content");

fn slice(s: &str, range: Range<usize>) -> Result<&str, RedactError> {
    s.get(range)
        .ok_or(RedactError::DetectorFailure("span not on a character boundary"))
}
