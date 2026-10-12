// SPDX-License-Identifier: Apache-2.0

//! Cryptographic primitives (plan D18). Thin wrappers over aws-lc-rs, the single audited
//! family used for hashing, MACs, AEAD and signatures. No custom constructions live here or
//! anywhere else: this module only adapts types (e.g. to the tagged digests of
//! `uaos_contracts::digest`).

use aws_lc_rs::digest;
use uaos_contracts::digest::Sha256Digest;

/// SHA-256 of `bytes`.
#[must_use]
pub fn sha256(bytes: &[u8]) -> Sha256Digest {
    let d = digest::digest(&digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    Sha256Digest::from_bytes(out)
}

/// Incremental SHA-256 for inputs assembled from several parts.
#[derive(Clone)]
pub struct Sha256 {
    ctx: digest::Context,
}

impl std::fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sha256 { .. }")
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self {
            ctx: digest::Context::new(&digest::SHA256),
        }
    }
}

impl Sha256 {
    /// Feeds more input.
    pub fn update(&mut self, bytes: &[u8]) {
        self.ctx.update(bytes);
    }

    /// Finishes and returns the digest.
    #[must_use]
    pub fn finish(self) -> Sha256Digest {
        let d = self.ctx.finish();
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        Sha256Digest::from_bytes(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        // FIPS 180-2 test vectors.
        assert_eq!(
            sha256(b"abc").to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256(b"").to_string(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut inc = Sha256::default();
        inc.update(b"a");
        inc.update(b"bc");
        assert_eq!(inc.finish(), sha256(b"abc"));
    }
}
