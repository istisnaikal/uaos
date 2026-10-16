// SPDX-License-Identifier: Apache-2.0

//! The canary for the one `clippy.toml` ban that `uaos-egress`'s canaries cannot name: entropy
//! comes only from the platform's own source. See `crates/uaos-egress/tests/bans.rs`.

mod canaries {
    #![allow(dead_code, reason = "canaries are compiled by clippy and never run")]

    #[expect(clippy::disallowed_methods, reason = "canary")]
    fn getrandom_fill() {
        // canary: `getrandom::fill`
        let mut buf = [0u8; 1];
        let _canary = getrandom::fill(&mut buf);
    }
}
