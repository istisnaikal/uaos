// SPDX-License-Identifier: Apache-2.0

//! Arbitrary bytes into the tape (contract §9). Nothing may panic; a tape that parses must pass
//! every invariant and decode every key and string, with and without the offset map; an error
//! must point inside the input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use uaos_json::{Limits, parse};

fuzz_target!(|data: &[u8]| {
    match parse(data, &Limits::DEFAULT) {
        Ok(tape) => {
            if let Err(violation) = tape.verify() {
                panic!("{violation}");
            }
            for node in tape.nodes() {
                if let Err(e) = node.key() {
                    panic!("a key on a tape does not decode: {e}");
                }
                if let Err(e) = node.str_value() {
                    panic!("a string on a tape does not decode: {e}");
                }
                if let Err(e) = node.str_value_mapped() {
                    panic!("a string on a tape does not decode with its map: {e}");
                }
            }
        }
        Err(e) => {
            let offset = usize::try_from(e.offset()).unwrap_or(usize::MAX);
            assert!(
                offset <= data.len(),
                "error offset {offset} beyond {} bytes",
                data.len()
            );
        }
    }
});
