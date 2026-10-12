// SPDX-License-Identifier: Apache-2.0

//! Developer Certificate of Origin (CONTRIBUTING.md §DCO). Every commit in a pull request
//! must carry `Signed-off-by: <author name> <<author email>>` matching its author.

use std::path::Path;

use crate::util::capture;

const RECORD_SEP: char = '\u{1e}';
const FIELD_SEP: char = '\u{0}';

pub(crate) fn check(repo: &Path, range: &str) -> Result<(), String> {
    let log = capture(repo, "git", &["log", "--format=%H%x00%an%x00%ae%x00%B%x1e", range])?;
    let mut unsigned = Vec::new();
    let mut count = 0usize;
    for record in log.split(RECORD_SEP).map(str::trim).filter(|r| !r.is_empty()) {
        count += 1;
        let mut fields = record.splitn(4, FIELD_SEP);
        let (Some(sha), Some(name), Some(email), Some(body)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(format!("could not parse git log record: {record:?}"));
        };
        let expected = format!("Signed-off-by: {name} <{email}>");
        if !body.lines().any(|l| l.trim() == expected) {
            unsigned.push(format!("{} (expected `{expected}`)", sha.get(..12).unwrap_or(sha)));
        }
    }
    if unsigned.is_empty() {
        println!("xtask dco: {count} commit(s) signed off");
        Ok(())
    } else {
        Err(format!(
            "{} commit(s) lack a matching DCO sign-off (use `git commit -s`):\n  {}",
            unsigned.len(),
            unsigned.join("\n  ")
        ))
    }
}
