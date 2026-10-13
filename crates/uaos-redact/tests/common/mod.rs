// SPDX-License-Identifier: Apache-2.0

//! Synthetic corpus v1: generators for secrets of every claimed class, the contexts they appear
//! in, and hard negatives.
//!
//! Everything is generated at test time from a seed: no secret-shaped string is ever committed,
//! so secret scanning of the repository stays meaningful. The generator code plus the seed *is*
//! the corpus version; changing either changes the corpus and must be recorded in ADR-0009.

#![allow(dead_code, reason = "shared by several test crates; each uses a subset")]

use uaos_redact::DataClass;

/// Seed of corpus v1 (merge runs). Nightly runs override it to explore further.
pub(crate) const CORPUS_V1_SEED: u64 = 0x5541_4F53_5244_0001;

/// `SplitMix64`: tiny, deterministic, good enough for corpus generation (not for cryptography).
#[derive(Debug, Clone)]
pub(crate) struct Prng(u64);

impl Prng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub(crate) fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next_u64() % u64::try_from(n).unwrap()).unwrap()
    }

    /// Inclusive range.
    pub(crate) fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }

    pub(crate) fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    pub(crate) fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    pub(crate) fn chars(&mut self, set: &[u8], len: usize) -> String {
        (0..len).map(|_| char::from(self.pick(set))).collect()
    }

    pub(crate) fn chars_in(&mut self, set: &[u8], lo: usize, hi: usize) -> String {
        let n = self.range(lo, hi);
        self.chars(set, n)
    }

    pub(crate) fn chars_of(&mut self, set: &[u8], lens: &[usize]) -> String {
        let n = self.pick(lens);
        self.chars(set, n)
    }
}

pub(crate) const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub(crate) const LOWER_DIGIT: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
pub(crate) const DIGITS: &[u8] = b"0123456789";
pub(crate) const HEX: &[u8] = b"0123456789abcdef";
pub(crate) const UPPER_DIGIT: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
pub(crate) const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
pub(crate) const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
pub(crate) const TOKEN: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
pub(crate) const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub(crate) const PASSWORD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!$%^*()_+~=-.";

/// A secret as it appears (`text`) and the part that must not survive redaction (`secret`).
#[derive(Debug, Clone)]
pub(crate) struct Sample {
    pub(crate) class: DataClass,
    pub(crate) text: String,
    pub(crate) secret: String,
}

fn whole(class: DataClass, text: String) -> Sample {
    Sample {
        class,
        secret: text.clone(),
        text,
    }
}

/// Base64url without padding.
pub(crate) fn b64url(bytes: &[u8]) -> String {
    const SET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            let index = usize::try_from((n >> (18 - 6 * i)) & 0x3F).unwrap();
            out.push(char::from(SET[index]));
        }
    }
    out
}

pub(crate) const WORDS: &[&str] = &[
    "the",
    "agent",
    "budget",
    "request",
    "token",
    "secret",
    "password",
    "deploy",
    "build",
    "cache",
    "journal",
    "pocket",
    "session",
    "error",
    "retry",
    "stream",
    "model",
    "tool",
    "call",
    "policy",
    "config",
    "value",
    "server",
    "client",
    "database",
    "migration",
    "rollback",
    "kernel",
    "module",
    "github",
    "gitlab",
    "slack",
    "stripe",
    "google",
    "amazon",
    "anthropic",
    "openai",
    "key",
    "id",
    "BEGIN",
    "PRIVATE",
    "KEY",
    "Bearer",
    "Authorization",
    "header",
    "payload",
    "sk-learn",
    "task-ant",
    "desk-antenna",
    "AKIAN",
    "ghost",
    "glpat",
    "xoxo",
    "AIza",
    "eyJ",
    "risk",
    "skill",
    "asking",
    "localhost",
    "example.com",
    "user@example.com",
    "git@github.com:org/repo.git",
    "v1.2.3",
    "çalışma",
    "güvenlik",
    "ışık",
    "şifre",
    "anahtar",
    "bütçe",
    "değer",
    "İstanbul",
    "ğ",
    "ü",
    "fn",
    "let",
    "mut",
    "impl",
    "struct",
    "async",
    "await",
    "return",
    "Ok(())",
    "None",
    "Some(x)",
];

pub(crate) fn prose(rng: &mut Prng) -> String {
    let n = rng.range(3, 20);
    let mut out = String::new();
    for i in 0..n {
        if i > 0 {
            out.push_str(rng.pick(&[" ", " ", " ", ", ", ". ", "\n", " - ", ": "]));
        }
        out.push_str(rng.pick(WORDS));
    }
    out
}

/// Contexts a secret (or a negative) is embedded in; `%S%` marks the spot.
pub(crate) const CONTEXTS: &[&str] = &[
    "%S%",
    "export API_KEY=%S%",
    "API_KEY=\"%S%\"",
    "Authorization: Bearer %S%",
    "  token: %S%\n",
    "key = '%S%'",
    "{\"api_key\": \"%S%\", \"x\": 1}",
    "curl -H \"Authorization: Bearer %S%\" https://api.example.com/v1/models",
    "Here is my key `%S%`, why does it fail?",
    "https://api.example.com/v1/data?key=%S%&format=json",
    "(%S%)",
    "[%S%]",
    "<%S%>",
    "%S%,",
    "%S%.",
    "%S%;",
    "line one\n%S%\nline three",
    "\t%S%\t",
    "os.environ[\"SECRET\"] = \"%S%\"",
    "const token = `%S%`;",
    "<value>%S%</value>",
    "- %S%",
    "error: invalid credentials %S% (401)",
    "%S%\r\n",
    "| prod | %S% | rotated |",
    "Merhaba, anahtarım %S% — çalışmıyor.",
];

pub(crate) fn embed(rng: &mut Prng, text: &str) -> String {
    rng.pick(CONTEXTS).replace("%S%", text)
}

/// A secret of `class`.
#[allow(clippy::too_many_lines, reason = "one generator per class, side by side")]
pub(crate) fn secret(rng: &mut Prng, class: DataClass) -> Sample {
    match class {
        DataClass::AnthropicApiKey => {
            let kind = rng.pick(&["api03", "api03", "admin01"]);
            whole(class, format!("sk-ant-{kind}-{}AA", rng.chars(TOKEN, 93)))
        }
        DataClass::OpenaiApiKey => {
            let text = if rng.chance(75) {
                let scope = rng.pick(&["proj", "svcacct", "admin"]);
                let n = rng.pick(&[58, 74]);
                format!("sk-{scope}-{}T3BlbkFJ{}", rng.chars(TOKEN, n), rng.chars(TOKEN, n))
            } else {
                format!("sk-{}T3BlbkFJ{}", rng.chars(ALNUM, 20), rng.chars(ALNUM, 20))
            };
            whole(class, text)
        }
        DataClass::AwsAccessKeyId => {
            let prefix = rng.pick(&["AKIA", "ASIA", "ABIA", "ACCA"]);
            whole(class, format!("{prefix}{}", rng.chars(BASE32, 16)))
        }
        DataClass::GithubToken => {
            let text = if rng.chance(80) {
                let prefix = rng.pick(&["ghp", "gho", "ghu", "ghs", "ghr"]);
                format!("{prefix}_{}", rng.chars(ALNUM, 36))
            } else {
                format!("github_pat_{}_{}", rng.chars(ALNUM, 22), rng.chars(ALNUM, 59))
            };
            whole(class, text)
        }
        DataClass::GitlabToken => {
            let text = if rng.chance(25) {
                format!("glpat-{}.01.{}", rng.chars(TOKEN, 27), rng.chars(LOWER_DIGIT, 9))
            } else {
                let prefix = rng.pick(&["glpat", "glrt", "gldt"]);
                format!("{prefix}-{}", rng.chars(TOKEN, 20))
            };
            whole(class, text)
        }
        DataClass::SlackToken => match rng.below(3) {
            0 => {
                let (a, b) = (rng.range(10, 13), rng.range(10, 13));
                let text = format!(
                    "xoxb-{}-{}-{}",
                    rng.chars(DIGITS, a),
                    rng.chars(DIGITS, b),
                    rng.chars(ALNUM, 24)
                );
                whole(class, text)
            }
            1 => {
                let prefix = rng.pick(&["xoxp", "xoxa", "xoxr", "xoxs", "xoxe"]);
                let (a, b, c) = (rng.range(10, 13), rng.range(10, 13), rng.range(10, 13));
                let text = format!(
                    "{prefix}-{}-{}-{}-{}",
                    rng.chars(DIGITS, a),
                    rng.chars(DIGITS, b),
                    rng.chars(DIGITS, c),
                    rng.chars(HEX, 32)
                );
                whole(class, text)
            }
            _ => {
                let (a, b) = (rng.range(8, 11), rng.range(8, 11));
                let path = format!(
                    "T{}/B{}/{}",
                    rng.chars(UPPER_DIGIT, a),
                    rng.chars(UPPER_DIGIT, b),
                    rng.chars(ALNUM, 24)
                );
                Sample {
                    class,
                    text: format!("https://hooks.slack.com/services/{path}"),
                    secret: path,
                }
            }
        },
        DataClass::StripeKey => {
            let kind = rng.pick(&["sk", "rk"]);
            let mode = rng.pick(&["live", "test"]);
            let n = rng.range(24, 99);
            whole(class, format!("{kind}_{mode}_{}", rng.chars(ALNUM, n)))
        }
        DataClass::GoogleApiKey => whole(class, format!("AIza{}", rng.chars(TOKEN, 35))),
        DataClass::PrivateKey => whole(class, pem(rng, true)),
        DataClass::Jwt => {
            let header = match rng.below(3) {
                0 => "{\"alg\":\"HS256\",\"typ\":\"JWT\"}".to_owned(),
                1 => format!(
                    "{{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"{}\"}}",
                    rng.chars(HEX, 8)
                ),
                _ => "{\"typ\":\"JWT\",\"alg\":\"ES256\"}".to_owned(),
            };
            let iat = 1_700_000_000 + rng.below(100_000_000);
            let payload = format!(
                "{{\"sub\":\"{}\",\"name\":\"{}\",\"iat\":{iat},\"exp\":{}}}",
                rng.chars_in(DIGITS, 6, 12),
                rng.pick(WORDS),
                iat + 3600
            );
            let signature = rng.chars_of(TOKEN, &[43, 86, 342]);
            whole(
                class,
                format!(
                    "{}.{}.{signature}",
                    b64url(header.as_bytes()),
                    b64url(payload.as_bytes())
                ),
            )
        }
        DataClass::UrlCredentials => {
            let scheme = rng.pick(&[
                "postgres",
                "postgresql",
                "mysql",
                "mongodb",
                "mongodb+srv",
                "redis",
                "rediss",
                "amqp",
                "amqps",
                "https",
                "http",
                "ftp",
                "smtp",
                "sqlserver",
                "clickhouse",
            ]);
            let user = if scheme.starts_with("redis") && rng.chance(50) {
                String::new()
            } else {
                format!(
                    "{}{}",
                    rng.pick(&["app", "admin", "svc", "deploy", "root", "u"]),
                    rng.chars_in(DIGITS, 0, 2)
                )
            };
            let mut password = rng.chars_in(PASSWORD, 8, 32);
            if rng.chance(10) {
                let at = rng.range(1, password.len() - 1);
                password.insert(at, '@');
            }
            let host = rng.pick(&[
                "db.example.com",
                "localhost",
                "10.0.0.5",
                "[::1]",
                "cache.internal",
                "mq.example.org",
            ]);
            let port = if rng.chance(50) {
                format!(":{}", rng.range(1024, 65535))
            } else {
                String::new()
            };
            let path = rng.pick(&["", "/app_db", "/0", "/vhost", "/inbox?ssl=true"]);
            Sample {
                class,
                text: format!("{scheme}://{user}:{password}@{host}{port}{path}"),
                secret: password,
            }
        }
        other => unreachable!("no generator for {other}"),
    }
}

/// A PEM block: a private key when `private`, otherwise a public object of the same shape.
pub(crate) fn pem(rng: &mut Prng, private: bool) -> String {
    let label = if private {
        rng.pick(&[
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "PRIVATE KEY",
            "PGP PRIVATE KEY BLOCK",
        ])
    } else {
        rng.pick(&[
            "PUBLIC KEY",
            "RSA PUBLIC KEY",
            "CERTIFICATE",
            "CERTIFICATE REQUEST",
            "X509 CRL",
            "PGP PUBLIC KEY BLOCK",
        ])
    };
    let nl = if rng.chance(20) { "\r\n" } else { "\n" };
    let mut body = String::new();
    if label.starts_with("PGP") {
        body.push_str("Version: GnuPG v2");
        body.push_str(nl);
        body.push_str(nl);
    }
    for _ in 0..rng.range(3, 25) {
        body.push_str(&rng.chars(B64, 64));
        body.push_str(nl);
    }
    body.push_str(&rng.chars_in(B64, 4, 60));
    body.push_str(rng.pick(&["", "=", "=="]));
    format!("-----BEGIN {label}-----{nl}{body}{nl}-----END {label}-----")
}

/// A string that contains no secret of any claimed class, built to look as close to one as
/// possible.
#[allow(clippy::too_many_lines, reason = "one near-miss family per arm")]
pub(crate) fn negative(rng: &mut Prng) -> String {
    let core = match rng.below(40) {
        0..=5 => return prose(rng),
        6..=7 => code_line(rng),
        8 => format!("sk-ant-{}", rng.chars_in(TOKEN, 5, 31)),
        9 => format!("sk-{}", rng.chars_in(ALNUM, 20, 80)),
        10 => "sk-learn-pipeline-estimator-transformer-grid-search-cross-validation".to_owned(),
        11 => format!("{}{}", rng.pick(&["AKIA", "ASIA"]), rng.chars_of(BASE32, &[12, 15])),
        12 => format!(
            "{}{}{}",
            rng.pick(&["AKIA", "ASIA"]),
            rng.chars(BASE32, 16),
            rng.chars(ALNUM, 1)
        ),
        13 => format!("akia{}", rng.chars(BASE32, 16)),
        14 => format!("AKIB{}", rng.chars(BASE32, 16)),
        15 => format!("ghp_{}", rng.chars_of(ALNUM, &[20, 35])),
        16 => format!("ghp_{}", rng.chars(ALNUM, 37)),
        17 => format!("{}_{}", rng.pick(&["ghx", "GHP", "ghq"]), rng.chars(ALNUM, 36)),
        18 => format!("github_pat_{}", rng.chars(ALNUM, 30)),
        19 => format!("glpat-{}", rng.chars_in(TOKEN, 5, 19)),
        20 => format!("{}{}", rng.pick(&["glpat_", "glxat-"]), rng.chars(TOKEN, 20)),
        21 => format!("xoxb-{}", rng.chars_in(ALNUM, 5, 14)),
        22 => format!("{}{}", rng.pick(&["xoxz-", "xox-"]), rng.chars(ALNUM, 30)),
        23 => format!("sk_live_{}", rng.chars_in(ALNUM, 5, 23)),
        24 => format!("pk_live_{}", rng.chars_in(ALNUM, 24, 99)),
        25 => format!("sk_prod_{}", rng.chars(ALNUM, 30)),
        26 => format!("AIza{}", rng.chars_of(ALNUM, &[20, 34])),
        27 => format!("{}{}", rng.pick(&["aiza", "AIzb"]), rng.chars(TOKEN, 35)),
        28 => pem(rng, false),
        29 => format!("eyJ{}", rng.chars_in(TOKEN, 20, 60)),
        30 => format!("eyJ{}.eyJ{}", rng.chars(TOKEN, 20), rng.chars(TOKEN, 30)),
        31 => format!(
            "eyJ{}.eyJ{}.{}",
            rng.chars(TOKEN, 20),
            rng.chars(TOKEN, 30),
            rng.chars(TOKEN, 8)
        ),
        32 => format!(
            "eyJ{}.{}.{}",
            rng.chars(TOKEN, 20),
            rng.chars(TOKEN, 30),
            rng.chars(TOKEN, 43)
        ),
        33 => rng
            .pick(&[
                "https://example.com/path?x=1",
                "https://user@host.example.com/repo",
                "https://host.example.com:8443/x",
                "http://localhost:3000/@user/profile",
                "ssh://git@github.com/org/repo.git",
                "mailto:user@example.com",
                "postgres://user:@localhost/db",
                "https://registry.example.com/@scope/pkg:1.0@latest",
                "ftp://anonymous@ftp.example.com/pub",
            ])
            .to_owned(),
        34 => uuid(rng),
        35 => rng.chars_of(HEX, &[40, 64]),
        36 => rng.chars_in(B64, 16, 200),
        37 => rng.chars_in(UPPER_DIGIT, 10, 40),
        38 => {
            let n = rng.range(20, 200);
            (0..n)
                .map(|_| char::from(u8::try_from(rng.range(32, 126)).unwrap()))
                .collect()
        }
        _ => format!("the {} header starts with BEGIN PRIVATE KEY", rng.pick(WORDS)),
    };
    embed(rng, &core)
}

fn uuid(rng: &mut Prng) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        rng.chars(HEX, 8),
        rng.chars(HEX, 4),
        rng.chars(HEX, 4),
        rng.chars(HEX, 4),
        rng.chars(HEX, 12)
    )
}

fn code_line(rng: &mut Prng) -> String {
    let ident = rng.pick(&[
        "value",
        "config_path",
        "retryCount",
        "user_id",
        "digest",
        "version",
        "endpoint",
    ]);
    let value = match rng.below(8) {
        0 => rng.range(0, 1_000_000).to_string(),
        1 => format!("\"{}\"", rng.pick(WORDS)),
        2 => format!("\"{}\"", uuid(rng)),
        3 => format!("\"sha256:{}\"", rng.chars(HEX, 64)),
        4 => format!("\"{}\"", rng.chars_in(B64, 16, 88)),
        5 => "\"/usr/local/bin/uaos\"".to_owned(),
        6 => "\"https://docs.example.com/api#auth\"".to_owned(),
        _ => format!("\"{}.{}.{}\"", rng.below(10), rng.below(30), rng.below(100)),
    };
    format!("let {ident} = {value};")
}
