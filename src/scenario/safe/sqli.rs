//! SQLi Detection — `safe/`.
//!
//! Generated:
//!  - a web-server log with legitimate requests (noise): lookups by numeric id,
//!    catalogue browsing, static assets;
//!  - an interleaved series of SQL injections against ONE parameter of one
//!    endpoint from a single external IP; the injection type is random
//!    (Union / Boolean / Error-based) and visible right in the log payloads;
//!  - the correct answers (IP, parameter, type, hit count) are derived from the
//!    generated `access.log`, not stored separately.

use std::collections::BTreeMap;

use crate::question::{Level, Question};
use crate::rng::Rng;
use crate::scenario::gen::{browser_ua, nginx_ts, public_ip, tool_ua};
use crate::scenario::{build_questions, Artifact, Category, GeneratedScenario, Generator};

const QUESTIONS: &str = include_str!("../../../data/scenarios/safe/sqli.toml");

/// SQL injection type — decides the payload and the correct Advanced answer.
#[derive(Clone, Copy)]
enum SqliKind {
    Union,
    Boolean,
    Error,
}

impl SqliKind {
    fn all() -> [SqliKind; 3] {
        [SqliKind::Union, SqliKind::Boolean, SqliKind::Error]
    }

    /// Human-readable type — the reference answer.
    fn answer(self) -> &'static str {
        match self {
            SqliKind::Union => "Union-based",
            SqliKind::Boolean => "Boolean-based",
            SqliKind::Error => "Error-based",
        }
    }

    /// Short form — accepted alongside the full one (for its own type only).
    fn short(self) -> &'static str {
        match self {
            SqliKind::Union => "union",
            SqliKind::Boolean => "boolean",
            SqliKind::Error => "error",
        }
    }

    /// Query string with an injection into parameter `param`.
    fn payload(self, param: &str) -> String {
        match self {
            SqliKind::Union => {
                format!("{param}=-1 UNION SELECT username,password,email FROM users--")
            }
            SqliKind::Boolean => format!("{param}=1' OR '1'='1' -- -"),
            SqliKind::Error => {
                format!("{param}=1' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -")
            }
        }
    }

    /// HTTP status the server returns for such a payload.
    fn status(self, rng: &mut Rng) -> u16 {
        match self {
            // Error-based usually crashes the request into a 500.
            SqliKind::Error => 500,
            // Union/Boolean — either passes (200) or is cut by a WAF (403).
            _ => *rng.pick(&[200u16, 200, 403]).unwrap(),
        }
    }
}

pub struct Sqli;

impl Generator for Sqli {
    fn id(&self) -> &'static str {
        "sqli"
    }

    fn title(&self) -> &'static str {
        "SQLi Detection"
    }

    fn category(&self) -> Category {
        Category::Safe
    }

    fn tools(&self) -> Vec<String> {
        [
            "/var/log/nginx/access.log",
            "/var/log/apache2/access.log",
            "grep -Ei \"union|select|' or |-- |extractvalue|sleep\\(\" access.log",
            "awk -F'\\\"' '{print $2}' access.log | sort | uniq -c | sort -rn",
            "cut -d' ' -f1 access.log | sort | uniq -c | sort -rn",
            "less / tail -f",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn generate(&self, rng: &mut Rng, level: Level) -> GeneratedScenario {
        let endpoint = *rng
            .pick(&[
                "/products.php",
                "/news.php",
                "/profile.php",
                "/catalog.php",
                "/article.php",
            ])
            .unwrap();
        let param = *rng
            .pick(&["id", "user_id", "search", "category", "page"])
            .unwrap();
        let kind = *rng.pick(&SqliKind::all()).unwrap();
        let attacker_ip = public_ip(rng);

        let mut lines: Vec<(u64, String)> = Vec::new();

        // Noise: legitimate lookups by numeric values of the same parameter +
        // static assets and section browsing.
        let noise = rng.range(30, 48);
        for _ in 0..noise {
            let t = rng.range(0, 900);
            let ip = public_ip(rng);
            let q = match rng.below(3) {
                0 => format!("{endpoint}?{param}={}", rng.range(1, 4000)),
                1 => "/static/app.css".to_string(),
                _ => "/index.php".to_string(),
            };
            lines.push((t, access_line(&ip, t, "GET", &q, 200, browser_ua(rng), rng)));
        }

        // Attack: a series of injections from one IP in a short window.
        let attack_hits = rng.range(8, 19);
        let attack_start = rng.range(900, 1100);
        for i in 0..attack_hits {
            let t = attack_start + i * rng.range(2, 9);
            let q = format!("{endpoint}?{}", kind.payload(param));
            lines.push((
                t,
                access_line(
                    &attacker_ip,
                    t,
                    "GET",
                    &q,
                    kind.status(rng),
                    tool_ua(rng),
                    rng,
                ),
            ));
        }

        lines.sort_by_key(|(t, _)| *t);
        let access_log = lines
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");

        let mut facts = BTreeMap::new();
        facts.insert("endpoint".into(), endpoint.to_string());
        facts.insert("param".into(), param.to_string());
        facts.insert("attacker_ip".into(), attacker_ip.clone());
        facts.insert("sqli_type".into(), kind.answer().to_string());
        facts.insert("sqli_type_short".into(), kind.short().to_string());
        facts.insert("attack_hits".into(), attack_hits.to_string());
        facts.insert("verdict".into(), "SQLi".to_string());

        let artifacts = vec![Artifact::new("/var/log/nginx/access.log", access_log)];

        let questions: Vec<Question> =
            build_questions(QUESTIONS, &facts, level, rng).expect("embedded sqli.toml is valid");

        GeneratedScenario {
            id: self.id().into(),
            title: self.title().into(),
            category: self.category(),
            tools: self.tools(),
            facts,
            artifacts,
            questions,
        }
    }
}

/// An access.log line in nginx combined format.
fn access_line(
    ip: &str,
    t: u64,
    method: &str,
    path: &str,
    status: u16,
    ua: &str,
    rng: &mut Rng,
) -> String {
    let bytes = rng.range(180, 6000);
    format!(
        "{ip} - - {ts} \"{method} {path} HTTP/1.1\" {status} {bytes} \"-\" \"{ua}\"",
        ts = nginx_ts(t)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_expected_shape() {
        let g = Sqli;
        for seed in 0..30 {
            for level in Level::ALL {
                let mut rng = Rng::new(seed);
                let s = g.generate(&mut rng, level);
                assert_eq!(s.category, Category::Safe);
                assert!(!s.questions.is_empty());
                assert!(s.artifacts.iter().any(|a| a.name.ends_with("access.log")));
                assert!(s.facts.contains_key("attacker_ip"));
                assert!(s.facts.contains_key("param"));
                // The payload really is in the log — the answer is derived from the artifact.
                let log = &s.artifacts[0].body;
                assert!(log.contains(s.facts["param"].as_str()));
                assert!(log.contains(s.facts["attacker_ip"].as_str()));
            }
        }
    }

    #[test]
    fn same_seed_same_output() {
        let g = Sqli;
        let mut a = Rng::new(99);
        let mut b = Rng::new(99);
        let sa = g.generate(&mut a, Level::Intermediate);
        let sb = g.generate(&mut b, Level::Intermediate);
        assert_eq!(sa.facts, sb.facts);
        assert_eq!(
            sa.artifacts.iter().map(|x| &x.body).collect::<Vec<_>>(),
            sb.artifacts.iter().map(|x| &x.body).collect::<Vec<_>>()
        );
    }
}
