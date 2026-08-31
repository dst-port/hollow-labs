//! CSRF Detection — `safe/`.
//!
//! Generated:
//!  - a web-server `access.log`: legitimate POSTs to a sensitive endpoint from
//!    the same origin as the app (noise);
//!  - a series of cross-site POST requests from one external IP and a foreign
//!    origin WITHOUT a CSRF token — the server accepted them (HTTP 200);
//!  - the app's `security.log`: each request records the origin, whether a
//!    csrf token was present, and the outcome — this shows why the request
//!    went through;
//!  - the reason the server let the token-less request through is random from
//!    a pool of misconfigurations.

use std::collections::BTreeMap;

use crate::question::{Level, Question};
use crate::rng::Rng;
use crate::scenario::gen::{browser_ua, clock, nginx_ts, public_ip, tool_ua};
use crate::scenario::{build_questions, Artifact, Category, GeneratedScenario, Generator};

const QUESTIONS: &str = include_str!("../../../data/scenarios/safe/csrf.toml");

/// The misconfiguration that let a token-less cross-site POST be accepted.
#[derive(Clone, Copy)]
enum Flaw {
    TokenCheckDisabled,
    EndpointUnprotected,
    OriginNotChecked,
}

impl Flaw {
    fn all() -> [Flaw; 3] {
        [
            Flaw::TokenCheckDisabled,
            Flaw::EndpointUnprotected,
            Flaw::OriginNotChecked,
        ]
    }

    /// Short canonical token — the reference answer for the Advanced question
    /// (matched against the `reason=` field in security.log via [`Flaw::tag`]).
    fn answer(self) -> &'static str {
        match self {
            Flaw::TokenCheckDisabled => "token",
            Flaw::EndpointUnprotected => "endpoint",
            Flaw::OriginNotChecked => "origin",
        }
    }

    /// How it looks in the `security.log` line (`reason=` field for accepted
    /// cross-site requests).
    fn tag(self) -> &'static str {
        match self {
            Flaw::TokenCheckDisabled => "csrf_check=off",
            Flaw::EndpointUnprotected => "route_not_protected",
            Flaw::OriginNotChecked => "origin_check=skip",
        }
    }
}

pub struct Csrf;

impl Generator for Csrf {
    fn id(&self) -> &'static str {
        "csrf"
    }

    fn title(&self) -> &'static str {
        "CSRF Detection"
    }

    fn category(&self) -> Category {
        Category::Safe
    }

    fn tools(&self) -> Vec<String> {
        [
            "/var/log/nginx/access.log",
            "/var/log/webapp/security.log",
            "grep -E \"POST /account/(transfer|settings|password|email)\" access.log",
            "grep -E \"origin=|csrf_token=|reason=\" security.log",
            "Referer / Origin headers in the combined log",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn generate(&self, rng: &mut Rng, level: Level) -> GeneratedScenario {
        let endpoint = *rng
            .pick(&[
                "/account/transfer",
                "/account/settings",
                "/account/password",
                "/account/email",
            ])
            .unwrap();
        let legit_origin = "https://app.hollow-corp.net";
        let attacker_origin = *rng
            .pick(&[
                "http://free-prize-draw.net",
                "http://cdn-analytics.co",
                "http://secure-login-verify.com",
                "http://coupons-daily.io",
            ])
            .unwrap();
        let flaw = *rng.pick(&Flaw::all()).unwrap();
        let attacker_ip = public_ip(rng);

        let mut access: Vec<(u64, String)> = Vec::new();
        let mut sec: Vec<(u64, String)> = Vec::new();

        // Noise: legitimate POSTs with a valid token and their own origin + normal GETs.
        let noise = rng.range(24, 40);
        for _ in 0..noise {
            let t = rng.range(0, 900);
            let ip = public_ip(rng);
            if rng.chance(0.4) {
                access.push((
                    t,
                    access_line(
                        &ip,
                        t,
                        "POST",
                        endpoint,
                        200,
                        legit_origin,
                        browser_ua(rng),
                        rng,
                    ),
                ));
                sec.push((
                    t,
                    sec_line(t, "POST", endpoint, legit_origin, "present", "accept", "ok"),
                ));
            } else {
                access.push((
                    t,
                    access_line(
                        &ip,
                        t,
                        "GET",
                        "/dashboard",
                        200,
                        legit_origin,
                        browser_ua(rng),
                        rng,
                    ),
                ));
            }
        }

        // Attack: token-less cross-site POSTs from one IP, all accepted.
        let attack_hits = rng.range(4, 10);
        let attack_start = rng.range(900, 1100);
        for i in 0..attack_hits {
            let t = attack_start + i * rng.range(3, 12);
            access.push((
                t,
                access_line(
                    &attacker_ip,
                    t,
                    "POST",
                    endpoint,
                    200,
                    attacker_origin,
                    tool_ua(rng),
                    rng,
                ),
            ));
            sec.push((
                t,
                sec_line(
                    t,
                    "POST",
                    endpoint,
                    attacker_origin,
                    "absent",
                    "accept",
                    flaw.tag(),
                ),
            ));
        }

        access.sort_by_key(|(t, _)| *t);
        sec.sort_by_key(|(t, _)| *t);
        let access_log = access
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");
        let security_log = sec
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");

        let mut facts = BTreeMap::new();
        facts.insert("endpoint".into(), endpoint.to_string());
        facts.insert("attacker_ip".into(), attacker_ip.clone());
        facts.insert("attacker_origin".into(), attacker_origin.to_string());
        facts.insert("legit_origin".into(), legit_origin.to_string());
        facts.insert("csrf_reason".into(), flaw.answer().to_string());
        facts.insert("csrf_reason_tag".into(), flaw.tag().to_string());
        facts.insert("attack_hits".into(), attack_hits.to_string());
        facts.insert("verdict".into(), "CSRF".to_string());

        let artifacts = vec![
            Artifact::new("/var/log/nginx/access.log", access_log),
            Artifact::new("/var/log/webapp/security.log", security_log),
        ];

        let questions: Vec<Question> =
            build_questions(QUESTIONS, &facts, level, rng).expect("embedded csrf.toml is valid");

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

/// An access.log line in nginx combined format (Referer = request origin).
#[allow(clippy::too_many_arguments)]
fn access_line(
    ip: &str,
    t: u64,
    method: &str,
    path: &str,
    status: u16,
    referer: &str,
    ua: &str,
    rng: &mut Rng,
) -> String {
    let bytes = rng.range(120, 900);
    format!(
        "{ip} - - {ts} \"{method} {path} HTTP/1.1\" {status} {bytes} \"{referer}/\" \"{ua}\"",
        ts = nginx_ts(t)
    )
}

/// A line in the app's security.log.
fn sec_line(
    t: u64,
    method: &str,
    path: &str,
    origin: &str,
    csrf_token: &str,
    result: &str,
    reason: &str,
) -> String {
    format!(
        "2026-08-31T{clk}Z webapp csrf: {method} {path} origin={origin} csrf_token={csrf_token} decision={result} reason={reason}",
        clk = clock(t)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_expected_shape() {
        let g = Csrf;
        for seed in 0..30 {
            for level in Level::ALL {
                let mut rng = Rng::new(seed);
                let s = g.generate(&mut rng, level);
                assert_eq!(s.category, Category::Safe);
                assert!(!s.questions.is_empty());
                assert!(s.artifacts.iter().any(|a| a.name.ends_with("access.log")));
                assert!(s.artifacts.iter().any(|a| a.name.ends_with("security.log")));
                assert!(s.facts.contains_key("attacker_origin"));
                let sec = &s.artifacts[1].body;
                // Token-less cross-site requests really are present in the log.
                assert!(sec.contains("csrf_token=absent"));
                assert!(sec.contains(s.facts["attacker_origin"].as_str()));
            }
        }
    }

    #[test]
    fn same_seed_same_output() {
        let g = Csrf;
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
