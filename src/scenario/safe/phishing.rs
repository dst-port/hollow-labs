//! Phishing Detection — `safe/`.
//!
//! Generated:
//!  - `/var/log/mail.log` (postfix): legitimate mail from known services
//!    (noise) + one or two phishing messages from the same IP;
//!  - `headers.txt` — parsed headers of the suspicious message
//!    (`From`, `Reply-To`, `Return-Path`, `Received`, `Subject`);
//!  - the technique is random: Typosquatting (look-alike domain in `From`),
//!    Spoofing (`From` matches the brand, but `Return-Path`/`Received` is a
//!    foreign domain), Homograph (substituted characters in `From`, real
//!    domain in punycode).
//!  - the real source domain, IP and technique are derived from the headers.

use std::collections::BTreeMap;

use crate::question::{Level, Question};
use crate::rng::Rng;
use crate::scenario::gen::{public_ip, syslog_ts};
use crate::scenario::{build_questions, Artifact, Category, GeneratedScenario, Generator};

const QUESTIONS: &str = include_str!("../../../data/scenarios/safe/phishing.toml");

/// The brand the phisher is impersonating.
#[derive(Clone, Copy)]
struct Brand {
    /// The brand's real domain (what the message claims to be).
    real: &'static str,
    /// Look-alike domain for typosquatting.
    typo: &'static str,
    /// Punycode domain for the homograph attack.
    homograph: &'static str,
}

const BRANDS: [Brand; 4] = [
    Brand {
        real: "paypal.com",
        typo: "paypa1.com",
        homograph: "xn--pypal-9if.com",
    },
    Brand {
        real: "google.com",
        typo: "g00gle.com",
        homograph: "xn--gogle-jua.com",
    },
    Brand {
        real: "microsoft.com",
        typo: "micros0ft-support.com",
        homograph: "xn--micrsoft-r8a.com",
    },
    Brand {
        real: "apple.com",
        typo: "app1e-id.com",
        homograph: "xn--aple-0va.com",
    },
];

/// Sender-forgery technique — the reference answer for the Advanced question.
#[derive(Clone, Copy)]
enum Technique {
    Typosquatting,
    Spoofing,
    Homograph,
}

impl Technique {
    fn all() -> [Technique; 3] {
        [
            Technique::Typosquatting,
            Technique::Spoofing,
            Technique::Homograph,
        ]
    }

    fn answer(self) -> &'static str {
        match self {
            Technique::Typosquatting => "Typosquatting",
            Technique::Spoofing => "Spoofing",
            Technique::Homograph => "Homograph",
        }
    }

    /// Short synonym — accepted alongside (for its own technique only).
    fn alt(self) -> &'static str {
        match self {
            Technique::Typosquatting => "typosquat",
            Technique::Spoofing => "spoof",
            Technique::Homograph => "homoglyph",
        }
    }
}

/// "Infrastructure" domains that spoofed mail actually goes out from.
const RELAY_DOMAINS: [&str; 4] = [
    "mail.cheap-vps.ru",
    "smtp.bulk-sender.net",
    "mx.compromised-host.org",
    "relay.unknown-cloud.io",
];

pub struct Phishing;

impl Generator for Phishing {
    fn id(&self) -> &'static str {
        "phishing"
    }

    fn title(&self) -> &'static str {
        "Phishing Detection"
    }

    fn category(&self) -> Category {
        Category::Safe
    }

    fn tools(&self) -> Vec<String> {
        [
            "/var/log/mail.log",
            "grep -E \"from=<|client=|message-id=\" /var/log/mail.log",
            "From / Reply-To / Return-Path / Received headers",
            "read Received: bottom to top — the first hop is the source",
            "whois / dig on the domain from Return-Path",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn generate(&self, rng: &mut Rng, level: Level) -> GeneratedScenario {
        let brand = *rng.pick(&BRANDS).unwrap();
        let technique = *rng.pick(&Technique::all()).unwrap();
        let relay = *rng.pick(&RELAY_DOMAINS).unwrap();
        let sender_ip = public_ip(rng);
        let subject = *rng
            .pick(&[
                "Your account has been limited - verify now",
                "Unusual sign-in attempt detected",
                "Payment confirmation required within 24h",
                "Action needed: confirm your billing details",
            ])
            .unwrap();

        // The From domain (what the analyst sees), the real source domain and
        // the sending MTA host (what appears in Received and mail.log).
        let (from_domain, real_domain, sender_mta) = match technique {
            Technique::Typosquatting => (brand.typo, brand.typo, format!("mail.{}", brand.typo)),
            Technique::Spoofing => (brand.real, relay, relay.to_string()),
            Technique::Homograph => (
                brand.homograph,
                brand.homograph,
                format!("mail.{}", brand.homograph),
            ),
        };

        let host = "hollow-mx";
        let mut mail: Vec<(u64, String)> = Vec::new();

        // Noise: legitimate mail from known services, Return-Path matches From.
        let legit = [
            (
                "notifications@github.com",
                "198.51.100.23",
                "mail-legit.github.com",
            ),
            ("no-reply@slack.com", "192.0.2.44", "mail.slack.com"),
            ("team@atlassian.com", "203.0.113.9", "mx.atlassian.com"),
            ("receipts@stripe.com", "198.51.100.77", "mail.stripe.com"),
        ];
        let noise = rng.range(10, 18);
        for i in 0..noise {
            let t = rng.range(0, 800);
            let (addr, ip, mx) = legit[rng.below(legit.len() as u64) as usize];
            let qid = format!("{:05X}", rng.range(0x10000, 0xFFFFF));
            mail.push((
                t,
                format!(
                    "{ts} {host} postfix/smtpd[{pid}]: {qid}: client={mx}[{ip}]",
                    ts = syslog_ts(t, host),
                    pid = 2000 + i
                ),
            ));
            mail.push((
                t + 1,
                format!(
                    "{ts} {host} postfix/qmgr[1980]: {qid}: from=<{addr}>, size={sz}, nrcpt=1 (queue active)",
                    ts = syslog_ts(t + 1, host),
                    sz = rng.range(1800, 9000)
                ),
            ));
        }

        // Phishing: one or two messages from a single IP.
        let attack_hits = rng.range(1, 2);
        let attack_start = rng.range(800, 1000);
        for i in 0..attack_hits {
            let t = attack_start + i * rng.range(40, 120);
            let qid = format!("{:05X}", rng.range(0x10000, 0xFFFFF));
            mail.push((
                t,
                format!(
                    "{ts} {host} postfix/smtpd[{pid}]: {qid}: client={sender_mta}[{sender_ip}]",
                    ts = syslog_ts(t, host),
                    pid = 2500 + i
                ),
            ));
            mail.push((
                t + 1,
                format!(
                    "{ts} {host} postfix/qmgr[1980]: {qid}: from=<service@{from_domain}>, size={sz}, nrcpt=1 (queue active)",
                    ts = syslog_ts(t + 1, host),
                    sz = rng.range(3200, 7000)
                ),
            ));
        }

        mail.sort_by_key(|(t, _)| *t);
        let mail_log = mail
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");

        // Parsed headers of the suspicious message.
        let reply_to = match technique {
            Technique::Spoofing => format!("refunds@{}", brand.typo),
            _ => format!("no-reply@{from_domain}"),
        };
        let headers = format!(
            "From: \"{brand_title} Service\" <service@{from_domain}>\n\
             Reply-To: <{reply_to}>\n\
             Return-Path: <bounce@{real_domain}>\n\
             Received: from {sender_mta} ({sender_mta} [{sender_ip}])\n\
             \tby {host} (Postfix) with ESMTPS id A17C4\n\
             \tfor <analyst@hollow-corp.net>; Mon, 31 Aug 2026 {clk} +0000\n\
             Authentication-Results: {host}; spf=fail smtp.mailfrom={real_domain};\n\
             \tdkim=none; dmarc=fail header.from={from_domain}\n\
             Subject: {subject}\n",
            brand_title = brand.real.split('.').next().unwrap(),
            clk = crate::scenario::gen::clock(attack_start),
        );

        let mut facts = BTreeMap::new();
        facts.insert("spoofed_domain".into(), brand.real.to_string());
        facts.insert("from_domain".into(), from_domain.to_string());
        facts.insert("real_domain".into(), real_domain.to_string());
        facts.insert("sender_ip".into(), sender_ip.clone());
        facts.insert("phish_technique".into(), technique.answer().to_string());
        facts.insert("phish_technique_alt".into(), technique.alt().to_string());
        facts.insert("attack_hits".into(), attack_hits.to_string());
        facts.insert("verdict".into(), "Phishing".to_string());

        let artifacts = vec![
            Artifact::new("/var/log/mail.log", mail_log),
            Artifact::new("/var/mail/analyst/headers.txt", headers),
        ];

        let questions: Vec<Question> = build_questions(QUESTIONS, &facts, level, rng)
            .expect("embedded phishing.toml is valid");

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_expected_shape() {
        let g = Phishing;
        for seed in 0..30 {
            for level in Level::ALL {
                let mut rng = Rng::new(seed);
                let s = g.generate(&mut rng, level);
                assert_eq!(s.category, Category::Safe);
                assert!(!s.questions.is_empty());
                assert!(s.artifacts.iter().any(|a| a.name.ends_with("mail.log")));
                assert!(s.facts.contains_key("real_domain"));
                assert!(s.facts.contains_key("phish_technique"));
                let headers = &s.artifacts[1].body;
                // The real source domain and IP really are in the headers.
                assert!(headers.contains(s.facts["real_domain"].as_str()));
                assert!(headers.contains(s.facts["sender_ip"].as_str()));
                assert!(s.artifacts[0].body.contains(s.facts["sender_ip"].as_str()));
            }
        }
    }

    #[test]
    fn same_seed_same_output() {
        let g = Phishing;
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
