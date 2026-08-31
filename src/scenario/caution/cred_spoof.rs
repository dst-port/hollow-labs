//! Credential Spoofing Detection — `caution/`.
//!
//! Generated:
//!  - `/var/log/auth.log`: legitimate logins of one user from a corporate IP
//!    (noise) + a login with VALID credentials but from an anomalous IP / at an
//!    anomalous time / with a client change;
//!  - a `last`-style session summary.
//!
//! The anomaly type is chosen at random and is the Advanced answer.

use std::collections::BTreeMap;

use crate::question::{Level, Question};
use crate::rng::Rng;
use crate::scenario::gen::{clock, ephemeral_port, pid, private_ip, public_ip, syslog_ts};
use crate::scenario::{build_questions, Artifact, Category, GeneratedScenario, Generator};

const QUESTIONS: &str = include_str!("../../../data/scenarios/caution/cred_spoof.toml");

const HOST: &str = "hollow-01";
const NOISE_USERS: [&str; 4] = ["deploy", "backup", "monitor", "root"];

/// Kinds of anomaly that point to credential spoofing.
#[derive(Clone, Copy)]
enum Anomaly {
    /// Login from an external (non-corporate) IP.
    ForeignIp,
    /// Two successful logins from different IPs within a couple of minutes —
    /// "impossible travel".
    ImpossibleTravel,
    /// Login at an uncharacteristic night-time hour.
    OddHour,
    /// Client/device change (different SSH client, new key).
    ClientChange,
}

impl Anomaly {
    fn all() -> [Anomaly; 4] {
        [
            Anomaly::ForeignIp,
            Anomaly::ImpossibleTravel,
            Anomaly::OddHour,
            Anomaly::ClientChange,
        ]
    }

    /// Short description — the Advanced reference, matches the wording of the
    /// question options verbatim.
    fn answer(self) -> &'static str {
        match self {
            Anomaly::ForeignIp => "external IP",
            Anomaly::ImpossibleTravel => "impossible travel",
            Anomaly::OddHour => "odd hour",
            Anomaly::ClientChange => "client change",
        }
    }
}

pub struct Type;

impl Generator for Type {
    fn id(&self) -> &'static str {
        "cred_spoof"
    }

    fn title(&self) -> &'static str {
        "Credential Spoofing Detection"
    }

    fn category(&self) -> Category {
        Category::Caution
    }

    fn tools(&self) -> Vec<String> {
        [
            "/var/log/auth.log",
            "/var/log/secure",
            "last / lastb / who",
            "grep -E \"Accepted|Failed\" /var/log/auth.log",
            "awk '{print $(NF-3)}' — pull out the source IP",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn generate(&self, rng: &mut Rng, level: Level) -> GeneratedScenario {
        // The auth.log artifact is materialized to disk; loopback sockets and
        // decoy reads are started by `crate::sandbox::Sandbox::activate` (Caution).
        let user = *rng
            .pick(&["analyst", "jkowalski", "svc_ci", "a.petrov", "ops"])
            .unwrap();
        let corp_ip = private_ip(rng);
        let anomaly = *rng.pick(&Anomaly::all()).unwrap();

        // Previous IP for "impossible travel".
        let prev_ip = public_ip(rng);
        // Address of the anomalous login: for IP anomalies — external; for the
        // "time" and "client" anomalies the IP must not stand out but must also
        // differ from the usual workstation — pick a different internal address.
        let spoof_ip = match anomaly {
            Anomaly::ForeignIp | Anomaly::ImpossibleTravel => public_ip(rng),
            Anomaly::OddHour | Anomaly::ClientChange => {
                let mut ip = private_ip(rng);
                while ip == corp_ip {
                    ip = private_ip(rng);
                }
                ip
            }
        };

        // Anomalous time: night for OddHour, a work day otherwise.
        let spoof_secs = match anomaly {
            Anomaly::OddHour => rng.range(2 * 3600, 4 * 3600),
            _ => rng.range(9 * 3600, 18 * 3600),
        };

        let mut lines: Vec<(u64, String)> = Vec::new();

        // Noise: legitimate logins of the target user from the corporate IP.
        let legit = rng.range(6, 11);
        for _ in 0..legit {
            let t = rng.range(8 * 3600, 19 * 3600);
            lines.push((
                t,
                format!(
                    "{} sshd[{}]: Accepted publickey for {} from {} port {} ssh2: RSA SHA256:c0rp{}",
                    syslog_ts(t, HOST),
                    pid(rng),
                    user,
                    corp_ip,
                    ephemeral_port(rng),
                    rng.range(10, 99),
                ),
            ));
        }
        // Noise: other service accounts + a couple of failed attempts.
        for _ in 0..rng.range(5, 9) {
            let t = rng.range(0, 86_400);
            let nu = *rng.pick(&NOISE_USERS).unwrap();
            let ok = rng.chance(0.7);
            lines.push((
                t,
                format!(
                    "{} sshd[{}]: {} for {} from {} port {} ssh2",
                    syslog_ts(t, HOST),
                    pid(rng),
                    if ok {
                        "Accepted publickey"
                    } else {
                        "Failed password"
                    },
                    nu,
                    private_ip(rng),
                    ephemeral_port(rng),
                ),
            ));
        }

        // Signal: the anomalous login(s).
        match anomaly {
            Anomaly::ImpossibleTravel => {
                lines.push((
                    spoof_secs.saturating_sub(120),
                    format!(
                        "{} sshd[{}]: Accepted password for {} from {} port {} ssh2",
                        syslog_ts(spoof_secs - 120, HOST),
                        pid(rng),
                        user,
                        prev_ip,
                        ephemeral_port(rng),
                    ),
                ));
                lines.push((
                    spoof_secs,
                    format!(
                        "{} sshd[{}]: Accepted password for {} from {} port {} ssh2",
                        syslog_ts(spoof_secs, HOST),
                        pid(rng),
                        user,
                        spoof_ip,
                        ephemeral_port(rng),
                    ),
                ));
            }
            Anomaly::ClientChange => {
                lines.push((
                    spoof_secs,
                    format!(
                        "{} sshd[{}]: Accepted password for {} from {} port {} ssh2: \
                         new client PuTTY-Release-0.78 (was OpenSSH_9.6)",
                        syslog_ts(spoof_secs, HOST),
                        pid(rng),
                        user,
                        spoof_ip,
                        ephemeral_port(rng),
                    ),
                ));
            }
            _ => {
                lines.push((
                    spoof_secs,
                    format!(
                        "{} sshd[{}]: Accepted password for {} from {} port {} ssh2",
                        syslog_ts(spoof_secs, HOST),
                        pid(rng),
                        user,
                        spoof_ip,
                        ephemeral_port(rng),
                    ),
                ));
            }
        }

        lines.sort_by_key(|(t, _)| *t);
        let auth_log = lines
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");

        // last-style summary.
        let mut last = String::new();
        last.push_str(&format!(
            "{user:<12} pts/0        {corp_ip:<15} still logged in\n"
        ));
        if matches!(anomaly, Anomaly::ImpossibleTravel) {
            last.push_str(&format!(
                "{user:<12} pts/2        {prev_ip:<15} {}   00:01\n",
                clock(spoof_secs - 120)
            ));
        }
        last.push_str(&format!(
            "{user:<12} pts/1        {spoof_ip:<15} {}   00:14\n",
            clock(spoof_secs)
        ));

        let spoof_time = clock(spoof_secs);

        let mut facts = BTreeMap::new();
        facts.insert("user".into(), user.to_string());
        facts.insert("corp_ip".into(), corp_ip.clone());
        facts.insert("spoof_ip".into(), spoof_ip.clone());
        facts.insert("spoof_time".into(), spoof_time.clone());
        facts.insert("anomaly".into(), anomaly.answer().to_string());
        facts.insert("verdict".into(), "spoofing".into());

        let artifacts = vec![
            Artifact::new("/var/log/auth.log", auth_log),
            Artifact::new("last -Fai", last),
        ];

        let questions: Vec<Question> = build_questions(QUESTIONS, &facts, level, rng)
            .expect("embedded cred_spoof.toml is valid");

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
        let g = Type;
        for seed in 0..40 {
            for level in Level::ALL {
                let mut rng = Rng::new(seed);
                let s = g.generate(&mut rng, level);
                assert_eq!(s.category, Category::Caution);
                assert!(!s.questions.is_empty());
                assert!(s.artifacts.iter().any(|a| a.name.ends_with("auth.log")));
                let spoof_ip = &s.facts["spoof_ip"];
                assert!(
                    s.artifacts[0].body.contains(spoof_ip),
                    "the anomalous IP must be in auth.log"
                );
                assert_eq!(s.facts["verdict"], "spoofing");
            }
        }
    }

    #[test]
    fn same_seed_same_output() {
        let g = Type;
        let mut a = Rng::new(99);
        let mut b = Rng::new(99);
        let sa = g.generate(&mut a, Level::Intermediate);
        let sb = g.generate(&mut b, Level::Intermediate);
        assert_eq!(sa.facts, sb.facts);
        assert_eq!(
            sa.artifacts.iter().map(|x| &x.body).collect::<Vec<_>>(),
            sb.artifacts.iter().map(|x| &x.body).collect::<Vec<_>>()
        );
        assert_eq!(
            sa.questions.iter().map(|q| &q.prompt).collect::<Vec<_>>(),
            sb.questions.iter().map(|q| &q.prompt).collect::<Vec<_>>()
        );
    }
}
