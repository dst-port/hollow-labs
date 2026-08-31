//! User Access from Unknown IP — `caution/`.
//!
//! Generated:
//!  - `/var/log/auth.log`: logins from a handful of known IPs (noise) + a
//!    connection to an internal resource from an address not in the history;
//!  - an `ss -tnp` snapshot with an established session to that address.
//!
//! The assessment (new legitimate user / compromised account / external
//! attacker) is chosen at random and is the Advanced answer.

use std::collections::BTreeMap;

use crate::question::{Level, Question};
use crate::rng::Rng;
use crate::scenario::gen::{clock, ephemeral_port, ipv4, pid, public_ip, syslog_ts};
use crate::scenario::{build_questions, Artifact, Category, GeneratedScenario, Generator};

const QUESTIONS: &str = include_str!("../../../data/scenarios/caution/unknown_ip.toml");

const HOST: &str = "hollow-bastion";

/// The situation assessment — the Advanced reference.
#[derive(Clone, Copy)]
enum Assessment {
    NewLegitUser,
    CompromisedAccount,
    ExternalAttacker,
}

impl Assessment {
    fn all() -> [Assessment; 3] {
        [
            Assessment::NewLegitUser,
            Assessment::CompromisedAccount,
            Assessment::ExternalAttacker,
        ]
    }

    fn answer(self) -> &'static str {
        match self {
            Assessment::NewLegitUser => "new legitimate user",
            Assessment::CompromisedAccount => "compromised account",
            Assessment::ExternalAttacker => "external attacker",
        }
    }
}

pub struct Type;

impl Generator for Type {
    fn id(&self) -> &'static str {
        "unknown_ip"
    }

    fn title(&self) -> &'static str {
        "User Access from Unknown IP"
    }

    fn category(&self) -> Category {
        Category::Caution
    }

    fn tools(&self) -> Vec<String> {
        [
            "/var/log/auth.log",
            "ss -tnp / netstat -tnp",
            "last / who",
            "grep 'Accepted' /var/log/auth.log | awk '{print $(NF-3)}' | sort -u",
            "compare the IP against the user's list of known addresses",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn generate(&self, rng: &mut Rng, level: Level) -> GeneratedScenario {
        // Real loopback connections are started by `crate::sandbox::Sandbox::activate`
        // for the whole Caution category (visible in `ss -tnp` / `lsof` by PID).
        let account = *rng
            .pick(&["k.sokolova", "admin", "j.smith", "devops", "n.ivanov"])
            .unwrap();

        // Internal resource behind the bastion: protocol, port, target IP and
        // the client process name in `ss` for the outbound hop.
        let (protocol, port, resource, client_proc) = *rng
            .pick(&[
                ("SSH", 22u16, "10.0.50.40", "ssh"),
                ("RDP", 3389, "10.0.50.55", "xfreerdp"),
                ("SMB", 445, "10.0.50.60", "smbclient"),
            ])
            .unwrap();

        let assessment = *rng.pick(&Assessment::all()).unwrap();

        // The user's known addresses — the office (/24) and one VPN address.
        let office_base = 0x0A00_1400; // 10.0.20.0/24
        let known_ips: Vec<String> = (0..3)
            .map(|_| ipv4(office_base | rng.range(2, 250) as u32))
            .collect();
        let vpn_ip = ipv4(0x0A08_0000 | rng.range(2, 250) as u32); // 10.8.0.x

        // The unknown address: for "new legitimate" — from the VPN pool,
        // otherwise external.
        let new_ip = match assessment {
            Assessment::NewLegitUser => vpn_ip.clone(),
            _ => public_ip(rng),
        };

        let conn_secs = match assessment {
            Assessment::ExternalAttacker => rng.range(0, 5 * 3600),
            _ => rng.range(8 * 3600, 20 * 3600),
        };

        let mut auth: Vec<(u64, String)> = Vec::new();

        // Noise: known logins of the account and its neighbours.
        for _ in 0..rng.range(8, 14) {
            let t = rng.range(0, 86_400);
            let ip = rng.pick(&known_ips).unwrap().clone();
            let who = *rng.pick(&[account, "backup", "monitor"]).unwrap();
            auth.push((
                t,
                format!(
                    "{} sshd[{}]: Accepted publickey for {} from {} port {} ssh2",
                    syslog_ts(t, HOST),
                    pid(rng),
                    who,
                    ip,
                    ephemeral_port(rng),
                ),
            ));
        }

        // Context for the assessment.
        match assessment {
            Assessment::NewLegitUser => {
                auth.push((
                    conn_secs.saturating_sub(200),
                    format!(
                        "{} useradd[{}]: new user: name={}-vpn, uid=1337, home=/home/{}",
                        syslog_ts(conn_secs.saturating_sub(200), HOST),
                        pid(rng),
                        account,
                        account,
                    ),
                ));
            }
            Assessment::ExternalAttacker => {
                for _ in 0..rng.range(4, 9) {
                    let t = conn_secs.saturating_sub(rng.range(30, 400));
                    auth.push((
                        t,
                        format!(
                            "{} sshd[{}]: Failed password for {} from {} port {} ssh2",
                            syslog_ts(t, HOST),
                            pid(rng),
                            account,
                            new_ip,
                            ephemeral_port(rng),
                        ),
                    ));
                }
            }
            Assessment::CompromisedAccount => {}
        }

        // Signal: a successful login from the unknown address.
        auth.push((
            conn_secs,
            format!(
                "{} sshd[{}]: Accepted password for {} from {} port {} ssh2",
                syslog_ts(conn_secs, HOST),
                pid(rng),
                account,
                new_ip,
                ephemeral_port(rng),
            ),
        ));

        auth.sort_by_key(|(t, _)| *t);
        let auth_log = auth
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");

        // ss -tnp taken on the bastion 10.0.50.10: inbound ssh sessions + one
        // outbound hop to the internal resource started by the unknown login.
        let mut ss = String::from(
            "State  Recv-Q Send-Q      Local Address:Port      Peer Address:Port   Process\n",
        );
        for ip in &known_ips {
            ss.push_str(&format!(
                "ESTAB  0      0           10.0.50.10:22          {ip}:{}   users:((\"sshd\",pid={}))\n",
                ephemeral_port(rng),
                pid(rng),
            ));
        }
        // Inbound session from the unknown address.
        ss.push_str(&format!(
            "ESTAB  0      0           10.0.50.10:22          {new_ip}:{}   users:((\"sshd\",pid={}))\n",
            ephemeral_port(rng),
            pid(rng),
        ));
        // Outbound hop bastion -> internal resource.
        ss.push_str(&format!(
            "ESTAB  0      0           10.0.50.10:{}        {resource}:{port}   users:((\"{client_proc}\",pid={}))\n",
            ephemeral_port(rng),
            pid(rng),
        ));

        let mut facts = BTreeMap::new();
        facts.insert("account".into(), account.to_string());
        facts.insert("new_ip".into(), new_ip.clone());
        facts.insert("resource".into(), resource.to_string());
        facts.insert("protocol".into(), protocol.to_string());
        facts.insert("port".into(), port.to_string());
        facts.insert("conn_time".into(), clock(conn_secs));
        facts.insert("assessment".into(), assessment.answer().to_string());
        facts.insert("verdict".into(), "anomalous IP".into());

        let artifacts = vec![
            Artifact::new("/var/log/auth.log", auth_log),
            Artifact::new("ss -tnp", ss),
        ];

        let questions: Vec<Question> = build_questions(QUESTIONS, &facts, level, rng)
            .expect("embedded unknown_ip.toml is valid");

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
                let auth = &s.artifacts[0].body;
                let ss = &s.artifacts[1].body;
                assert!(auth.contains(&s.facts["new_ip"]));
                assert!(ss.contains(&s.facts["new_ip"]));
                assert_eq!(s.facts["verdict"], "anomalous IP");
            }
        }
    }

    #[test]
    fn same_seed_same_output() {
        let g = Type;
        let mut a = Rng::new(21);
        let mut b = Rng::new(21);
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
