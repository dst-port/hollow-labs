//! Internal Breaches Detection — `caution/`.
//!
//! Generated:
//!  - `/var/log/auth.log`: normal activity of internal accounts (noise) + a
//!    user reaching beyond their privileges (lateral movement);
//!  - `/var/log/audit/audit.log`: access to a restricted resource.
//!
//! The method (privilege escalation / credential reuse / misconfigured
//! permissions) is chosen at random and is the Advanced answer.

use std::collections::BTreeMap;

use crate::question::{Level, Question};
use crate::rng::Rng;
use crate::scenario::gen::{ephemeral_port, ipv4, pid, private_ip, syslog_ts};
use crate::scenario::{build_questions, Artifact, Category, GeneratedScenario, Generator};

const QUESTIONS: &str = include_str!("../../../data/scenarios/caution/internal_breach.toml");

const HOST: &str = "hollow-app01";
/// Nominal "run midnight" in epoch seconds for audit.log lines.
const EPOCH_BASE: u64 = 1_788_998_400;

fn audit_ts(secs: u64, event: u32) -> String {
    format!("audit({}.{:03}:{})", EPOCH_BASE + secs, secs % 1000, event)
}

/// The unauthorized-access method — the Advanced reference.
#[derive(Clone, Copy)]
enum Method {
    PrivEsc,
    CredReuse,
    MisconfiguredPerms,
}

impl Method {
    fn all() -> [Method; 3] {
        [
            Method::PrivEsc,
            Method::CredReuse,
            Method::MisconfiguredPerms,
        ]
    }

    fn answer(self) -> &'static str {
        match self {
            Method::PrivEsc => "privilege escalation",
            Method::CredReuse => "credential reuse",
            Method::MisconfiguredPerms => "misconfigured permissions",
        }
    }
}

pub struct Type;

impl Generator for Type {
    fn id(&self) -> &'static str {
        "internal_breach"
    }

    fn title(&self) -> &'static str {
        "Internal Breaches Detection"
    }

    fn category(&self) -> Category {
        Category::Caution
    }

    fn tools(&self) -> Vec<String> {
        [
            "/var/log/auth.log",
            "/var/log/audit/audit.log",
            "grep -E \"sudo|COMMAND=|session opened\" /var/log/auth.log",
            "ausearch -k restricted -i",
            "ausearch -f /srv -i  # access to restricted directories",
            "compare uid and auid in audit.log (auid != uid -> sudo/su)",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn generate(&self, rng: &mut Rng, level: Level) -> GeneratedScenario {
        // Real decoy files and loopback connections are started by
        // `crate::sandbox::Sandbox::activate` for the whole Caution category.
        let user = *rng
            .pick(&["jdoe", "m.orlov", "intern1", "qa_bot", "d.hall"])
            .unwrap();
        let resource = *rng
            .pick(&[
                "/srv/finance/payroll.xlsx",
                "/srv/hr/contracts",
                "/var/lib/postgresql/prod",
                "/srv/secrets/vault-unseal.key",
                "/srv/infra/terraform.tfstate",
            ])
            .unwrap();
        let method = *rng.pick(&Method::all()).unwrap();
        let src_host = private_ip(rng);
        // Target host in the "server" segment 10.0.50.0/24.
        let target_host = ipv4(0x0A00_3200 | rng.range(10, 240) as u32);
        let access_secs = rng.range(3600, 23 * 3600);
        let svc_account = "svc_deploy";
        // A regular employee's login uid — kept stable so the "auid != uid"
        // signature during privilege escalation is diagnosable.
        let user_uid: u32 = 1000 + rng.range(2, 40) as u32;

        let mut auth: Vec<(u64, String)> = Vec::new();

        // Noise: normal sessions.
        for _ in 0..rng.range(7, 13) {
            let t = rng.range(0, 86_400);
            let who = *rng.pick(&["jdoe", "m.orlov", "ops", "backup"]).unwrap();
            auth.push((
                t,
                format!(
                    "{} sshd[{}]: Accepted publickey for {} from {} port {} ssh2",
                    syslog_ts(t, HOST),
                    pid(rng),
                    who,
                    private_ip(rng),
                    ephemeral_port(rng),
                ),
            ));
        }

        // Every method starts with a login — that is how src_host shows in
        // auth.log. For CredReuse the login itself is the signal: the CI
        // service account logs in with a PASSWORD from an employee workstation
        // instead of the runner's key.
        let login_secs = access_secs.saturating_sub(30);
        let (login_who, login_kind) = match method {
            Method::CredReuse => (svc_account, "password"),
            _ => (user, "publickey"),
        };
        auth.push((
            login_secs,
            format!(
                "{} sshd[{}]: Accepted {} for {} from {} port {} ssh2",
                syslog_ts(login_secs, HOST),
                pid(rng),
                login_kind,
                login_who,
                src_host,
                ephemeral_port(rng),
            ),
        ));

        // Signal in auth.log on top of the login.
        match method {
            Method::PrivEsc => {
                auth.push((
                    access_secs,
                    format!(
                        "{} sudo:   {} : TTY=pts/3 ; PWD=/home/{} ; USER=root ; \
                         COMMAND=/bin/cat {}",
                        syslog_ts(access_secs, HOST),
                        user,
                        user,
                        resource,
                    ),
                ));
                auth.push((
                    access_secs + 1,
                    format!(
                        "{} sudo: pam_unix(sudo:session): session opened for user root by {}(uid={})",
                        syslog_ts(access_secs + 1, HOST),
                        user,
                        user_uid,
                    ),
                ));
            }
            Method::CredReuse => {
                auth.push((
                    login_secs + 1,
                    format!(
                        "{} sshd[{}]: pam_unix(sshd:session): session opened for user {} by (uid=0)",
                        syslog_ts(login_secs + 1, HOST),
                        pid(rng),
                        svc_account,
                    ),
                ));
            }
            Method::MisconfiguredPerms => {}
        }

        auth.sort_by_key(|(t, _)| *t);
        let auth_log = auth
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");

        // audit.log: first background access to open files (noise), then one
        // event accessing the restricted resource.
        let mut event = rng.range(5000, 7000) as u32;
        let noise_files = [
            "/srv/pub/readme.txt",
            "/srv/pub/onboarding.md",
            "/etc/hostname",
            "/srv/shared/reports/q3.csv",
        ];
        let noise_comms = ["bash", "cat", "less", "python3", "vim"];
        let mut audit_events: Vec<(u64, String)> = Vec::new();
        for _ in 0..rng.range(4, 8) {
            let t = rng.range(0, 86_400);
            event += 1;
            let f = *rng.pick(&noise_files).unwrap();
            let c = *rng.pick(&noise_comms).unwrap();
            audit_events.push((
                t,
                format!(
                    "type=SYSCALL msg={m}: syscall=257 success=yes comm=\"{c}\" \
                     exe=\"/usr/bin/{c}\" auid={user_uid} uid={user_uid} exit=3\n\
                     type=PATH msg={m}: item=0 name=\"{f}\" mode=0100644 ouid=0 ogid=0",
                    m = audit_ts(t, event),
                ),
            ));
        }

        event += 1;
        // Diagnostic fields per method:
        //  - PrivEsc: the employee's auid, but uid=0 (process already under sudo);
        //  - CredReuse: all under the svc account (service account uid);
        //  - MisconfiguredPerms: access with a normal uid, but the file has extra bits.
        let (comm, exe, auid, uid, mode_str) = match method {
            Method::PrivEsc => ("cat", "/usr/bin/cat", user_uid, 0u32, "0100640"),
            Method::CredReuse => ("scp", "/usr/bin/scp", 990, 990, "0100640"),
            Method::MisconfiguredPerms => ("cp", "/usr/bin/cp", user_uid, user_uid, "0100777"),
        };
        audit_events.push((
            access_secs,
            format!(
                "type=SYSCALL msg={m}: syscall=257 success=yes comm=\"{comm}\" \
                 exe=\"{exe}\" auid={auid} uid={uid} exit=3 key=\"restricted\"\n\
                 type=PATH msg={m}: item=0 name=\"{resource}\" mode={mode_str} ouid=0 ogid=0",
                m = audit_ts(access_secs, event),
            ),
        ));
        audit_events.sort_by_key(|(t, _)| *t);
        let audit = audit_events
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");

        // The account that reached beyond its privileges: for credential reuse
        // it is the service account itself, otherwise the employee.
        let offender = match method {
            Method::CredReuse => svc_account,
            _ => user,
        };

        let mut facts = BTreeMap::new();
        facts.insert("user".into(), offender.to_string());
        facts.insert("resource".into(), resource.to_string());
        facts.insert("method".into(), method.answer().to_string());
        facts.insert("src_host".into(), src_host.clone());
        facts.insert("target_host".into(), target_host.clone());
        facts.insert(
            "access_time".into(),
            crate::scenario::gen::clock(access_secs),
        );
        facts.insert("verdict".into(), "internal breach".into());

        let artifacts = vec![
            Artifact::new("/var/log/auth.log", auth_log),
            Artifact::new("/var/log/audit/audit.log", audit),
        ];

        let questions: Vec<Question> = build_questions(QUESTIONS, &facts, level, rng)
            .expect("embedded internal_breach.toml is valid");

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
                assert!(s.artifacts.iter().any(|a| a.name.ends_with("audit.log")));
                assert!(
                    s.artifacts[1].body.contains(&s.facts["resource"]),
                    "the restricted resource must be in audit.log"
                );
                assert_eq!(s.facts["verdict"], "internal breach");
            }
        }
    }

    #[test]
    fn same_seed_same_output() {
        let g = Type;
        let mut a = Rng::new(11);
        let mut b = Rng::new(11);
        let sa = g.generate(&mut a, Level::Advanced);
        let sb = g.generate(&mut b, Level::Advanced);
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
