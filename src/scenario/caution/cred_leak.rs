//! Credential Leak Detection — `caution/`.
//!
//! Generated:
//!  - `/var/log/audit/audit.log`: normal file activity (noise) + an anomalous
//!    read of a sensitive file (`/etc/shadow`, `.env`, cloud keys);
//!  - `/var/log/syslog`: evidence of exfiltration (an outbound connection / an
//!    archive in a hidden directory) or its absence ("unknown where the data
//!    went").

use std::collections::BTreeMap;

use crate::question::{Level, Question};
use crate::rng::Rng;
use crate::scenario::gen::{pid, public_ip, syslog_ts};
use crate::scenario::{build_questions, Artifact, Category, GeneratedScenario, Generator};

const QUESTIONS: &str = include_str!("../../../data/scenarios/caution/cred_leak.toml");

const HOST: &str = "hollow-01";
/// Nominal "run midnight" in epoch seconds for audit.log lines.
const EPOCH_BASE: u64 = 1_788_998_400;

const NOISE_FILES: [&str; 6] = [
    "/var/www/app/index.php",
    "/etc/nginx/nginx.conf",
    "/var/log/app/access.log",
    "/home/deploy/.bashrc",
    "/usr/share/zoneinfo/UTC",
    "/etc/hosts",
];

/// Background audit processes: (comm, full exe, uid). Correct for a typical
/// LAMP box — cron/sshd as root, nginx/php-fpm as www-data (33).
const NOISE_PROCS: [(&str, &str, u32); 5] = [
    ("nginx", "/usr/sbin/nginx", 33),
    ("php-fpm", "/usr/sbin/php-fpm8.2", 33),
    ("bash", "/usr/bin/bash", 1000),
    ("cron", "/usr/sbin/cron", 0),
    ("sshd", "/usr/sbin/sshd", 0),
];

fn audit_ts(secs: u64, event: u32) -> String {
    format!("audit({}.{:03}:{})", EPOCH_BASE + secs, secs % 1000, event)
}

/// Where the read data went — the Advanced reference.
#[derive(Clone, Copy)]
enum Dest {
    ExternalIp,
    LocalDump,
    Unknown,
}

impl Dest {
    fn all() -> [Dest; 3] {
        [Dest::ExternalIp, Dest::LocalDump, Dest::Unknown]
    }

    fn answer(self) -> &'static str {
        match self {
            Dest::ExternalIp => "external IP",
            Dest::LocalDump => "local dump",
            Dest::Unknown => "unknown",
        }
    }
}

pub struct Type;

impl Generator for Type {
    fn id(&self) -> &'static str {
        "cred_leak"
    }

    fn title(&self) -> &'static str {
        "Credential Leak Detection"
    }

    fn category(&self) -> Category {
        Category::Caution
    }

    fn tools(&self) -> Vec<String> {
        [
            "/var/log/audit/audit.log",
            "auditctl -l / ausearch -k secrets",
            "ausearch -f /etc/shadow -i",
            "lsof / inotifywait -m",
            "/var/log/syslog",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn generate(&self, rng: &mut Rng, level: Level) -> GeneratedScenario {
        // Real decoy reads with an activity.log entry are performed by
        // `crate::sandbox::Sandbox::activate` for the whole Caution category.
        let secret_file = *rng
            .pick(&[
                "/etc/shadow",
                "/srv/app/.env",
                "/root/.aws/credentials",
                "/etc/mysql/my.cnf",
                "/home/deploy/.ssh/id_rsa",
            ])
            .unwrap();
        let dest = *rng.pick(&Dest::all()).unwrap();
        // The reader process is chosen to fit the exfil method so syslog and
        // audit.log do not contradict each other.
        let proc = *rng
            .pick(match dest {
                Dest::ExternalIp => &["curl", "python3", "scp", "nc"][..],
                Dest::LocalDump => &["tar", "cp", "python3"][..],
                Dest::Unknown => &["cat", "less", "python3", "xxd"][..],
            })
            .unwrap();
        let leak_pid = pid(rng);
        let uid = rng.range(1001, 1050);
        let user = *rng.pick(&["deploy", "www-data", "jenkins", "ops"]).unwrap();
        let ext_ip = public_ip(rng);
        let dump_path = "/tmp/.cache/backup.tar.gz";
        let read_secs = rng.range(3 * 3600, 22 * 3600);

        // audit.log: noise + anomalous read.
        let mut lines: Vec<(u64, String)> = Vec::new();
        let mut event = rng.range(2000, 4000) as u32;
        let noise = rng.range(10, 18);
        for _ in 0..noise {
            let t = rng.range(0, 86_400);
            let f = *rng.pick(&NOISE_FILES).unwrap();
            let (np_comm, np_exe, np_uid) = *rng.pick(&NOISE_PROCS).unwrap();
            event += 1;
            lines.push((
                t,
                format!(
                    "type=SYSCALL msg={}: arch=c000003e syscall=257 success=yes exit=4 \
                     comm=\"{}\" exe=\"{}\" uid={} key=(null)\n\
                     type=PATH msg={}: item=0 name=\"{}\" mode=0100644 ouid=0 ogid=0",
                    audit_ts(t, event),
                    np_comm,
                    np_exe,
                    np_uid,
                    audit_ts(t, event),
                    f,
                ),
            ));
        }

        // Signal: reading the secret, flagged by the rule key "secrets".
        event += 1;
        lines.push((
            read_secs,
            format!(
                "type=SYSCALL msg={}: arch=c000003e syscall=257 success=yes exit=3 \
                 comm=\"{}\" exe=\"/usr/bin/{}\" pid={} uid={} auid={} key=\"secrets\"\n\
                 type=PATH msg={}: item=0 name=\"{}\" mode=0100640 ouid=0 ogid=42",
                audit_ts(read_secs, event),
                proc,
                proc,
                leak_pid,
                uid,
                uid,
                audit_ts(read_secs, event),
                secret_file,
            ),
        ));

        lines.sort_by_key(|(t, _)| *t);
        let audit_log = lines
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");

        // syslog: evidence of exfiltration.
        let mut syslog = String::new();
        for _ in 0..rng.range(4, 8) {
            let t = rng.range(0, 86_400);
            syslog.push_str(&format!(
                "{} CRON[{}]: (root) CMD (/usr/local/bin/rotate-logs)\n",
                syslog_ts(t, HOST),
                pid(rng)
            ));
        }
        match dest {
            Dest::ExternalIp => syslog.push_str(&format!(
                "{} {}[{}]: connect to {}:443 — sent {} bytes\n",
                syslog_ts(read_secs + rng.range(1, 30), HOST),
                proc,
                leak_pid,
                ext_ip,
                rng.range(2048, 65_000),
            )),
            Dest::LocalDump => syslog.push_str(&format!(
                "{} {}[{}]: wrote {} <- {} ({} bytes)\n",
                syslog_ts(read_secs + rng.range(1, 30), HOST),
                proc,
                leak_pid,
                dump_path,
                secret_file,
                rng.range(2048, 65_000),
            )),
            Dest::Unknown => {}
        }

        let dest_value = match dest {
            Dest::ExternalIp => ext_ip.clone(),
            Dest::LocalDump => dump_path.to_string(),
            Dest::Unknown => "unknown".to_string(),
        };

        let mut facts = BTreeMap::new();
        facts.insert("secret_file".into(), secret_file.to_string());
        facts.insert("proc".into(), proc.to_string());
        facts.insert("pid".into(), leak_pid.to_string());
        facts.insert("user".into(), user.to_string());
        facts.insert("dest".into(), dest_value);
        facts.insert("dest_kind".into(), dest.answer().to_string());
        facts.insert("verdict".into(), "leak".into());

        let artifacts = vec![
            Artifact::new("/var/log/audit/audit.log", audit_log),
            Artifact::new("/var/log/syslog", syslog),
        ];

        let questions: Vec<Question> = build_questions(QUESTIONS, &facts, level, rng)
            .expect("embedded cred_leak.toml is valid");

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
                    s.artifacts[0].body.contains(&s.facts["secret_file"]),
                    "the secret file must appear in audit.log"
                );
                assert!(s.artifacts[0].body.contains(&s.facts["pid"]));
                assert_eq!(s.facts["verdict"], "leak");
            }
        }
    }

    #[test]
    fn same_seed_same_output() {
        let g = Type;
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
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
