//! Bruteforce Detection — `caution/`.
//!
//! Generated:
//!  - `/var/log/auth.log`: legitimate logins (noise) + a run of consecutive
//!    failed attempts from one IP against one service (SSH / FTP / web panel) —
//!    the line format matches the service (sshd / vsftpd PAM / panel via PAM);
//!  - `fail2ban-client status <jail>` output with a summary of failed attempts.
//!
//! The interval between attempts tells whether it is manual guessing or an
//! automated tool — the Advanced answer.

use std::collections::BTreeMap;

use crate::question::{Level, Question};
use crate::rng::Rng;
use crate::scenario::gen::{ephemeral_port, pid, private_ip, public_ip, syslog_ts};
use crate::scenario::{build_questions, Artifact, Category, GeneratedScenario, Generator};

const QUESTIONS: &str = include_str!("../../../data/scenarios/caution/bruteforce.toml");

const HOST: &str = "hollow-01";
const NOISE_USERS: [&str; 4] = ["deploy", "backup", "monitor", "ansible"];

/// The attacked service: log tag, fail2ban jail, and what a failed-auth line
/// looks like.
#[derive(Clone, Copy)]
enum Service {
    Ssh,
    Ftp,
    WebPanel,
}

impl Service {
    fn all() -> [Service; 3] {
        [Service::Ssh, Service::Ftp, Service::WebPanel]
    }

    fn label(self) -> &'static str {
        match self {
            Service::Ssh => "SSH",
            Service::Ftp => "FTP",
            Service::WebPanel => "web panel",
        }
    }

    fn jail(self) -> &'static str {
        match self {
            Service::Ssh => "sshd",
            Service::Ftp => "vsftpd",
            Service::WebPanel => "hollow-panel",
        }
    }

    /// One failed-attempt line for `/var/log/auth.log`.
    fn fail_line(self, t: u64, user: &str, ip: &str, p: u32, port: u16) -> String {
        let ts = syslog_ts(t, HOST);
        match self {
            Service::Ssh => {
                format!("{ts} sshd[{p}]: Failed password for {user} from {ip} port {port} ssh2")
            }
            Service::Ftp => format!(
                "{ts} vsftpd[{p}]: pam_unix(vsftpd:auth): authentication failure; \
                 logname= uid=0 euid=0 tty=ftp ruser={user} rhost={ip}"
            ),
            Service::WebPanel => format!(
                "{ts} hollow-panel[{p}]: pam_unix(hollow-panel:auth): authentication failure; \
                 rhost={ip} user={user}"
            ),
        }
    }

    /// Successful-login line (when the brute-force eventually succeeds).
    fn ok_line(self, t: u64, user: &str, ip: &str, p: u32, port: u16) -> String {
        let ts = syslog_ts(t, HOST);
        match self {
            Service::Ssh => {
                format!("{ts} sshd[{p}]: Accepted password for {user} from {ip} port {port} ssh2")
            }
            Service::Ftp => format!(
                "{ts} vsftpd[{p}]: pam_unix(vsftpd:auth): session opened for user {user} by (uid=0) rhost={ip}"
            ),
            Service::WebPanel => format!(
                "{ts} hollow-panel[{p}]: accepted password for {user} from {ip} (session started)"
            ),
        }
    }
}

pub struct Type;

impl Generator for Type {
    fn id(&self) -> &'static str {
        "bruteforce"
    }

    fn title(&self) -> &'static str {
        "Bruteforce Detection"
    }

    fn category(&self) -> Category {
        Category::Caution
    }

    fn tools(&self) -> Vec<String> {
        [
            "/var/log/auth.log",
            "grep -E 'Failed password|authentication failure' /var/log/auth.log",
            "awk -F'rhost=' '/authentication failure/{print $2}' | awk '{print $1}' | sort | uniq -c | sort -rn",
            "fail2ban-client status <jail>  (sshd / vsftpd / hollow-panel)",
            "gaps between timestamps — manual guessing or a tool",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn generate(&self, rng: &mut Rng, level: Level) -> GeneratedScenario {
        // auth.log is written to the sandbox as a real file; loopback sockets and
        // decoy reads are started by `crate::sandbox::Sandbox::activate` (Caution).
        let attacker_ip = public_ip(rng);
        let target_user = *rng
            .pick(&["root", "admin", "postgres", "oracle", "git", "ubuntu"])
            .unwrap();
        let service = *rng.pick(&Service::all()).unwrap();
        let attempts = rng.range(18, 60);

        // Automated tool — an almost constant small interval;
        // manual guessing — large irregular pauses.
        let automated = rng.chance(0.6);
        let base_interval = if automated {
            rng.range(1, 3)
        } else {
            rng.range(20, 75)
        };
        let mode = if automated {
            "automated tool"
        } else {
            "manual guessing"
        };
        // Success at the end of the run — not always.
        let succeeded = rng.chance(0.35);

        let mut lines: Vec<(u64, String)> = Vec::new();

        // Noise: legitimate logins of service accounts.
        for _ in 0..rng.range(6, 12) {
            let t = rng.range(0, 86_400);
            let nu = *rng.pick(&NOISE_USERS).unwrap();
            lines.push((
                t,
                format!(
                    "{} sshd[{}]: Accepted publickey for {} from {} port {} ssh2",
                    syslog_ts(t, HOST),
                    pid(rng),
                    nu,
                    private_ip(rng),
                    ephemeral_port(rng),
                ),
            ));
        }

        // Signal: a run of consecutive failed attempts against one service.
        let start = rng.range(3600, 20 * 3600);
        let mut t = start;
        for _ in 0..attempts {
            let jitter = if automated {
                0
            } else {
                rng.range(0, base_interval / 2 + 1)
            };
            t += base_interval + jitter;
            lines.push((
                t,
                service.fail_line(t, target_user, &attacker_ip, pid(rng), ephemeral_port(rng)),
            ));
        }
        if succeeded {
            t += base_interval;
            lines.push((
                t,
                service.ok_line(t, target_user, &attacker_ip, pid(rng), ephemeral_port(rng)),
            ));
        }

        lines.sort_by_key(|(k, _)| *k);
        let auth_log = lines
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");

        // fail2ban-client status <jail>: summary of failed attempts.
        let banned = attempts >= 20; // jail trigger threshold
        let f2b = format!(
            "Status for the jail: {jail}\n\
             |- Filter\n\
             |  |- Currently failed:\t{cur}\n\
             |  |- Total failed:\t{attempts}\n\
             |  `- File list:\t/var/log/auth.log\n\
             `- Actions\n\
             \x20  |- Currently banned:\t{nb}\n\
             \x20  |- Total banned:\t{nb}\n\
             \x20  `- Banned IP list:\t{iplist}\n",
            jail = service.jail(),
            cur = if banned { 0 } else { attempts.min(5) },
            nb = u8::from(banned),
            iplist = if banned { attacker_ip.as_str() } else { "" },
        );

        let mut facts = BTreeMap::new();
        facts.insert("attacker_ip".into(), attacker_ip.clone());
        facts.insert("target_user".into(), target_user.to_string());
        facts.insert("attempts".into(), attempts.to_string());
        facts.insert("service".into(), service.label().to_string());
        facts.insert("mode".into(), mode.to_string());
        facts.insert(
            "outcome".into(),
            if succeeded { "yes" } else { "no" }.into(),
        );
        facts.insert("verdict".into(), "bruteforce".into());

        let artifacts = vec![
            Artifact::new("/var/log/auth.log", auth_log),
            Artifact::new(format!("fail2ban-client status {}", service.jail()), f2b),
        ];

        let questions: Vec<Question> = build_questions(QUESTIONS, &facts, level, rng)
            .expect("embedded bruteforce.toml is valid");

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
                let body = &s.artifacts[0].body;
                // The failure line depends on the service: sshd -> "Failed password",
                // vsftpd/panel -> PAM "authentication failure".
                let failed = body.matches("Failed password").count()
                    + body.matches("authentication failure").count();
                assert_eq!(failed.to_string(), s.facts["attempts"]);
                assert!(body.contains(&s.facts["attacker_ip"]));
                assert!(s.artifacts[1].name.starts_with("fail2ban-client status"));
                assert_eq!(s.facts["verdict"], "bruteforce");
            }
        }
    }

    #[test]
    fn same_seed_same_output() {
        let g = Type;
        let mut a = Rng::new(5);
        let mut b = Rng::new(5);
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
