//! DDoS Mitigation — `safe/`. Reference generator implementation.
//!
//! Generated:
//!  - a sharp spike of requests from random IPs against one endpoint;
//!  - some IPs from a single `/24` (botnet hint), some traffic legitimate (noise);
//!  - a deliberately broken firewall config snippet (random from a pool):
//!    commented-out rate-limit / `ACCEPT ALL` above the blocking rule /
//!    an overly wide whitelist (`/16` instead of `/32`).

use std::collections::BTreeMap;

use crate::question::{Level, Question};
use crate::rng::Rng;
use crate::scenario::gen::{
    browser_ua, ephemeral_port, ip_in_subnet, ipv4, nginx_ts, public_ip, subnet_base, tool_ua,
};
use crate::scenario::{build_questions, Artifact, Category, GeneratedScenario, Generator};

const QUESTIONS: &str = include_str!("../../../data/scenarios/safe/ddos.toml");

/// Variants of the broken firewall misconfiguration.
#[derive(Clone, Copy)]
enum Misconfig {
    RateLimitCommented,
    AcceptAllFirst,
    WhitelistTooWide,
}

impl Misconfig {
    fn all() -> [Misconfig; 3] {
        [
            Misconfig::RateLimitCommented,
            Misconfig::AcceptAllFirst,
            Misconfig::WhitelistTooWide,
        ]
    }

    /// Short canonical token — the reference for the Advanced question.
    fn answer(self) -> &'static str {
        match self {
            Misconfig::RateLimitCommented => "rate limit",
            Misconfig::AcceptAllFirst => "ACCEPT ALL",
            Misconfig::WhitelistTooWide => "whitelist",
        }
    }

    fn rules_v4(self, botnet_slash24: &str) -> String {
        match self {
            Misconfig::RateLimitCommented => {
                let _ = botnet_slash24;
                "*filter\n\
                 :INPUT DROP [0:0]\n\
                 -A INPUT -i lo -j ACCEPT\n\
                 -A INPUT -p tcp --dport 22 -j ACCEPT\n\
                 # -A INPUT -p tcp --dport 80 -m hashlimit --hashlimit-above 50/sec \\\n\
                 #   --hashlimit-mode srcip --hashlimit-name http -j DROP\n\
                 -A INPUT -p tcp --dport 80 -j ACCEPT\n\
                 -A INPUT -p tcp --dport 443 -j ACCEPT\n\
                 COMMIT\n"
                    .to_string()
            }
            Misconfig::AcceptAllFirst => format!(
                "*filter\n\
                 :INPUT DROP [0:0]\n\
                 -A INPUT -i lo -j ACCEPT\n\
                 -A INPUT -j ACCEPT\n\
                 -A INPUT -s {botnet_slash24}/24 -j DROP\n\
                 -A INPUT -p tcp --dport 80 -m hashlimit --hashlimit-above 50/sec \\\n\
                   --hashlimit-mode srcip --hashlimit-name http -j DROP\n\
                 COMMIT\n"
            ),
            Misconfig::WhitelistTooWide => format!(
                "*filter\n\
                 :INPUT DROP [0:0]\n\
                 -A INPUT -i lo -j ACCEPT\n\
                 -A INPUT -s {botnet_slash24}/16 -j ACCEPT\n\
                 -A INPUT -p tcp --dport 80 -m hashlimit --hashlimit-above 50/sec \\\n\
                   --hashlimit-mode srcip --hashlimit-name http -j DROP\n\
                 COMMIT\n"
            ),
        }
    }
}

pub struct Ddos;

impl Generator for Ddos {
    fn id(&self) -> &'static str {
        "ddos"
    }

    fn title(&self) -> &'static str {
        "DDoS Mitigation"
    }

    fn category(&self) -> Category {
        Category::Safe
    }

    fn tools(&self) -> Vec<String> {
        [
            "netstat / ss -ntu",
            "tcpdump -ni any 'tcp port 80'",
            "iptables -L -n -v",
            "awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn",
            "/var/log/nginx/access.log",
            "/etc/nginx/nginx.conf",
            "/etc/iptables/rules.v4",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn generate(&self, rng: &mut Rng, level: Level) -> GeneratedScenario {
        // No "/" — otherwise the attacked endpoint is indistinguishable from background noise.
        let endpoint = *rng
            .pick(&[
                "/api/login",
                "/search",
                "/checkout",
                "/graphql",
                "/api/v2/orders",
            ])
            .unwrap();

        // Botnet: one /24, most attack addresses come from it.
        let botnet = subnet_base(rng);
        let botnet_str = ipv4(botnet);
        let botnet_slash24 = {
            let o = botnet_str.rsplit_once('.').unwrap().0;
            format!("{o}.0")
        };

        let misconfig = *rng.pick(&Misconfig::all()).unwrap();

        // access.log: noise + spike.
        let mut lines: Vec<(u64, String)> = Vec::new();
        let noise = rng.range(25, 45);
        for _ in 0..noise {
            let t = rng.range(0, 600);
            let ip = public_ip(rng);
            lines.push((
                t,
                access_line(&ip, t, "GET", "/", 200, browser_ua(rng), rng),
            ));
        }

        let spike_start = rng.range(600, 660);
        let attack_hits = rng.range(180, 320);
        let from_botnet = (attack_hits as f64 * rng.range(60, 85) as f64 / 100.0) as u64;
        for i in 0..attack_hits {
            let t = spike_start + i / rng.range(8, 20).max(1);
            let ip = if i < from_botnet {
                ip_in_subnet(rng, botnet)
            } else {
                public_ip(rng)
            };
            lines.push((
                t,
                access_line(&ip, t, "GET", endpoint, 200, tool_ua(rng), rng),
            ));
        }
        lines.sort_by_key(|(t, _)| *t);
        let access_log = lines
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");

        let rules = misconfig.rules_v4(&botnet_slash24);

        let mut facts = BTreeMap::new();
        facts.insert("endpoint".into(), endpoint.to_string());
        facts.insert("botnet_subnet".into(), format!("{botnet_slash24}/24"));
        facts.insert("botnet_prefix".into(), botnet_slash24.clone());
        facts.insert("attack_hits".into(), attack_hits.to_string());
        facts.insert("misconfig".into(), misconfig.answer().to_string());
        facts.insert("verdict".into(), "DDoS".to_string());

        let artifacts = vec![
            Artifact::new("/var/log/nginx/access.log", access_log),
            Artifact::new("/etc/iptables/rules.v4", rules),
        ];

        let questions: Vec<Question> =
            build_questions(QUESTIONS, &facts, level, rng).expect("embedded ddos.toml is valid");

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

fn access_line(
    ip: &str,
    t: u64,
    method: &str,
    path: &str,
    status: u16,
    ua: &str,
    rng: &mut Rng,
) -> String {
    let bytes = rng.range(120, 5000);
    let _ = ephemeral_port(rng);
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
        let g = Ddos;
        for seed in 0..30 {
            let mut rng = Rng::new(seed);
            let s = g.generate(&mut rng, Level::Advanced);
            assert_eq!(s.category, Category::Safe);
            assert!(!s.questions.is_empty());
            assert!(s.artifacts.iter().any(|a| a.name.ends_with("access.log")));
            assert!(s.facts.contains_key("botnet_subnet"));
        }
    }

    #[test]
    fn same_seed_same_output() {
        let g = Ddos;
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
