//! Generator stub. Compiles and runs, but the content is minimal. Each stub is
//! replaced by a full scenario in its own file (see `ddos.rs` as a reference).
//! The list is in `docs/SPEC.md`.

use std::collections::BTreeMap;

use crate::question::{Level, Question};
use crate::rng::Rng;
use crate::scenario::gen::{private_ip, public_ip, syslog_ts};
use crate::scenario::{Artifact, Category, GeneratedScenario, Generator};

pub struct Stub {
    pub id: &'static str,
    pub title: &'static str,
    pub category: Category,
    pub tools: &'static [&'static str],
    /// Legitimate/anomalous verdict for the beginner question.
    pub verdict: &'static str,
}

impl Generator for Stub {
    fn id(&self) -> &'static str {
        self.id
    }
    fn title(&self) -> &'static str {
        self.title
    }
    fn category(&self) -> Category {
        self.category
    }
    fn tools(&self) -> Vec<String> {
        self.tools.iter().map(|s| s.to_string()).collect()
    }

    fn generate(&self, rng: &mut Rng, _level: Level) -> GeneratedScenario {
        let good = private_ip(rng);
        let bad = public_ip(rng);
        let host = "hollow-01";

        let mut log = String::new();
        for i in 0..12 {
            let t = 3600 + i * 47;
            log.push_str(&format!(
                "{} sshd[{}]: Accepted password for analyst from {} port {} ssh2\n",
                syslog_ts(t, host),
                1000 + i,
                good,
                40000 + i
            ));
        }
        log.push_str(&format!(
            "{} sshd[{}]: Accepted password for analyst from {} port {} ssh2\n",
            syslog_ts(4200, host),
            1300,
            bad,
            51234
        ));

        let mut facts = BTreeMap::new();
        facts.insert("anomalous_ip".into(), bad.clone());
        facts.insert("verdict".into(), self.verdict.into());

        let questions = vec![
            Question::choice(
                format!(
                    "[STUB {}] Is this legitimate activity or an anomaly?",
                    self.id
                ),
                vec!["Legitimate".into(), "Anomaly".into()],
                1,
            ),
            Question::free(
                "Which IP produced the anomalous entry?",
                crate::validator::FreeAnswer::new(bad).normalize(crate::validator::Normalize::Ip),
            ),
        ];

        GeneratedScenario {
            id: self.id.into(),
            title: self.title.into(),
            category: self.category,
            tools: self.tools(),
            facts,
            artifacts: vec![Artifact::new("/var/log/auth.log", log)],
            questions,
        }
    }
}
