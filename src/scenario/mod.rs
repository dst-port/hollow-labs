//! Lab scenario model and the extension point for generators.
//!
//! Each scenario (`safe/` or `caution/`) implements [`Generator`]:
//!  - declares an id, title, category and a list of recommended tools;
//!  - on a run it randomizes parameters through [`Rng`] and returns a
//!    [`GeneratedScenario`]: a set of "facts", generated artifacts (logs,
//!    config snippets) and questions for the chosen level.
//!
//! Questions are described in TOML (`data/scenarios/<cat>/<id>.toml`), embedded
//! via `include_str!`. `{key}` placeholders in the question text are filled from
//! `facts`, so the wording and correct answer always match the logs.

pub mod caution;
pub mod gen;
pub mod safe;
pub mod stub;

use std::collections::BTreeMap;

use crate::question::{BuildError, Level, Question, RawQuestion};
use crate::rng::Rng;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    /// Web attacks: logs are generated locally, no external load.
    /// 3 attempts per answer, 15 minutes.
    Safe,
    /// Real system activity (processes, filesystem, loopback network).
    /// 2 attempts per answer, 15 minutes, a warning at start.
    Caution,
}

impl Category {
    pub fn dir(self) -> &'static str {
        match self {
            Category::Safe => "safe",
            Category::Caution => "caution",
        }
    }

    pub fn attempts(self) -> u8 {
        match self {
            Category::Safe => 3,
            Category::Caution => 2,
        }
    }

    pub fn time_limit_secs(self) -> u64 {
        15 * 60
    }
}

/// A generated artifact — what the analyst will `grep` through.
#[derive(Clone, Debug)]
pub struct Artifact {
    /// Display name / path, as in a real system.
    pub name: String,
    /// Content (usually a multi-line log).
    pub body: String,
}

impl Artifact {
    pub fn new(name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            body: body.into(),
        }
    }
}

/// The result of one scenario run at a fixed seed.
#[derive(Clone, Debug)]
pub struct GeneratedScenario {
    pub id: String,
    pub title: String,
    pub category: Category,
    /// Recommended tools and commands — the pre-start screen.
    pub tools: Vec<String>,
    /// Key -> value for placeholder substitution and debugging.
    pub facts: BTreeMap<String, String>,
    pub artifacts: Vec<Artifact>,
    pub questions: Vec<Question>,
}

/// Implemented by every scenario.
pub trait Generator: Send + Sync {
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn category(&self) -> Category;
    fn tools(&self) -> Vec<String>;

    /// Full run: randomization + artifacts + questions for the level.
    fn generate(&self, rng: &mut Rng, level: Level) -> GeneratedScenario;
}

/// All registered generators (safe + caution).
pub fn all() -> Vec<Box<dyn Generator>> {
    let mut v = safe::generators();
    v.extend(caution::generators());
    v
}

pub fn by_category(cat: Category) -> Vec<Box<dyn Generator>> {
    all().into_iter().filter(|g| g.category() == cat).collect()
}

/// Helper for generators: assemble questions from the embedded TOML, filter by
/// level, substitute facts, truncate to `count`, and (for non-Beginner) drop
/// hints.
pub fn build_questions(
    toml_src: &str,
    facts: &BTreeMap<String, String>,
    level: Level,
    rng: &mut Rng,
) -> Result<Vec<Question>, ScenarioError> {
    #[derive(serde::Deserialize)]
    struct File {
        #[serde(default, rename = "question")]
        questions: Vec<RawQuestion>,
    }

    let file: File = toml::from_str(toml_src).map_err(ScenarioError::Toml)?;

    let mut built: Vec<Question> = Vec::new();
    for raw in &file.questions {
        if (raw.level as u8) > (level as u8) {
            continue;
        }
        let mut q = raw
            .build(|s| substitute(s, facts))
            .map_err(ScenarioError::Build)?;
        if !level.hints_allowed() {
            q.hint = None;
        }
        built.push(q);
    }

    rng.shuffle(&mut built);
    let (lo, hi) = level.question_count();
    let target = rng.range(lo as u64, hi as u64) as usize;
    built.truncate(target.max(1));
    Ok(built)
}

/// Replaces `{key}` with `facts["key"]`. Unknown placeholders are left as-is —
/// visible during content review.
pub fn substitute(s: &str, facts: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close) => {
                let key = &after[..close];
                match facts.get(key) {
                    Some(val) => out.push_str(val),
                    None => {
                        out.push('{');
                        out.push_str(key);
                        out.push('}');
                    }
                }
                rest = &after[close + 1..];
            }
            None => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[derive(Debug)]
pub enum ScenarioError {
    Toml(toml::de::Error),
    Build(BuildError),
}

impl std::fmt::Display for ScenarioError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScenarioError::Toml(e) => write!(f, "parsing scenario TOML: {e}"),
            ScenarioError::Build(e) => write!(f, "building question: {e}"),
        }
    }
}

impl std::error::Error for ScenarioError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("ip".to_string(), "203.0.113.7".to_string()),
            ("port".to_string(), "8080".to_string()),
        ])
    }

    #[test]
    fn substitute_known_and_unknown() {
        let f = facts();
        assert_eq!(substitute("src {ip}:{port}", &f), "src 203.0.113.7:8080");
        assert_eq!(substitute("{missing} tail", &f), "{missing} tail");
        assert_eq!(substitute("no braces", &f), "no braces");
        assert_eq!(substitute("dangling {", &f), "dangling {");
    }

    #[test]
    fn registry_ids_are_unique() {
        let all = all();
        let mut ids: Vec<&str> = all.iter().map(|g| g.id()).collect();
        ids.sort();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate generator ids");
    }

    /// Every IP answer (free input, normalize = ip) must appear in the
    /// scenario artifacts — otherwise the question is not solvable from the
    /// logs. Catches drift between facts and artifacts.
    #[test]
    fn ip_answers_are_present_in_artifacts() {
        use crate::question::Kind;
        use crate::validator::Normalize;

        for g in all() {
            for level in Level::ALL {
                for seed in [1u64, 7, 13, 42, 99, 256] {
                    let mut rng = Rng::new(seed);
                    let s = g.generate(&mut rng, level);
                    let hay = s
                        .artifacts
                        .iter()
                        .map(|a| a.body.as_str())
                        .collect::<Vec<_>>()
                        .join("\n");
                    for q in &s.questions {
                        let Kind::Free(fa) = &q.kind else { continue };
                        if fa.normalize != Normalize::Ip {
                            continue;
                        }
                        assert!(
                            fa.accept.iter().any(|ip| hay.contains(ip)),
                            "{}/{:?}/seed={seed}: none of the answers {:?} were found \
                             in the artifacts for question \"{}\"",
                            g.id(),
                            level,
                            fa.accept,
                            q.prompt,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn build_questions_filters_by_level() {
        let src = r#"
[[question]]
level = "beginner"
kind = "choice"
prompt = "src {ip}?"
options = ["yes", "no"]
answer = "0"

[[question]]
level = "advanced"
kind = "free"
prompt = "port?"
answer = "{port}"
normalize = "digits"
"#;
        let f = facts();
        let mut rng = Rng::new(1);
        let qs = build_questions(src, &f, Level::Beginner, &mut rng).unwrap();
        assert!(qs.iter().all(|q| q.min_level == Level::Beginner));
    }
}
