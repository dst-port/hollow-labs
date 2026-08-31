//! Shared question model for Quiz and for labs (Safe/Caution).

use serde::Deserialize;

use crate::validator::{ChoiceAnswer, FreeAnswer, Normalize};

/// User level. Picked on first launch, stored in the config, changed in
/// settings. Affects the number of questions, the share of free input, hints
/// and timer strictness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    #[default]
    Beginner,
    Intermediate,
    Advanced,
}

impl Level {
    pub const ALL: [Level; 3] = [Level::Beginner, Level::Intermediate, Level::Advanced];

    pub fn label(self) -> &'static str {
        match self {
            Level::Beginner => "Beginner",
            Level::Intermediate => "Intermediate",
            Level::Advanced => "Advanced",
        }
    }

    pub fn tag(self) -> &'static str {
        match self {
            Level::Beginner => "beginner",
            Level::Intermediate => "intermediate",
            Level::Advanced => "advanced",
        }
    }

    /// How many questions to show at this level (range from the plan).
    pub fn question_count(self) -> (usize, usize) {
        match self {
            Level::Beginner => (2, 3),
            Level::Intermediate => (3, 4),
            Level::Advanced => (4, 5),
        }
    }

    /// Whether hints are allowed.
    pub fn hints_allowed(self) -> bool {
        matches!(self, Level::Beginner)
    }

    pub fn next(self) -> Option<Level> {
        match self {
            Level::Beginner => Some(Level::Intermediate),
            Level::Intermediate => Some(Level::Advanced),
            Level::Advanced => None,
        }
    }
}

/// Question type.
#[derive(Clone, Debug)]
pub enum Kind {
    /// Free input: an atomic answer (IP, port, PID, timestamp, domain).
    Free(FreeAnswer),
    /// One correct option from a list.
    Choice {
        options: Vec<String>,
        answer: ChoiceAnswer,
    },
}

/// A ready question — after loading from TOML and substituting generated values
/// (for labs), or as-is (for the quiz).
#[derive(Clone, Debug)]
pub struct Question {
    pub prompt: String,
    pub kind: Kind,
    /// Shown only on Beginner and only if `Level::hints_allowed`.
    pub hint: Option<String>,
    /// Minimum level at which the question appears at all.
    pub min_level: Level,
}

impl Question {
    pub fn free(prompt: impl Into<String>, answer: FreeAnswer) -> Self {
        Self {
            prompt: prompt.into(),
            kind: Kind::Free(answer),
            hint: None,
            min_level: Level::Beginner,
        }
    }

    pub fn choice(prompt: impl Into<String>, options: Vec<String>, correct: usize) -> Self {
        let answer = ChoiceAnswer::single(correct, options.len());
        Self {
            prompt: prompt.into(),
            kind: Kind::Choice { options, answer },
            hint: None,
            min_level: Level::Beginner,
        }
    }

    pub fn hint(mut self, h: impl Into<String>) -> Self {
        self.hint = Some(h.into());
        self
    }

    pub fn min_level(mut self, l: Level) -> Self {
        self.min_level = l;
        self
    }

    /// Whether the answer is correct. For `Free` — the input string; for
    /// `Choice` — the index.
    pub fn check_free(&self, input: &str) -> bool {
        match &self.kind {
            Kind::Free(a) => a.check(input),
            Kind::Choice { .. } => false,
        }
    }

    pub fn check_choice(&self, selected: usize) -> bool {
        match &self.kind {
            Kind::Choice { answer, .. } => answer.check(selected),
            Kind::Free(_) => false,
        }
    }

    pub fn is_free(&self) -> bool {
        matches!(self.kind, Kind::Free(_))
    }
}

/// A raw question from TOML. Shared format for quiz and scenario files.
///
/// ```toml
/// [[question]]
/// level = "beginner"          # minimum level (default: beginner)
/// kind  = "choice"            # "choice" | "free"
/// prompt = "Is this a DDoS or a legitimate spike?"
/// options = ["DDoS", "Legitimate spike"]   # choice only
/// answer = "0"               # choice: index; free: canonical string
/// normalize = "casefold"     # free: trim | casefold | digits | ip
/// accept = ["alt answer"]    # free: extra accepted strings
/// hint = "Look at the per-subnet distribution"  # opt., shown on beginner
/// ```
///
/// Placeholders like `{ip}`, `{port}` in `prompt` / `answer` / `options` are
/// substituted by the scenario generator from its fact set.
#[derive(Clone, Debug, Deserialize)]
pub struct RawQuestion {
    #[serde(default)]
    pub level: Level,
    pub kind: RawKind,
    pub prompt: String,
    #[serde(default)]
    pub options: Vec<String>,
    pub answer: String,
    #[serde(default)]
    pub normalize: RawNormalize,
    #[serde(default)]
    pub accept: Vec<String>,
    #[serde(default)]
    pub hint: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RawKind {
    Choice,
    Free,
}

#[derive(Clone, Copy, Debug, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RawNormalize {
    #[default]
    Trim,
    Casefold,
    Digits,
    Ip,
}

impl From<RawNormalize> for Normalize {
    fn from(r: RawNormalize) -> Self {
        match r {
            RawNormalize::Trim => Normalize::Trim,
            RawNormalize::Casefold => Normalize::Casefold,
            RawNormalize::Digits => Normalize::Digits,
            RawNormalize::Ip => Normalize::Ip,
        }
    }
}

/// Error building a question from its raw representation.
#[derive(Debug)]
#[allow(clippy::enum_variant_names)] // every variant is about a choice question — intentional
pub enum BuildError {
    ChoiceNeedsOptions,
    ChoiceAnswerNotIndex(String),
    ChoiceAnswerOutOfRange { index: usize, len: usize },
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::ChoiceNeedsOptions => write!(f, "choice question has an empty `options`"),
            BuildError::ChoiceAnswerNotIndex(s) => {
                write!(f, "choice question `answer` is not an index: {s:?}")
            }
            BuildError::ChoiceAnswerOutOfRange { index, len } => {
                write!(
                    f,
                    "answer={index} is out of range for `options` (len={len})"
                )
            }
        }
    }
}

impl std::error::Error for BuildError {}

impl RawQuestion {
    /// Builds a ready `Question`. `subst` is called for every string (`prompt`,
    /// `answer`, each option) — the generator substitutes its own values for
    /// placeholders here. For the quiz, pass `|s| s.to_string()`.
    pub fn build(&self, mut subst: impl FnMut(&str) -> String) -> Result<Question, BuildError> {
        let prompt = subst(&self.prompt);
        let hint = self.hint.as_deref().map(&mut subst);

        let kind = match self.kind {
            RawKind::Free => {
                let mut fa = FreeAnswer::new(subst(&self.answer)).normalize(self.normalize.into());
                for alt in &self.accept {
                    fa = fa.with(subst(alt));
                }
                Kind::Free(fa)
            }
            RawKind::Choice => {
                if self.options.is_empty() {
                    return Err(BuildError::ChoiceNeedsOptions);
                }
                let options: Vec<String> = self.options.iter().map(|o| subst(o)).collect();
                let idx: usize = self
                    .answer
                    .trim()
                    .parse()
                    .map_err(|_| BuildError::ChoiceAnswerNotIndex(self.answer.clone()))?;
                if idx >= options.len() {
                    return Err(BuildError::ChoiceAnswerOutOfRange {
                        index: idx,
                        len: options.len(),
                    });
                }
                Kind::Choice {
                    answer: ChoiceAnswer::single(idx, options.len()),
                    options,
                }
            }
        };

        Ok(Question {
            prompt,
            kind,
            hint,
            min_level: self.level,
        })
    }
}
