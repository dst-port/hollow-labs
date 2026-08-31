//! Quiz — the theory mode.
//!
//! 30 seconds per question, timer changes colour (green -> yellow <=15s ->
//! red+blink <=5s), 2 attempts per question, running out of time = skip (does
//! not spend attempts). Results screen: check / cross / star — correct answers
//! are not shown. Replay reshuffles the order of questions and options.

use std::time::Duration;

use crate::question::{Kind, Level, Question, RawQuestion};
use crate::rng::Rng;
use crate::timer::{Thresholds, Timer};

/// Seconds per question.
pub const PER_QUESTION_SECS: u64 = 30;
/// Attempts per question.
pub const ATTEMPTS: u8 = 2;

/// All embedded quiz question banks. Add files here.
const BANKS: &[&str] = &[
    include_str!("../../data/quiz/fundamentals.toml"),
    include_str!("../../data/quiz/web_attacks.toml"),
    include_str!("../../data/quiz/host_forensics.toml"),
    include_str!("../../data/quiz/detection_ops.toml"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Correct,
    Wrong,
    Skipped,
}

impl Outcome {
    pub fn glyph(self) -> char {
        match self {
            Outcome::Correct => '✓',
            Outcome::Wrong => '✗',
            Outcome::Skipped => '⭐',
        }
    }
}

/// A loaded and prepared set of questions for one run.
pub struct Quiz {
    questions: Vec<Question>,
}

impl Quiz {
    /// Assembles the quiz: parses banks, filters by level, shuffles the order
    /// of questions and options, takes the required number of questions.
    pub fn build(level: Level, rng: &mut Rng) -> Result<Self, QuizError> {
        #[derive(serde::Deserialize)]
        struct File {
            #[serde(default, rename = "question")]
            questions: Vec<RawQuestion>,
        }

        let mut pool: Vec<Question> = Vec::new();
        for src in BANKS {
            let file: File = toml::from_str(src).map_err(QuizError::Toml)?;
            for raw in &file.questions {
                if (raw.level as u8) > (level as u8) {
                    continue;
                }
                let mut q = raw.build(|s| s.to_string()).map_err(QuizError::Build)?;
                if !level.hints_allowed() {
                    q.hint = None;
                }
                shuffle_options(&mut q, rng);
                pool.push(q);
            }
        }

        if pool.is_empty() {
            return Err(QuizError::Empty);
        }

        rng.shuffle(&mut pool);
        let (lo, hi) = level.question_count();
        let n = (rng.range(lo as u64, hi as u64) as usize)
            .min(pool.len())
            .max(1);
        pool.truncate(n);

        Ok(Self { questions: pool })
    }

    pub fn len(&self) -> usize {
        self.questions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.questions.is_empty()
    }

    pub fn into_session(self, thresholds: Thresholds) -> QuizSession {
        QuizSession::new(self.questions, thresholds)
    }
}

/// Reorders `Choice` options and fixes the correct-answer index.
fn shuffle_options(q: &mut Question, rng: &mut Rng) {
    if let Kind::Choice { options, answer } = &mut q.kind {
        let mut idx: Vec<usize> = (0..options.len()).collect();
        rng.shuffle(&mut idx);
        let new_options: Vec<String> = idx.iter().map(|&i| options[i].clone()).collect();
        let new_correct: Vec<usize> = answer
            .correct
            .iter()
            .filter_map(|old| idx.iter().position(|&i| i == *old))
            .collect();
        *options = new_options;
        answer.correct = new_correct;
    }
}

/// A quiz run: where we are, how many attempts are left, what has been scored.
pub struct QuizSession {
    questions: Vec<Question>,
    idx: usize,
    attempts_left: u8,
    outcomes: Vec<Outcome>,
    timer: Timer,
    thresholds: Thresholds,
    finished: bool,
}

impl QuizSession {
    fn new(questions: Vec<Question>, thresholds: Thresholds) -> Self {
        let timer = Timer::from_secs(PER_QUESTION_SECS, thresholds);
        Self {
            questions,
            idx: 0,
            attempts_left: ATTEMPTS,
            outcomes: Vec::new(),
            timer,
            thresholds,
            finished: false,
        }
    }

    pub fn current(&self) -> Option<&Question> {
        self.questions.get(self.idx)
    }

    pub fn timer(&self) -> &Timer {
        &self.timer
    }

    pub fn attempts_left(&self) -> u8 {
        self.attempts_left
    }

    pub fn progress(&self) -> (usize, usize) {
        (self.idx + 1, self.questions.len())
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn outcomes(&self) -> &[Outcome] {
        &self.outcomes
    }

    /// Tallies the result: (correct, wrong, skipped).
    pub fn tally(&self) -> (usize, usize, usize) {
        let mut c = (0, 0, 0);
        for o in &self.outcomes {
            match o {
                Outcome::Correct => c.0 += 1,
                Outcome::Wrong => c.1 += 1,
                Outcome::Skipped => c.2 += 1,
            }
        }
        c
    }

    /// Called from the render loop. If time is up, records a skip and moves to
    /// the next question.
    pub fn tick(&mut self) {
        if self.finished {
            return;
        }
        if self.timer.is_expired() {
            self.record(Outcome::Skipped);
        }
    }

    /// Answer to a free question. Returns `true` if the question is closed
    /// (correct, or attempts exhausted).
    pub fn submit_free(&mut self, input: &str) -> bool {
        let Some(q) = self.questions.get(self.idx) else {
            return true;
        };
        if !q.is_free() {
            return false;
        }
        if q.check_free(input) {
            self.record(Outcome::Correct);
            return true;
        }
        self.consume_attempt()
    }

    /// Answer to a multiple-choice question. Returns `true` if the question is closed.
    pub fn submit_choice(&mut self, selected: usize) -> bool {
        let Some(q) = self.questions.get(self.idx) else {
            return true;
        };
        if q.is_free() {
            return false;
        }
        if q.check_choice(selected) {
            self.record(Outcome::Correct);
            return true;
        }
        self.consume_attempt()
    }

    /// Skip manually.
    pub fn skip(&mut self) {
        if !self.finished {
            self.record(Outcome::Skipped);
        }
    }

    fn consume_attempt(&mut self) -> bool {
        self.attempts_left = self.attempts_left.saturating_sub(1);
        if self.attempts_left == 0 {
            self.record(Outcome::Wrong);
            true
        } else {
            false
        }
    }

    fn record(&mut self, outcome: Outcome) {
        self.outcomes.push(outcome);
        self.idx += 1;
        self.attempts_left = ATTEMPTS;
        if self.idx >= self.questions.len() {
            self.finished = true;
        } else {
            self.timer.restart(Duration::from_secs(PER_QUESTION_SECS));
        }
    }

    /// Start over with the same set but a reshuffled order/options.
    pub fn replay(mut self, rng: &mut Rng) -> QuizSession {
        for q in &mut self.questions {
            shuffle_options(q, rng);
        }
        rng.shuffle(&mut self.questions);
        QuizSession::new(self.questions, self.thresholds)
    }
}

#[derive(Debug)]
pub enum QuizError {
    Toml(toml::de::Error),
    Build(crate::question::BuildError),
    Empty,
}

impl std::fmt::Display for QuizError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuizError::Toml(e) => write!(f, "parsing quiz bank: {e}"),
            QuizError::Build(e) => write!(f, "building quiz question: {e}"),
            QuizError::Empty => write!(f, "no questions for the chosen level"),
        }
    }
}

impl std::error::Error for QuizError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_for_every_level() {
        for level in Level::ALL {
            let mut rng = Rng::new(1);
            let quiz = Quiz::build(level, &mut rng).expect("banks are valid");
            assert!(!quiz.is_empty());
            let (lo, hi) = level.question_count();
            assert!(quiz.len() >= lo.min(quiz.len()) && quiz.len() <= hi);
        }
    }

    #[test]
    fn wrong_twice_marks_wrong_and_advances() {
        let mut rng = Rng::new(5);
        let quiz = Quiz::build(Level::Beginner, &mut rng).unwrap();
        let total = quiz.len();
        let mut s = quiz.into_session(Thresholds::QUIZ);
        // Fail the first question.
        let closed_1 = s.submit_choice(usize::MAX); // definitely wrong
        assert!(!closed_1);
        let closed_2 = s.submit_choice(usize::MAX);
        assert!(closed_2);
        assert_eq!(s.outcomes(), &[Outcome::Wrong]);
        assert_eq!(s.progress().0, 2.min(total).max(1));
    }

    #[test]
    fn manual_skip_records_star() {
        let mut rng = Rng::new(6);
        let s = Quiz::build(Level::Beginner, &mut rng)
            .unwrap()
            .into_session(Thresholds::QUIZ);
        let mut s = s;
        s.skip();
        assert_eq!(s.outcomes()[0], Outcome::Skipped);
    }

    #[test]
    fn finishing_sets_flag_and_tally_sums() {
        let mut rng = Rng::new(7);
        let quiz = Quiz::build(Level::Advanced, &mut rng).unwrap();
        let n = quiz.len();
        let mut s = quiz.into_session(Thresholds::QUIZ);
        for _ in 0..n {
            s.skip();
        }
        assert!(s.is_finished());
        let (a, b, c) = s.tally();
        assert_eq!(a + b + c, n);
    }
}
