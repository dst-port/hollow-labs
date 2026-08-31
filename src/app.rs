//! Application state and input handling. Rendering lives in [`crate::ui`].

use std::time::Duration;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::config::Config;
use crate::question::Level;
use crate::quiz::{Outcome, Quiz, QuizSession};
use crate::rng::Rng;
use crate::sandbox::Sandbox;
use crate::scenario::{self, GeneratedScenario};
use crate::timer::{Thresholds, Timer};

/// What is shown right now.
pub enum Screen {
    LevelSelect { cursor: usize },
    Menu { cursor: usize },
    Settings { cursor: usize },
    Quiz,
    QuizResults,
    LabBrief,
    Lab,
    LabResults,
    Error(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LabView {
    Artifacts,
    Questions,
}

/// The active lab (Safe/Caution).
pub struct LabState {
    pub scenario: GeneratedScenario,
    pub timer: Timer,
    pub view: LabView,
    pub artifact_idx: usize,
    pub scroll: usize,
    pub question_idx: usize,
    pub attempts_left: u8,
    pub outcomes: Vec<Outcome>,
    pub feedback: Option<String>,
    pub finished: bool,
}

impl LabState {
    fn new(scenario: GeneratedScenario) -> Self {
        let attempts = scenario.category.attempts();
        let limit = Duration::from_secs(scenario.category.time_limit_secs());
        Self {
            timer: Timer::new(limit, Thresholds::LAB),
            view: LabView::Artifacts,
            artifact_idx: 0,
            scroll: 0,
            question_idx: 0,
            attempts_left: attempts,
            outcomes: Vec::new(),
            feedback: None,
            finished: false,
            scenario,
        }
    }

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

    fn record(&mut self, outcome: Outcome) {
        self.outcomes.push(outcome);
        self.question_idx += 1;
        self.attempts_left = self.scenario.category.attempts();
        self.feedback = None;
        if self.question_idx >= self.scenario.questions.len() {
            self.finished = true;
        }
    }

    /// Marks the remaining questions as skipped (time is up).
    fn flush_skips(&mut self) {
        while self.question_idx < self.scenario.questions.len() {
            self.outcomes.push(Outcome::Skipped);
            self.question_idx += 1;
        }
        self.finished = true;
    }
}

pub struct App {
    pub screen: Screen,
    pub config: Config,
    pub level: Level,
    pub seed: u64,
    pub rng: Rng,
    pub quiz: Option<QuizSession>,
    pub lab: Option<LabState>,
    /// Real sandbox of the active lab: artifacts on disk + side effects.
    /// `None` when no lab is running or the sandbox is disabled.
    pub sandbox: Option<Sandbox>,
    /// Shared free-input buffer.
    pub input: String,
    /// Cursor in option lists.
    pub choice_cursor: usize,
    pub should_quit: bool,
}

impl App {
    pub fn new(config: Config, seed: u64) -> Self {
        let level = config.level().unwrap_or_default();
        let screen = if config.level().is_none() {
            Screen::LevelSelect { cursor: 0 }
        } else {
            Screen::Menu { cursor: 0 }
        };
        Self {
            screen,
            config,
            level,
            seed,
            rng: Rng::new(seed),
            quiz: None,
            lab: None,
            sandbox: None,
            input: String::new(),
            choice_cursor: 0,
            should_quit: false,
        }
    }

    /// Once per frame: tick the active timers.
    pub fn tick(&mut self) {
        if let Some(q) = &mut self.quiz {
            let before = q.is_finished();
            q.tick();
            if !before && q.is_finished() {
                self.screen = Screen::QuizResults;
            }
        }
        if let Some(lab) = &mut self.lab {
            if !lab.finished && lab.timer.is_expired() {
                lab.flush_skips();
            }
            if lab.finished && matches!(self.screen, Screen::Lab) {
                self.screen = Screen::LabResults;
            }
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(key.code, KeyCode::Char('c')) {
            self.should_quit = true;
            return;
        }
        match &mut self.screen {
            Screen::LevelSelect { .. } => self.key_level_select(key),
            Screen::Menu { .. } => self.key_menu(key),
            Screen::Settings { .. } => self.key_settings(key),
            Screen::Quiz => self.key_quiz(key, ctrl),
            Screen::QuizResults => self.key_quiz_results(key),
            Screen::LabBrief => self.key_lab_brief(key),
            Screen::Lab => self.key_lab(key, ctrl),
            Screen::LabResults => self.key_lab_results(key),
            Screen::Error(_) => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                    self.screen = Screen::Menu { cursor: 0 };
                }
            }
        }
    }

    fn key_level_select(&mut self, key: KeyEvent) {
        let Screen::LevelSelect { cursor } = &mut self.screen else {
            return;
        };
        match key.code {
            KeyCode::Up => *cursor = cursor.saturating_sub(1),
            KeyCode::Down => *cursor = (*cursor + 1).min(Level::ALL.len() - 1),
            KeyCode::Enter => {
                let level = Level::ALL[*cursor];
                self.level = level;
                self.config.set_level(level);
                let _ = self.config.save();
                self.screen = Screen::Menu { cursor: 0 };
            }
            _ => {}
        }
    }

    fn key_menu(&mut self, key: KeyEvent) {
        let Screen::Menu { cursor } = &mut self.screen else {
            return;
        };
        const N: usize = 5;
        match key.code {
            KeyCode::Up => *cursor = cursor.saturating_sub(1),
            KeyCode::Down => *cursor = (*cursor + 1).min(N - 1),
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Enter => match *cursor {
                0 => self.start_quiz(),
                1 => self.start_lab(scenario::Category::Safe),
                2 => self.start_lab(scenario::Category::Caution),
                3 => {
                    self.screen = Screen::Settings {
                        cursor: self.level as usize,
                    }
                }
                _ => self.should_quit = true,
            },
            _ => {}
        }
    }

    fn key_settings(&mut self, key: KeyEvent) {
        let Screen::Settings { cursor } = &mut self.screen else {
            return;
        };
        match key.code {
            KeyCode::Up => *cursor = cursor.saturating_sub(1),
            KeyCode::Down => *cursor = (*cursor + 1).min(Level::ALL.len() - 1),
            KeyCode::Enter => {
                let level = Level::ALL[*cursor];
                self.level = level;
                self.config.set_level(level);
                let _ = self.config.save();
                self.screen = Screen::Menu { cursor: 0 };
            }
            KeyCode::Esc => self.screen = Screen::Menu { cursor: 0 },
            _ => {}
        }
    }

    fn start_quiz(&mut self) {
        self.input.clear();
        self.choice_cursor = 0;
        match Quiz::build(self.level, &mut self.rng) {
            Ok(quiz) => {
                self.quiz = Some(quiz.into_session(Thresholds::QUIZ));
                self.screen = Screen::Quiz;
            }
            Err(e) => self.screen = Screen::Error(format!("Failed to build the quiz: {e}")),
        }
    }

    fn key_quiz(&mut self, key: KeyEvent, ctrl: bool) {
        let Some(session) = &mut self.quiz else {
            return;
        };
        let is_free = session.current().map(|q| q.is_free()).unwrap_or(true);
        let opt_count = session
            .current()
            .and_then(|q| match &q.kind {
                crate::question::Kind::Choice { options, .. } => Some(options.len()),
                _ => None,
            })
            .unwrap_or(0);

        if ctrl && matches!(key.code, KeyCode::Char('s')) {
            session.skip();
            self.after_quiz_step();
            return;
        }
        match key.code {
            KeyCode::Esc => {
                self.quiz = None;
                self.screen = Screen::Menu { cursor: 0 };
            }
            KeyCode::Up if !is_free => {
                self.choice_cursor = self.choice_cursor.saturating_sub(1);
            }
            KeyCode::Down if !is_free => {
                if opt_count > 0 {
                    self.choice_cursor = (self.choice_cursor + 1).min(opt_count - 1);
                }
            }
            KeyCode::Char(c) if is_free => self.input.push(c),
            KeyCode::Backspace if is_free => {
                self.input.pop();
            }
            KeyCode::Enter => {
                if is_free {
                    let done = session.submit_free(&self.input.clone());
                    if done {
                        self.after_quiz_step();
                    } else {
                        self.input.clear();
                    }
                } else {
                    let done = session.submit_choice(self.choice_cursor);
                    self.after_quiz_step_if(done);
                }
            }
            _ => {}
        }
    }

    fn after_quiz_step_if(&mut self, done: bool) {
        if done {
            self.after_quiz_step();
        }
    }

    fn after_quiz_step(&mut self) {
        self.input.clear();
        self.choice_cursor = 0;
        if let Some(session) = &self.quiz {
            if session.is_finished() {
                self.screen = Screen::QuizResults;
            }
        }
    }

    fn key_quiz_results(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('r') => {
                if let Some(session) = self.quiz.take() {
                    self.quiz = Some(session.replay(&mut self.rng));
                    self.input.clear();
                    self.choice_cursor = 0;
                    self.screen = Screen::Quiz;
                }
            }
            KeyCode::Enter | KeyCode::Esc => {
                self.quiz = None;
                self.screen = Screen::Menu { cursor: 0 };
            }
            _ => {}
        }
    }

    fn start_lab(&mut self, cat: scenario::Category) {
        self.input.clear();
        self.choice_cursor = 0;
        let gens = scenario::by_category(cat);
        if gens.is_empty() {
            self.screen = Screen::Error("No scenarios in this category".into());
            return;
        }
        let pick = self.rng.below(gens.len() as u64) as usize;
        let mut sub = self.rng.fork();
        let scenario = gens[pick].generate(&mut sub, self.level);
        if scenario.questions.is_empty() {
            self.screen = Screen::Error(format!(
                "Scenario {} produced no questions for level {}",
                scenario.id,
                self.level.label()
            ));
            return;
        }
        // Materialize artifacts to disk (side effects are not started yet —
        // that happens on Enter at the briefing).
        self.sandbox = Sandbox::create(&scenario).ok().flatten();
        self.lab = Some(LabState::new(scenario));
        self.screen = Screen::LabBrief;
    }

    /// Ends the lab: clears state and, via the sandbox's Drop, all real side
    /// effects and the temp directory.
    fn end_lab(&mut self) {
        self.lab = None;
        self.sandbox = None;
    }

    fn key_lab_brief(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                if let Some(lab) = &mut self.lab {
                    lab.timer = Timer::new(
                        Duration::from_secs(lab.scenario.category.time_limit_secs()),
                        Thresholds::LAB,
                    );
                }
                if let Some(sb) = &mut self.sandbox {
                    sb.activate();
                }
                self.screen = Screen::Lab;
            }
            KeyCode::Esc => {
                self.end_lab();
                self.screen = Screen::Menu { cursor: 0 };
            }
            _ => {}
        }
    }

    fn key_lab(&mut self, key: KeyEvent, ctrl: bool) {
        let Some(lab) = &mut self.lab else { return };
        let art_lines = lab.scenario.artifacts[lab.artifact_idx]
            .body
            .lines()
            .count();
        let is_free = lab.scenario.questions[lab.question_idx].is_free();
        let opt_count = match &lab.scenario.questions[lab.question_idx].kind {
            crate::question::Kind::Choice { options, .. } => options.len(),
            _ => 0,
        };

        if ctrl && matches!(key.code, KeyCode::Char('s')) {
            lab.record(Outcome::Skipped);
            self.post_lab_step();
            return;
        }

        match key.code {
            KeyCode::Esc => {
                self.end_lab();
                self.screen = Screen::Menu { cursor: 0 };
            }
            KeyCode::Tab => {
                lab.view = match lab.view {
                    LabView::Artifacts => LabView::Questions,
                    LabView::Questions => LabView::Artifacts,
                };
            }
            KeyCode::Left => {
                lab.artifact_idx = lab.artifact_idx.saturating_sub(1);
                lab.scroll = 0;
            }
            KeyCode::Right => {
                lab.artifact_idx = (lab.artifact_idx + 1).min(lab.scenario.artifacts.len() - 1);
                lab.scroll = 0;
            }
            KeyCode::Up => match lab.view {
                LabView::Artifacts => lab.scroll = lab.scroll.saturating_sub(1),
                LabView::Questions if !is_free => {
                    self.choice_cursor = self.choice_cursor.saturating_sub(1);
                }
                _ => {}
            },
            KeyCode::Down => match lab.view {
                LabView::Artifacts => {
                    lab.scroll = (lab.scroll + 1).min(art_lines.saturating_sub(1));
                }
                LabView::Questions if !is_free && opt_count > 0 => {
                    self.choice_cursor = (self.choice_cursor + 1).min(opt_count - 1);
                }
                _ => {}
            },
            KeyCode::Char(c) if lab.view == LabView::Questions && is_free => self.input.push(c),
            KeyCode::Backspace if lab.view == LabView::Questions && is_free => {
                self.input.pop();
            }
            KeyCode::Enter if lab.view == LabView::Questions => {
                let q = &lab.scenario.questions[lab.question_idx];
                let correct = if is_free {
                    q.check_free(&self.input)
                } else {
                    q.check_choice(self.choice_cursor)
                };
                if correct {
                    lab.record(Outcome::Correct);
                    self.post_lab_step();
                } else {
                    lab.attempts_left = lab.attempts_left.saturating_sub(1);
                    self.input.clear();
                    if lab.attempts_left == 0 {
                        lab.record(Outcome::Wrong);
                        self.post_lab_step();
                    } else {
                        lab.feedback = Some(format!("Wrong. Attempts left: {}", lab.attempts_left));
                    }
                }
            }
            _ => {}
        }
    }

    fn post_lab_step(&mut self) {
        self.input.clear();
        self.choice_cursor = 0;
        if let Some(lab) = &self.lab {
            if lab.finished {
                self.screen = Screen::LabResults;
            }
        }
    }

    #[cfg(test)]
    pub fn screen_name(&self) -> &'static str {
        match self.screen {
            Screen::LevelSelect { .. } => "level_select",
            Screen::Menu { .. } => "menu",
            Screen::Settings { .. } => "settings",
            Screen::Quiz => "quiz",
            Screen::QuizResults => "quiz_results",
            Screen::LabBrief => "lab_brief",
            Screen::Lab => "lab",
            Screen::LabResults => "lab_results",
            Screen::Error(_) => "error",
        }
    }

    fn key_lab_results(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('n') => {
                // Another run: same level, next seed stream.
                let cat = self
                    .lab
                    .as_ref()
                    .map(|l| l.scenario.category)
                    .unwrap_or(scenario::Category::Safe);
                self.end_lab();
                self.start_lab(cat);
            }
            KeyCode::Enter | KeyCode::Esc => {
                self.end_lab();
                self.screen = Screen::Menu { cursor: 0 };
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    /// Redirect config writes to /tmp and disable the on-disk sandbox — tests
    /// must not touch the real ~/.config or spawn sockets.
    fn isolate_config() {
        let p = std::env::temp_dir().join(format!("hollow-labs-test-{}.toml", std::process::id()));
        std::env::set_var("HOLLOW_LABS_CONFIG", p);
        std::env::set_var(crate::sandbox::DISABLE_ENV, "1");
    }

    fn app_at_menu() -> App {
        isolate_config();
        let mut cfg = Config::default();
        cfg.set_level(Level::Beginner);
        App::new(cfg, 1)
    }

    #[test]
    fn first_run_starts_at_level_select_then_menu() {
        isolate_config();
        let mut app = App::new(Config::default(), 1);
        assert_eq!(app.screen_name(), "level_select");
        app.on_key(key(KeyCode::Enter)); // Beginner
        assert_eq!(app.screen_name(), "menu");
        assert_eq!(app.level, Level::Beginner);
    }

    #[test]
    fn menu_enter_launches_quiz_and_esc_returns() {
        let mut app = app_at_menu();
        app.on_key(key(KeyCode::Enter)); // item 0 = Quiz
        assert_eq!(app.screen_name(), "quiz");
        assert!(app.quiz.is_some());
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.screen_name(), "menu");
        assert!(app.quiz.is_none());
    }

    #[test]
    fn quiz_can_be_completed_by_skipping_to_results() {
        let mut app = app_at_menu();
        app.on_key(key(KeyCode::Enter));
        for _ in 0..10 {
            if app.screen_name() == "quiz_results" {
                break;
            }
            app.on_key(ctrl('s'));
        }
        assert_eq!(app.screen_name(), "quiz_results");
        let session = app.quiz.as_ref().unwrap();
        let (c, w, s) = session.tally();
        assert_eq!(c + w + s, session.outcomes().len());
        assert!(s > 0);
    }

    #[test]
    fn quiz_replay_from_results_reshuffles_and_restarts() {
        let mut app = app_at_menu();
        app.on_key(key(KeyCode::Enter));
        while app.screen_name() != "quiz_results" {
            app.on_key(ctrl('s'));
        }
        app.on_key(key(KeyCode::Char('r')));
        assert_eq!(app.screen_name(), "quiz");
        assert_eq!(app.quiz.as_ref().unwrap().progress().0, 1);
    }

    #[test]
    fn safe_lab_brief_then_run_then_results() {
        let mut app = app_at_menu();
        // move down to the "Safe" item (index 1)
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen_name(), "lab_brief");
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen_name(), "lab");

        let n = app.lab.as_ref().unwrap().scenario.questions.len();
        app.on_key(key(KeyCode::Tab)); // to the questions panel
        for _ in 0..(n + 2) {
            if app.screen_name() == "lab_results" {
                break;
            }
            app.on_key(ctrl('s'));
        }
        assert_eq!(app.screen_name(), "lab_results");
        let lab = app.lab.as_ref().unwrap();
        let (c, w, s) = lab.tally();
        assert_eq!(c + w + s, n);
    }

    #[test]
    fn settings_changes_level_and_persists_in_memory() {
        let mut app = app_at_menu();
        // menu -> Settings (index 3)
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen_name(), "settings");
        app.on_key(key(KeyCode::Down)); // Intermediate
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.level, Level::Intermediate);
        assert_eq!(app.screen_name(), "menu");
    }

    #[test]
    fn ctrl_c_quits_from_anywhere() {
        let mut app = app_at_menu();
        app.on_key(ctrl('c'));
        assert!(app.should_quit);
    }
}
