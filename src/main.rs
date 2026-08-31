//! HOLLOW LABS — a TUI trainer for IR/SOC analysts.
//!
//! Modes: Quiz (theory), Safe (web attacks), Caution (system activity).
//! `--seed N` pins the randomization for a reproducible run.

// Scaffold: part of the modules' public API is used by scenarios and the
// sandbox as it grows, but not all of it is reachable from the binary on
// every commit.
#![allow(dead_code)]

mod app;
mod config;
mod question;
mod quiz;
mod rng;
mod sandbox;
mod scenario;
mod timer;
mod ui;
mod validator;

use std::io::{self, Stdout};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::prelude::*;

use crate::app::App;
use crate::config::Config;
use crate::question::Level;
use crate::rng::Rng;

/// Target frame rate: ~20 fps is enough for the timer and blinking.
const FRAME: Duration = Duration::from_millis(50);

fn main() -> io::Result<()> {
    let opts = Options::parse(std::env::args().skip(1));
    if opts.help {
        print_help();
        return Ok(());
    }
    if opts.no_sandbox {
        std::env::set_var(sandbox::DISABLE_ENV, "1");
    }

    let seed = opts.seed.unwrap_or_else(random_seed);

    if let Some(id) = &opts.dump {
        return dump_scenario(id, seed, opts.level);
    }

    let config = Config::load();
    let mut app = App::new(config, seed);

    let mut terminal = setup_terminal()?;
    let res = run(&mut terminal, &mut app);
    restore_terminal(&mut terminal)?;
    res
}

fn run(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> io::Result<()> {
    let mut last = Instant::now();
    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        let timeout = FRAME.saturating_sub(last.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == event::KeyEventKind::Press {
                    app.on_key(key);
                }
            }
        }

        if last.elapsed() >= FRAME {
            app.tick();
            last = Instant::now();
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

/// `--dump <id>`: prints the generated artifacts and questions of a scenario
/// to stdout without the TUI. Handy for demos, scripts and content debugging.
///
/// The whole output is accumulated into a string and written with a single
/// `write_all`; `BrokenPipe` (`--dump ... | head`) is not treated as an error.
fn dump_scenario(id: &str, seed: u64, level: Level) -> io::Result<()> {
    use std::fmt::Write as _;
    use std::io::Write as _;

    let Some(gen) = scenario::all().into_iter().find(|g| g.id() == id) else {
        eprintln!("no scenario with id {id:?}. Available:");
        for g in scenario::all() {
            eprintln!("  {:<16} {} ({:?})", g.id(), g.title(), g.category());
        }
        std::process::exit(2);
    };

    let mut rng = Rng::new(seed);
    let s = gen.generate(&mut rng, level);

    let mut out = String::new();
    let _ = writeln!(
        out,
        "# {} [{}]  seed={seed}  level={}",
        s.title,
        s.id,
        level.label()
    );
    let _ = writeln!(out, "\n## Recommended tools");
    for t in &s.tools {
        let _ = writeln!(out, "  - {t}");
    }
    let _ = writeln!(out, "\n## Facts (substitution keys)");
    for (k, v) in &s.facts {
        let _ = writeln!(out, "  {k} = {v}");
    }
    for art in &s.artifacts {
        let _ = writeln!(out, "\n## Artifact: {}\n{}", art.name, art.body.trim_end());
    }
    let _ = writeln!(out, "\n## Questions ({}):", s.questions.len());
    for (i, q) in s.questions.iter().enumerate() {
        let _ = writeln!(out, "  {}. [{}] {}", i + 1, q.min_level.label(), q.prompt);
        if let crate::question::Kind::Choice { options, .. } = &q.kind {
            for (j, opt) in options.iter().enumerate() {
                let _ = writeln!(out, "       {j}) {opt}");
            }
        }
    }

    match io::stdout().write_all(out.as_bytes()) {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

fn setup_terminal() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout))
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()
}

/// Seed from the system clock when `--seed` is not given.
fn random_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_nanos() as u64) ^ (std::process::id() as u64).rotate_left(17)
}

struct Options {
    seed: Option<u64>,
    help: bool,
    no_sandbox: bool,
    dump: Option<String>,
    level: Level,
}

impl Options {
    fn parse(args: impl Iterator<Item = String>) -> Self {
        let mut seed = None;
        let mut help = false;
        let mut no_sandbox = false;
        let mut dump = None;
        let mut level = Level::Advanced;
        let mut it = args.into_iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--seed" => seed = it.next().and_then(|s| s.parse().ok()),
                s if s.starts_with("--seed=") => seed = s["--seed=".len()..].parse().ok(),
                "--dump" => dump = it.next(),
                s if s.starts_with("--dump=") => dump = Some(s["--dump=".len()..].to_string()),
                "--level" => {
                    if let Some(v) = it.next() {
                        level = parse_level(&v).unwrap_or(level);
                    }
                }
                s if s.starts_with("--level=") => {
                    level = parse_level(&s["--level=".len()..]).unwrap_or(level);
                }
                "--no-sandbox" => no_sandbox = true,
                "-h" | "--help" => help = true,
                _ => {}
            }
        }
        Self {
            seed,
            help,
            no_sandbox,
            dump,
            level,
        }
    }
}

fn parse_level(s: &str) -> Option<Level> {
    match s.to_lowercase().as_str() {
        "beginner" | "b" => Some(Level::Beginner),
        "intermediate" | "i" => Some(Level::Intermediate),
        "advanced" | "a" => Some(Level::Advanced),
        _ => None,
    }
}

fn print_help() {
    println!(
        "HOLLOW LABS — a TUI trainer for IR/SOC analysts\n\n\
         Usage:\n  \
         hollow-labs [--seed N] [--no-sandbox]\n  \
         hollow-labs --dump <id> [--seed N] [--level beginner|intermediate|advanced]\n\n\
         Options:\n  \
         --seed N        pin the randomization of scenarios and quizzes (reproducible run)\n  \
         --dump <id>     print a scenario's artifacts and questions to stdout without the TUI\n  \
         --level L       level for --dump (default: advanced)\n  \
         --no-sandbox    do not write artifacts to disk or start loopback sockets\n  \
         -h, --help      this help\n\n\
         Scenarios: ddos, sqli, xss, csrf, phishing, cred_spoof, cred_leak,\n  \
         bruteforce, internal_breach, unknown_ip\n\n\
         TUI controls: arrows — navigate, Enter — select, Tab — panels,\n  \
         Ctrl+S — skip a question, Esc — back, Ctrl+C — quit."
    );
}
