//! TUI rendering. One entry point [`draw`], dispatched per screen.

use ratatui::prelude::*;
use ratatui::widgets::*;

use crate::app::{App, LabView, Screen};
use crate::question::{Kind, Level};
use crate::timer::Phase;

/// Palette. Timer: green -> yellow -> red by phase.
pub fn phase_color(p: Phase) -> Color {
    match p {
        Phase::Calm => Color::Green,
        Phase::Warn => Color::Yellow,
        Phase::Critical => Color::Red,
    }
}

const ACCENT: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;

pub fn draw(f: &mut Frame, app: &App) {
    match &app.screen {
        Screen::LevelSelect { cursor } => level_select(f, *cursor),
        Screen::Menu { cursor } => menu(f, app, *cursor),
        Screen::Settings { cursor } => settings(f, app, *cursor),
        Screen::Quiz => quiz(f, app),
        Screen::QuizResults => quiz_results(f, app),
        Screen::LabBrief => lab_brief(f, app),
        Screen::Lab => lab(f, app),
        Screen::LabResults => lab_results(f, app),
        Screen::Error(msg) => error(f, msg),
    }
}

fn frame_block(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(DIM))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    Rect {
        x,
        y,
        width: w.min(area.width),
        height: h.min(area.height),
    }
}

fn footer(f: &mut Frame, area: Rect, hint: &str) {
    let p =
        Paragraph::new(Span::styled(hint, Style::default().fg(DIM))).alignment(Alignment::Center);
    f.render_widget(p, area);
}

fn list(f: &mut Frame, area: Rect, title: &str, items: &[String], cursor: usize) {
    let rows: Vec<ListItem> = items
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let selected = i == cursor;
            let style = if selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let marker = if selected { "▸ " } else { "  " };
            ListItem::new(Line::from(vec![
                Span::raw(marker),
                Span::styled(s.clone(), style),
            ]))
        })
        .collect();
    f.render_widget(List::new(rows).block(frame_block(title)), area);
}

fn level_select(f: &mut Frame, cursor: usize) {
    let area = centered(f.area(), 60, 12);
    let items: Vec<String> = Level::ALL
        .iter()
        .map(|l| {
            let (lo, hi) = l.question_count();
            format!("{:<14} {}-{} questions", l.label(), lo, hi)
        })
        .collect();
    list(f, area, "HOLLOW LABS · choose a level", &items, cursor);
    let below = Rect {
        y: area.y + area.height,
        height: 2,
        ..area
    };
    footer(
        f,
        below,
        "up/down — choose · Enter — confirm · level changes in settings",
    );
}

fn menu(f: &mut Frame, app: &App, cursor: usize) {
    let outer = centered(f.area(), 64, 16);
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(outer);

    let head = Line::from(vec![
        Span::styled(
            "HOLLOW LABS",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("   level: {}   seed: {}", app.level.label(), app.seed),
            Style::default().fg(DIM),
        ),
    ]);
    f.render_widget(Paragraph::new(head).alignment(Alignment::Center), chunks[0]);

    let items = vec![
        "Quiz     — theory, 30s per question".to_string(),
        "Safe     — web attacks, 3 attempts, 15 min".to_string(),
        "Caution  — system activity, 2 attempts, 15 min".to_string(),
        "Settings".to_string(),
        "Quit".to_string(),
    ];
    list(f, chunks[1], "menu", &items, cursor);
    footer(f, chunks[2], "up/down · Enter · q — quit");
}

fn settings(f: &mut Frame, app: &App, cursor: usize) {
    let area = centered(f.area(), 60, 10);
    let items: Vec<String> = Level::ALL
        .iter()
        .map(|l| {
            let mark = if *l == app.level { "  (current)" } else { "" };
            format!("Level: {}{}", l.label(), mark)
        })
        .collect();
    list(f, area, "Settings", &items, cursor);
    let below = Rect {
        y: area.y + area.height,
        height: 2,
        ..area
    };
    footer(f, below, "Enter — apply and save · Esc — back");
}

fn header_bar(f: &mut Frame, area: Rect, left: &str, timer_label: &str, phase: Phase, blink: bool) {
    let cols = Layout::horizontal([Constraint::Min(0), Constraint::Length(12)]).split(area);
    f.render_widget(
        Paragraph::new(Span::styled(left, Style::default().fg(DIM))),
        cols[0],
    );
    let mut style = Style::default()
        .fg(phase_color(phase))
        .add_modifier(Modifier::BOLD);
    if !blink {
        style = Style::default().fg(Color::Reset);
    }
    f.render_widget(
        Paragraph::new(Span::styled(format!("⏱ {timer_label}"), style)).alignment(Alignment::Right),
        cols[1],
    );
}

fn quiz(f: &mut Frame, app: &App) {
    let Some(session) = &app.quiz else { return };
    let Some(q) = session.current() else { return };

    let outer = centered(f.area(), 84, 22);
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(outer);

    let (cur, total) = session.progress();
    let t = session.timer();
    header_bar(
        f,
        rows[0],
        &format!(
            "Quiz · question {cur}/{total} · attempts: {}",
            session.attempts_left()
        ),
        &t.label(),
        t.phase(),
        t.blink_on(),
    );

    let gauge = Gauge::default()
        .ratio(t.ratio())
        .gauge_style(Style::default().fg(phase_color(t.phase())))
        .label("");
    f.render_widget(gauge, rows[1]);

    f.render_widget(
        Paragraph::new(q.prompt.clone())
            .wrap(Wrap { trim: true })
            .block(frame_block("question")),
        rows[2],
    );

    match &q.kind {
        Kind::Choice { options, .. } => {
            let items: Vec<String> = options.clone();
            list(f, rows[3], "options", &items, app.choice_cursor);
        }
        Kind::Free(_) => {
            let input = Paragraph::new(Line::from(vec![
                Span::styled("> ", Style::default().fg(ACCENT)),
                Span::raw(app.input.clone()),
                Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
            ]))
            .block(frame_block("free input"));
            f.render_widget(input, rows[3]);
        }
    }

    let hint = q
        .hint
        .as_deref()
        .map(|h| format!("hint: {h}"))
        .unwrap_or_else(|| "Enter — answer · Ctrl+S — skip".to_string());
    footer(f, rows[4], &hint);
}

fn quiz_results(f: &mut Frame, app: &App) {
    let Some(session) = &app.quiz else { return };
    let area = centered(f.area(), 70, 18);
    let (correct, wrong, skipped) = session.tally();

    let strip: String = session
        .outcomes()
        .iter()
        .map(|o| o.glyph())
        .collect::<Vec<_>>()
        .iter()
        .map(|c| format!("{c} "))
        .collect();

    let mut lines = vec![
        Line::from(Span::styled(
            "Quiz results",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(strip),
        Line::raw(""),
        Line::from(vec![
            Span::styled(format!("✓ {correct}   "), Style::default().fg(Color::Green)),
            Span::styled(format!("✗ {wrong}   "), Style::default().fg(Color::Red)),
            Span::styled(format!("⭐ {skipped}"), Style::default().fg(Color::Yellow)),
        ]),
        Line::raw(""),
        Line::from(Span::styled(
            "Correct answers are not shown — by design.",
            Style::default().fg(DIM),
        )),
    ];
    if wrong + skipped == 0 {
        if let Some(next) = app.level.next() {
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                format!("Clean run! Try level {} in settings.", next.label()),
                Style::default().fg(Color::Green),
            )));
        }
    }

    f.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .block(frame_block("results")),
        area,
    );
    let below = Rect {
        y: area.y + area.height,
        height: 2,
        ..area
    };
    footer(f, below, "r — replay (new order) · Enter/Esc — menu");
}

fn lab_brief(f: &mut Frame, app: &App) {
    let Some(lab) = &app.lab else { return };
    let area = centered(f.area(), 84, 24);
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(area);

    let warn = if lab.scenario.category == crate::scenario::Category::Caution {
        "⚠ Caution: this scenario creates real local artifacts (logs, loopback sockets)."
    } else {
        "Safe: everything is generated as local logs, no external load."
    };
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                lab.scenario.title.clone(),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(warn, Style::default().fg(Color::Yellow))),
        ])
        .block(frame_block("briefing")),
        rows[0],
    );

    let tools: Vec<String> = lab.scenario.tools.clone();
    let mut body: Vec<Line> = std::iter::once(Line::from(Span::styled(
        "Recommended tools and commands:",
        Style::default().add_modifier(Modifier::BOLD),
    )))
    .chain(tools.iter().map(|t| Line::from(format!("  • {t}"))))
    .chain(std::iter::once(Line::raw("")))
    .chain(std::iter::once(Line::from(format!(
        "Artifacts: {} · questions: {} · attempts per question: {}",
        lab.scenario.artifacts.len(),
        lab.scenario.questions.len(),
        lab.scenario.category.attempts(),
    ))))
    .collect();

    body.push(Line::raw(""));
    match &app.sandbox {
        Some(sb) => {
            for line in sb.hint().lines() {
                body.push(Line::from(Span::styled(
                    line.to_string(),
                    Style::default().fg(Color::Green),
                )));
            }
        }
        None => body.push(Line::from(Span::styled(
            "On-disk sandbox disabled (--no-sandbox) — artifacts in the TUI only.",
            Style::default().fg(DIM),
        ))),
    }
    f.render_widget(
        Paragraph::new(body).block(frame_block("preparation")),
        rows[1],
    );
    footer(
        f,
        rows[2],
        "Enter — start (starts the 15:00 timer) · Esc — back",
    );
}

fn lab(f: &mut Frame, app: &App) {
    let Some(lab) = &app.lab else { return };
    let outer = centered(f.area(), 100, 30);
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(outer);

    let t = &lab.timer;
    header_bar(
        f,
        rows[0],
        &format!(
            "{} · {} · attempts: {}",
            lab.scenario.title,
            match lab.view {
                LabView::Artifacts => "artifacts",
                LabView::Questions => "questions",
            },
            lab.attempts_left,
        ),
        &t.label(),
        t.phase(),
        t.blink_on(),
    );

    let cols =
        Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).split(rows[1]);

    // Left column — artifacts.
    let art = &lab.scenario.artifacts[lab.artifact_idx.min(lab.scenario.artifacts.len() - 1)];
    let art_title = format!(
        "[{}/{}] {}",
        lab.artifact_idx + 1,
        lab.scenario.artifacts.len(),
        art.name
    );
    let art_style = if lab.view == LabView::Artifacts {
        Style::default().fg(ACCENT)
    } else {
        Style::default().fg(DIM)
    };
    let art_lines: Vec<Line> = art
        .body
        .lines()
        .skip(lab.scroll)
        .take(cols[0].height.saturating_sub(2) as usize)
        .map(|l| Line::raw(l.to_string()))
        .collect();
    f.render_widget(
        Paragraph::new(art_lines).block(frame_block(&art_title).border_style(art_style)),
        cols[0],
    );

    // Right column — current question.
    let q = &lab.scenario.questions[lab.question_idx.min(lab.scenario.questions.len() - 1)];
    let q_style = if lab.view == LabView::Questions {
        Style::default().fg(ACCENT)
    } else {
        Style::default().fg(DIM)
    };
    let mut q_lines = vec![
        Line::from(Span::styled(
            format!(
                "Question {}/{}",
                lab.question_idx + 1,
                lab.scenario.questions.len()
            ),
            Style::default().fg(DIM),
        )),
        Line::raw(""),
    ];
    for l in textwrap(&q.prompt, cols[1].width.saturating_sub(2) as usize) {
        q_lines.push(Line::raw(l));
    }
    q_lines.push(Line::raw(""));
    match &q.kind {
        Kind::Choice { options, .. } => {
            for (i, opt) in options.iter().enumerate() {
                let sel = i == app.choice_cursor && lab.view == LabView::Questions;
                let marker = if sel { "▸ " } else { "  " };
                let st = if sel {
                    Style::default().fg(Color::Black).bg(ACCENT)
                } else {
                    Style::default()
                };
                q_lines.push(Line::from(vec![
                    Span::raw(marker),
                    Span::styled(opt.clone(), st),
                ]));
            }
        }
        Kind::Free(_) => {
            q_lines.push(Line::from(vec![
                Span::styled("> ", Style::default().fg(ACCENT)),
                Span::raw(app.input.clone()),
                Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
            ]));
        }
    }
    if let Some(fb) = &lab.feedback {
        q_lines.push(Line::raw(""));
        q_lines.push(Line::from(Span::styled(
            fb.clone(),
            Style::default().fg(Color::Yellow),
        )));
    }
    f.render_widget(
        Paragraph::new(q_lines)
            .wrap(Wrap { trim: true })
            .block(frame_block("investigation").border_style(q_style)),
        cols[1],
    );

    footer(
        f,
        rows[2],
        "Tab — switch panel · up/down — scroll/select · left/right — artifact · Enter — answer · Ctrl+S — skip",
    );
}

fn lab_results(f: &mut Frame, app: &App) {
    let Some(lab) = &app.lab else { return };
    let area = centered(f.area(), 76, 20);
    let (correct, wrong, skipped) = lab.tally();
    let strip: String = lab
        .outcomes
        .iter()
        .map(|o| format!("{} ", o.glyph()))
        .collect();

    let mut lines = vec![
        Line::from(Span::styled(
            format!("Results: {}", lab.scenario.title),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(strip),
        Line::raw(""),
        Line::from(vec![
            Span::styled(format!("✓ {correct}   "), Style::default().fg(Color::Green)),
            Span::styled(format!("✗ {wrong}   "), Style::default().fg(Color::Red)),
            Span::styled(format!("⭐ {skipped}"), Style::default().fg(Color::Yellow)),
        ]),
    ];
    if lab.timer.is_expired() {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "Time is up — the remaining questions counted as skipped.",
            Style::default().fg(Color::Red),
        )));
    }
    f.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .block(frame_block("results")),
        area,
    );
    let below = Rect {
        y: area.y + area.height,
        height: 2,
        ..area
    };
    let _ = app;
    footer(f, below, "n — another run (new seed) · Enter/Esc — menu");
}

fn error(f: &mut Frame, msg: &str) {
    let area = centered(f.area(), 80, 10);
    f.render_widget(
        Paragraph::new(msg.to_string())
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(Color::Red))
            .block(frame_block("error")),
        area,
    );
    let below = Rect {
        y: area.y + area.height,
        height: 1,
        ..area
    };
    footer(f, below, "Esc — menu");
}

/// Naive word wrapping (ratatui Wrap does not expose lines ahead of time).
fn textwrap(s: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![s.to_string()];
    }
    let mut out = Vec::new();
    let mut cur = String::new();
    for word in s.split_whitespace() {
        if cur.is_empty() {
            cur = word.to_string();
        } else if cur.chars().count() + 1 + word.chars().count() <= width {
            cur.push(' ');
            cur.push_str(word);
        } else {
            out.push(std::mem::take(&mut cur));
            cur = word.to_string();
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}
