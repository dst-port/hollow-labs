//! Countdown with a colour indicator.
//!
//! Quiz: 30s per question. Green -> yellow (<=15s) -> red + blink (<=5s).
//! Safe/Caution use the same timer with a larger limit (15 minutes per lab).

use std::time::{Duration, Instant};

/// Timer colour phase — mapped to the palette in `ui`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Plenty of time left.
    Calm,
    /// Time to hurry (default: <= 50% of the limit, or <= 15s for the quiz).
    Warn,
    /// Almost out — the widget should blink.
    Critical,
}

/// Phase switch thresholds (in seconds remaining).
#[derive(Clone, Copy, Debug)]
pub struct Thresholds {
    pub warn_secs: u64,
    pub critical_secs: u64,
}

impl Thresholds {
    /// Thresholds for the 30-second quiz from the plan.
    pub const QUIZ: Thresholds = Thresholds {
        warn_secs: 15,
        critical_secs: 5,
    };

    /// Thresholds for the 15-minute lab.
    pub const LAB: Thresholds = Thresholds {
        warn_secs: 180,
        critical_secs: 30,
    };
}

/// Monotonic countdown. Does not tick by itself — polled from the render loop.
#[derive(Clone, Debug)]
pub struct Timer {
    limit: Duration,
    started: Instant,
    paused_at: Option<Instant>,
    paused_total: Duration,
    thresholds: Thresholds,
}

impl Timer {
    pub fn new(limit: Duration, thresholds: Thresholds) -> Self {
        Self {
            limit,
            started: Instant::now(),
            paused_at: None,
            paused_total: Duration::ZERO,
            thresholds,
        }
    }

    pub fn from_secs(secs: u64, thresholds: Thresholds) -> Self {
        Self::new(Duration::from_secs(secs), thresholds)
    }

    /// Resets the countdown to a new limit (next question).
    pub fn restart(&mut self, limit: Duration) {
        self.limit = limit;
        self.started = Instant::now();
        self.paused_at = None;
        self.paused_total = Duration::ZERO;
    }

    pub fn pause(&mut self) {
        if self.paused_at.is_none() {
            self.paused_at = Some(Instant::now());
        }
    }

    pub fn resume(&mut self) {
        if let Some(at) = self.paused_at.take() {
            self.paused_total += at.elapsed();
        }
    }

    fn active_elapsed(&self) -> Duration {
        let raw = self.started.elapsed() - self.paused_total;
        match self.paused_at {
            Some(at) => raw.saturating_sub(at.elapsed()),
            None => raw,
        }
    }

    /// How much is left. Zero once time is up.
    pub fn remaining(&self) -> Duration {
        self.limit.saturating_sub(self.active_elapsed())
    }

    pub fn remaining_secs(&self) -> u64 {
        // Round up so "1" holds for a full second instead of flickering.
        let r = self.remaining();
        r.as_secs() + u64::from(r.subsec_millis() > 0)
    }

    pub fn is_expired(&self) -> bool {
        self.remaining().is_zero()
    }

    /// Fraction of elapsed time, 0.0..=1.0 — for the gauge widget.
    pub fn ratio(&self) -> f64 {
        if self.limit.is_zero() {
            return 1.0;
        }
        (self.active_elapsed().as_secs_f64() / self.limit.as_secs_f64()).clamp(0.0, 1.0)
    }

    pub fn phase(&self) -> Phase {
        let left = self.remaining_secs();
        if left <= self.thresholds.critical_secs {
            Phase::Critical
        } else if left <= self.thresholds.warn_secs {
            Phase::Warn
        } else {
            Phase::Calm
        }
    }

    /// Whether the widget should be visible right now (blink in Critical, ~2 Hz).
    pub fn blink_on(&self) -> bool {
        if self.phase() != Phase::Critical {
            return true;
        }
        (self.active_elapsed().as_millis() / 250).is_multiple_of(2)
    }

    /// `MM:SS` for the remaining time.
    pub fn label(&self) -> String {
        let s = self.remaining_secs();
        format!("{:02}:{:02}", s / 60, s % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_timer_is_calm_and_full() {
        let t = Timer::from_secs(30, Thresholds::QUIZ);
        assert_eq!(t.phase(), Phase::Calm);
        assert!(!t.is_expired());
        assert!(t.ratio() < 0.05);
        assert_eq!(t.label(), "00:30");
    }

    #[test]
    fn phase_thresholds() {
        let mut t = Timer::from_secs(30, Thresholds::QUIZ);
        // Simulate elapsed time by moving the start point into the past.
        t.started = Instant::now() - Duration::from_secs(20);
        assert_eq!(t.phase(), Phase::Warn); // ~10s left
        t.started = Instant::now() - Duration::from_secs(27);
        assert_eq!(t.phase(), Phase::Critical); // ~3s left
        t.started = Instant::now() - Duration::from_secs(40);
        assert!(t.is_expired());
        assert_eq!(t.phase(), Phase::Critical);
        assert_eq!(t.label(), "00:00");
    }

    #[test]
    fn pause_freezes_remaining() {
        let mut t = Timer::from_secs(30, Thresholds::QUIZ);
        t.started = Instant::now() - Duration::from_secs(10);
        t.pause();
        let a = t.remaining_secs();
        std::thread::sleep(Duration::from_millis(30));
        let b = t.remaining_secs();
        assert_eq!(a, b);
        t.resume();
    }
}
