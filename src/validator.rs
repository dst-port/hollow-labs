//! Answer checking.
//!
//! Two question types from the plan:
//!  - free input — IP, port, PID, timestamp, domain: a single answer, but the
//!    user may format it differently (spaces, case, `:port`);
//!  - multiple choice — matched by the index of the selected option.
//!
//! We do not grade phrasing: "conceptual" questions always offer choices, and
//! free input is kept only where the answer is atomic.

/// How to normalize free input before comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Normalize {
    /// Trim + collapse whitespace, keep case.
    #[default]
    Trim,
    /// `Trim` + lowercase (domains, user-agents, methods).
    Casefold,
    /// Digits only (PID, port, counters) — drop everything else.
    Digits,
    /// IP address: strip `:port`, IPv6 brackets, leading zeros in octets.
    Ip,
}

/// Spec of the correct answer to a free-input question.
#[derive(Clone, Debug)]
pub struct FreeAnswer {
    /// Accepted variants (after normalization). Usually one.
    pub accept: Vec<String>,
    pub normalize: Normalize,
}

impl FreeAnswer {
    pub fn new(answer: impl Into<String>) -> Self {
        Self {
            accept: vec![answer.into()],
            normalize: Normalize::Trim,
        }
    }

    pub fn with(mut self, alt: impl Into<String>) -> Self {
        self.accept.push(alt.into());
        self
    }

    pub fn normalize(mut self, n: Normalize) -> Self {
        self.normalize = n;
        self
    }

    /// Whether the user's input is correct.
    pub fn check(&self, input: &str) -> bool {
        let got = normalize(input, self.normalize);
        if got.is_empty() {
            return false;
        }
        self.accept
            .iter()
            .any(|a| normalize(a, self.normalize) == got)
    }
}

/// Spec of a multiple-choice question.
#[derive(Clone, Debug)]
pub struct ChoiceAnswer {
    /// Indices of the correct options (usually one).
    pub correct: Vec<usize>,
    pub options_len: usize,
}

impl ChoiceAnswer {
    pub fn single(correct: usize, options_len: usize) -> Self {
        Self {
            correct: vec![correct],
            options_len,
        }
    }

    pub fn check(&self, selected: usize) -> bool {
        self.correct.contains(&selected)
    }

    pub fn check_multi(&self, selected: &[usize]) -> bool {
        let mut a: Vec<usize> = self.correct.clone();
        let mut b: Vec<usize> = selected.to_vec();
        a.sort_unstable();
        a.dedup();
        b.sort_unstable();
        b.dedup();
        a == b
    }
}

/// Normalize a string with the chosen strategy.
pub fn normalize(s: &str, mode: Normalize) -> String {
    let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
    match mode {
        Normalize::Trim => collapsed,
        Normalize::Casefold => collapsed.to_lowercase(),
        Normalize::Digits => collapsed.chars().filter(|c| c.is_ascii_digit()).collect(),
        Normalize::Ip => normalize_ip(collapsed.trim()),
    }
}

fn normalize_ip(s: &str) -> String {
    let mut host = s.trim();

    // Bracketed IPv6: [::1]:8080 -> ::1
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_lowercase();
        }
    }

    // IPv4 with a port: 10.0.0.1:443 -> 10.0.0.1 (IPv6 has many colons — leave it)
    if host.matches(':').count() == 1 {
        if let Some((ip, _port)) = host.split_once(':') {
            host = ip;
        }
    }

    // Leading zeros in IPv4 octets: 010.000.001.005 -> 10.0.1.5
    if host.split('.').count() == 4 && host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return host
            .split('.')
            .map(|o| o.trim_start_matches('0'))
            .map(|o| if o.is_empty() { "0" } else { o })
            .collect::<Vec<_>>()
            .join(".");
    }

    host.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_trim_and_casefold() {
        let a = FreeAnswer::new("Union-based").normalize(Normalize::Casefold);
        assert!(a.check("  union-based "));
        assert!(a.check("UNION-BASED"));
        assert!(!a.check("boolean-based"));
    }

    #[test]
    fn free_digits() {
        let a = FreeAnswer::new("4145").normalize(Normalize::Digits);
        assert!(a.check("pid 4145"));
        assert!(a.check("4145"));
        assert!(!a.check("4146"));
    }

    #[test]
    fn free_ip_forms() {
        let a = FreeAnswer::new("10.0.1.5").normalize(Normalize::Ip);
        assert!(a.check("10.0.1.5:443"));
        assert!(a.check("010.000.001.005"));
        assert!(a.check(" 10.0.1.5 "));
        assert!(!a.check("10.0.1.6"));
    }

    #[test]
    fn free_ipv6_bracketed() {
        let a = FreeAnswer::new("::1").normalize(Normalize::Ip);
        assert!(a.check("[::1]:8080"));
    }

    #[test]
    fn empty_input_never_passes() {
        let a = FreeAnswer::new("x");
        assert!(!a.check(""));
        assert!(!a.check("   "));
    }

    #[test]
    fn choice_single_and_multi() {
        let c = ChoiceAnswer::single(2, 4);
        assert!(c.check(2));
        assert!(!c.check(0));

        let m = ChoiceAnswer {
            correct: vec![0, 3],
            options_len: 4,
        };
        assert!(m.check_multi(&[3, 0]));
        assert!(!m.check_multi(&[0]));
    }
}
