//! Artifact generation primitives: IPs, timestamps, ports, user-agents.
//! Shared across all scenarios so logs look uniform and "real".

use crate::rng::Rng;

/// Public ranges for "external" addresses (TEST-NET from RFC 5737 — safe to
/// print in logs, owned by nobody).
pub const TEST_NETS: [(u32, u8); 3] = [
    (0xC000_0200, 24), // 192.0.2.0/24
    (0xC633_6400, 24), // 198.51.100.0/24
    (0xCB00_7100, 24), // 203.0.113.0/24
];

/// Random "external" IPv4 from TEST-NET.
pub fn public_ip(rng: &mut Rng) -> String {
    let (base, _) = TEST_NETS[rng.below(TEST_NETS.len() as u64) as usize];
    let host = rng.range(1, 254) as u32;
    ipv4(base | host)
}

/// Random IP from a single `/24` subnet — a "botnet" with a shared prefix.
pub fn ip_in_subnet(rng: &mut Rng, base_slash24: u32) -> String {
    ipv4((base_slash24 & 0xFFFF_FF00) | rng.range(1, 254) as u32)
}

/// Base of a random `/24` from TEST-NET (for clustering addresses).
pub fn subnet_base(rng: &mut Rng) -> u32 {
    let (base, _) = TEST_NETS[rng.below(TEST_NETS.len() as u64) as usize];
    base & 0xFFFF_FF00
}

/// Private IP (RFC 1918) — an "internal" host.
pub fn private_ip(rng: &mut Rng) -> String {
    match rng.below(3) {
        0 => ipv4(0x0A00_0000 | rng.range(1, 0x00FF_FFFE) as u32), // 10/8
        1 => ipv4(0xAC10_0000 | rng.range(1, 0x000F_FFFE) as u32), // 172.16/12
        _ => ipv4(0xC0A8_0000 | rng.range(1, 0xFFFE) as u32),      // 192.168/16
    }
}

pub fn ipv4(n: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (n >> 24) & 0xFF,
        (n >> 16) & 0xFF,
        (n >> 8) & 0xFF,
        n & 0xFF
    )
}

pub const USER_AGENTS: [&str; 6] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "curl/8.7.1",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
];

pub fn browser_ua(rng: &mut Rng) -> &'static str {
    USER_AGENTS[rng.below(3) as usize]
}

pub fn tool_ua(rng: &mut Rng) -> &'static str {
    USER_AGENTS[3 + rng.below(3) as usize]
}

/// Seconds from "run midnight" formatted as `HH:MM:SS`.
pub fn clock(secs_from_midnight: u64) -> String {
    let s = secs_from_midnight % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

/// A string like `[31/Aug/2026:HH:MM:SS +0000]` for nginx-style logs.
pub fn nginx_ts(secs_from_midnight: u64) -> String {
    format!("[31/Aug/2026:{} +0000]", clock(secs_from_midnight))
}

/// A string like `Aug 31 HH:MM:SS host` for syslog-style logs.
pub fn syslog_ts(secs_from_midnight: u64, host: &str) -> String {
    format!("Aug 31 {} {}", clock(secs_from_midnight), host)
}

/// A random "ephemeral" client port.
pub fn ephemeral_port(rng: &mut Rng) -> u16 {
    rng.range(32_768, 60_999) as u16
}

/// A random PID.
pub fn pid(rng: &mut Rng) -> u32 {
    rng.range(300, 32_000) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_formats_octets() {
        assert_eq!(ipv4(0xC000_0207), "192.0.2.7");
    }

    #[test]
    fn subnet_keeps_prefix() {
        let mut r = Rng::new(3);
        let base = 0xC000_0200;
        for _ in 0..200 {
            let ip = ip_in_subnet(&mut r, base);
            assert!(ip.starts_with("192.0.2."));
        }
    }

    #[test]
    fn clock_wraps_day() {
        assert_eq!(clock(0), "00:00:00");
        assert_eq!(clock(3661), "01:01:01");
        assert_eq!(clock(86_400), "00:00:00");
    }
}
