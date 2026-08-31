//! `caution/` — real system activity: processes, filesystem, loopback network.
//! Credential Spoofing, Credential Leak, Bruteforce, Internal Breaches, Unknown IP.
//! 2 attempts per answer, a warning at start.

pub mod bruteforce;
pub mod cred_leak;
pub mod cred_spoof;
pub mod internal_breach;
pub mod unknown_ip;

use crate::scenario::Generator;

pub fn generators() -> Vec<Box<dyn Generator>> {
    vec![
        Box::new(cred_spoof::Type),
        Box::new(cred_leak::Type),
        Box::new(bruteforce::Type),
        Box::new(internal_breach::Type),
        Box::new(unknown_ip::Type),
    ]
}
