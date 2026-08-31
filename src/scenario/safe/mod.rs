//! `safe/` — web attacks, generated as local logs, no external load.
//! DDoS, SQLi, XSS, CSRF, Phishing.

pub mod csrf;
pub mod ddos;
pub mod phishing;
pub mod sqli;
pub mod xss;

use crate::scenario::Generator;

pub fn generators() -> Vec<Box<dyn Generator>> {
    vec![
        Box::new(ddos::Ddos),
        Box::new(sqli::Sqli),
        Box::new(xss::Xss),
        Box::new(csrf::Csrf),
        Box::new(phishing::Phishing),
    ]
}
