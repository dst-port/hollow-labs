//! User config: the level is picked on first launch, written to
//! `$XDG_CONFIG_HOME/hollow-labs/config.toml` (or `~/.config/...`), and changed
//! from settings inside the TUI.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::question::Level;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Config {
    /// `None` — level not chosen yet, show the selection screen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<LevelField>,
}

/// Wrapper to (de)serialize `Level` as a string in TOML.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LevelField {
    Beginner,
    Intermediate,
    Advanced,
}

impl From<Level> for LevelField {
    fn from(l: Level) -> Self {
        match l {
            Level::Beginner => LevelField::Beginner,
            Level::Intermediate => LevelField::Intermediate,
            Level::Advanced => LevelField::Advanced,
        }
    }
}

impl From<LevelField> for Level {
    fn from(l: LevelField) -> Self {
        match l {
            LevelField::Beginner => Level::Beginner,
            LevelField::Intermediate => Level::Intermediate,
            LevelField::Advanced => Level::Advanced,
        }
    }
}

impl Config {
    pub fn level(&self) -> Option<Level> {
        self.level.map(Into::into)
    }

    pub fn set_level(&mut self, level: Level) {
        self.level = Some(level.into());
    }

    /// Path to the config file. `HOLLOW_LABS_CONFIG` overrides everything (for tests).
    pub fn path() -> PathBuf {
        if let Some(p) = std::env::var_os("HOLLOW_LABS_CONFIG") {
            return PathBuf::from(p);
        }
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("hollow-labs").join("config.toml")
    }

    /// Reads the config. A missing or broken file -> default (not an error).
    pub fn load() -> Self {
        let path = Self::path();
        let Ok(text) = fs::read_to_string(&path) else {
            return Self::default();
        };
        toml::from_str(&text).unwrap_or_default()
    }

    /// Writes the config, creating parent directories.
    pub fn save(&self) -> std::io::Result<()> {
        let path = Self::path();
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let text = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(path, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_level() {
        let mut c = Config::default();
        assert_eq!(c.level(), None);
        c.set_level(Level::Advanced);
        let text = toml::to_string(&c).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back.level(), Some(Level::Advanced));
    }

    #[test]
    fn broken_file_is_default() {
        let c: Config = toml::from_str("this is not toml =").unwrap_or_default();
        assert_eq!(c.level(), None);
    }
}
