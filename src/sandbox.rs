//! Real lab sandbox.
//!
//! Scenario artifacts are written to disk in a temp directory that mirrors real
//! paths (`$SANDBOX/var/log/auth.log` etc.) — you can inspect them with real
//! `cat` / `grep` / `less` from another terminal. For `caution/` the sandbox
//! additionally performs REAL local actions: listening and outbound loopback
//! sockets (visible in `ss -tnp` / `lsof` by PID) and real reads of decoy files
//! logged to its own activity log.
//!
//! The directory and all side effects are torn down when the lab exits (`Drop`).

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::scenario::{Category, GeneratedScenario};

/// Disable the sandbox entirely (tests, CI, `--no-sandbox`).
pub const DISABLE_ENV: &str = "HOLLOW_LABS_NO_SANDBOX";

pub struct Sandbox {
    pub root: PathBuf,
    /// (original artifact name -> real path on disk).
    pub files: Vec<(String, PathBuf)>,
    /// Category — decides whether to run real side effects.
    category: Category,
    stop: Option<Sender<()>>,
    worker: Option<JoinHandle<()>>,
    active: bool,
}

impl Sandbox {
    /// Creates the directory and materializes artifacts. `Ok(None)` — the
    /// sandbox is disabled via the env var. Filesystem errors are not fatal for
    /// the lab: the caller can continue with in-memory artifacts.
    pub fn create(scenario: &GeneratedScenario) -> std::io::Result<Option<Sandbox>> {
        if std::env::var_os(DISABLE_ENV).is_some() {
            return Ok(None);
        }
        let root = std::env::temp_dir().join(format!(
            "hollow-labs-{}-{}",
            std::process::id(),
            scenario.id
        ));
        Sandbox::build(scenario, root).map(Some)
    }

    /// Core without the env check: materializes artifacts into `root`.
    fn build(scenario: &GeneratedScenario, root: PathBuf) -> std::io::Result<Sandbox> {
        // Fresh directory on every run.
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;

        let mut files = Vec::with_capacity(scenario.artifacts.len());
        for art in &scenario.artifacts {
            let rel = sanitize(&art.name);
            let path = root.join(&rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, &art.body)?;
            files.push((art.name.clone(), path));
        }

        Ok(Sandbox {
            root,
            files,
            category: scenario.category,
            stop: None,
            worker: None,
            active: false,
        })
    }

    /// Starts real local side effects (only for `caution/`). Idempotent. Keeps
    /// sockets open until `Drop`.
    pub fn activate(&mut self) {
        if self.active || self.category != Category::Caution {
            self.active = true;
            return;
        }
        let (tx, rx) = mpsc::channel::<()>();
        let root = self.root.clone();
        let worker = thread::Builder::new()
            .name("hollow-labs-sandbox".into())
            .spawn(move || run_side_effects(root, rx))
            .ok();
        self.stop = Some(tx);
        self.worker = worker;
        self.active = true;
    }

    /// Short blurb for the briefing screen.
    pub fn hint(&self) -> String {
        match self.category {
            Category::Caution => format!(
                "Sandbox: {}\n\
                 Logs are real files (cat/grep/less). Real loopback sockets and\n\
                 decoy reads are running — check `ss -tnp` / `lsof -p {}` in another terminal.",
                self.root.display(),
                std::process::id()
            ),
            Category::Safe => format!(
                "Sandbox: {}\n\
                 Artifacts are laid out as real files — open them with cat/grep/less.",
                self.root.display()
            ),
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// `/var/log/auth.log` -> `var/log/auth.log`; strips `..` and forbidden
/// characters so writes cannot escape the sandbox.
fn sanitize(name: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in name.split(['/', '\\']) {
        match comp {
            "" | "." | ".." => continue,
            _ => {
                let safe: String = comp
                    .chars()
                    .map(|c| if c.is_control() || c == ':' { '_' } else { c })
                    .collect();
                out.push(safe);
            }
        }
    }
    if out.as_os_str().is_empty() {
        out.push("artifact.txt");
    }
    out
}

/// Worker body: real sockets + decoy reads until a stop signal arrives.
fn run_side_effects(root: PathBuf, rx: mpsc::Receiver<()>) {
    // 1. Decoy files — actually created, then actually read.
    let decoys = [
        (
            "opt/app/.env",
            "DB_PASSWORD=s3cr3t-prod\nAWS_SECRET_ACCESS_KEY=AKIA...\n",
        ),
        (
            "etc/hollow/passwd.bak",
            "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n",
        ),
    ];
    let mut decoy_paths = Vec::new();
    for (rel, body) in decoys {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if fs::write(&p, body).is_ok() {
            decoy_paths.push(p);
        }
    }

    // 2. Real loopback sockets: listeners + clients connected to them.
    let mut listeners = Vec::new();
    let mut streams = Vec::new();
    for _ in 0..3 {
        if let Ok(l) = TcpListener::bind("127.0.0.1:0") {
            if let Ok(addr) = l.local_addr() {
                if let Ok(client) = TcpStream::connect(addr) {
                    if let Ok((server, _)) = l.accept() {
                        streams.push(client);
                        streams.push(server);
                    }
                }
            }
            listeners.push(l);
        }
    }

    let activity = root.join("var/log/hollow-labs-activity.log");
    if let Some(parent) = activity.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let pid = std::process::id();
    let mut tick: u64 = 0;

    loop {
        match rx.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }

        // Real decoy read — issues an actual read() syscall.
        for p in &decoy_paths {
            if let Ok(mut f) = fs::File::open(p) {
                let mut buf = Vec::new();
                let _ = f.read_to_end(&mut buf);
                if let Ok(mut log) = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&activity)
                {
                    let _ = writeln!(
                        log,
                        "tick={tick} pid={pid} read {} ({} bytes)",
                        p.display(),
                        buf.len()
                    );
                }
            }
        }

        // Keep sockets alive with light keep-alive traffic.
        for i in (0..streams.len()).step_by(2) {
            if let (Some(a), Some(b)) = (streams.get(i), streams.get(i + 1)) {
                let mut a = a;
                let mut b = b;
                let _ = a.set_nonblocking(true);
                let _ = b.set_nonblocking(true);
                let _ = a.write_all(b"ping\n");
                let mut sink = [0u8; 64];
                let _ = b.read(&mut sink);
            }
        }

        tick += 1;
        thread::sleep(Duration::from_millis(500));
    }

    // Explicit cleanup of sockets and decoys (the directory is removed by Sandbox's Drop).
    drop(streams);
    drop(listeners);
    for p in decoy_paths {
        let _ = fs::remove_file(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::{Artifact, Category, GeneratedScenario};
    use std::collections::BTreeMap;

    fn scenario(cat: Category) -> GeneratedScenario {
        GeneratedScenario {
            id: "t".into(),
            title: "T".into(),
            category: cat,
            tools: vec![],
            facts: BTreeMap::new(),
            artifacts: vec![
                Artifact::new("/var/log/auth.log", "line 1\nline 2\n"),
                Artifact::new("/etc/iptables/rules.v4", "*filter\nCOMMIT\n"),
            ],
            questions: vec![],
        }
    }

    fn uniq_root(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hollow-labs-test-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn disabled_via_env_returns_none() {
        // Do not touch the global var (app tests set it in parallel) — just
        // check the fact: if the var is set, create returns None.
        std::env::set_var(DISABLE_ENV, "1");
        assert!(Sandbox::create(&scenario(Category::Safe))
            .unwrap()
            .is_none());
    }

    #[test]
    fn materializes_artifacts_as_real_files_and_cleans_up() {
        let root = uniq_root("mat");
        let dir;
        {
            let s = Sandbox::build(&scenario(Category::Safe), root.clone()).unwrap();
            dir = s.root.clone();
            let auth = s.root.join("var/log/auth.log");
            assert!(auth.is_file());
            assert_eq!(fs::read_to_string(&auth).unwrap(), "line 1\nline 2\n");
            assert!(s.root.join("etc/iptables/rules.v4").is_file());
        }
        assert!(!dir.exists(), "Drop must remove the directory");
    }

    #[test]
    fn sanitize_strips_traversal() {
        assert_eq!(
            sanitize("/var/log/auth.log"),
            PathBuf::from("var/log/auth.log")
        );
        assert_eq!(sanitize("../../etc/passwd"), PathBuf::from("etc/passwd"));
        assert_eq!(sanitize("///"), PathBuf::from("artifact.txt"));
    }

    #[test]
    fn caution_activate_runs_and_stops_cleanly() {
        let mut s = Sandbox::build(&scenario(Category::Caution), uniq_root("act")).unwrap();
        s.activate();
        thread::sleep(Duration::from_millis(120));
        assert!(s.worker.is_some());
        drop(s); // must not hang
    }

    #[test]
    fn safe_activate_is_noop_no_thread() {
        let mut s = Sandbox::build(&scenario(Category::Safe), uniq_root("safe")).unwrap();
        s.activate();
        assert!(s.worker.is_none());
    }
}
