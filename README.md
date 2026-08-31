# HOLLOW LABS

A TUI trainer for IR/SOC analysts, written in Rust. It simulates real attacks
with dynamic generation of artifacts (logs, config snippets) and questions
across three difficulty levels. No system dependencies, cross-compiles to
Linux/Windows, reproducible via `--seed`.

```
HOLLOW LABS
├── Quiz      theory, 30s per question, correct answers not shown in results
├── Safe      web attacks as local logs, 3 attempts per question, 15 minutes
└── Caution   system activity (processes, filesystem, loopback), 2 attempts, 15 minutes
```

## Running

```sh
cargo run                       # random seed
cargo run -- --seed 1337        # reproducible run (for groups and instructors)
cargo run -- --no-sandbox       # do not write artifacts to disk or open sockets
cargo run -- --dump bruteforce --seed 42 --level intermediate   # artifacts to stdout, no TUI
cargo run -- --help
```

Controls: arrows — navigate, `Enter` — select, `Esc` — back, `Tab` — switch
panels in a lab, `Ctrl+S` — skip a question, `Ctrl+C` — quit.

## Demo

A static transcript of a run (artifact generation + questions for one `--seed`)
is in [`docs/sample-run.md`](docs/sample-run.md), regenerated with `make sample`.

Animated gif: `make demo` renders [`demo.tape`](demo.tape) with
[vhs](https://github.com/charmbracelet/vhs) into `docs/demo.gif` (needs a
release build and vhs installed). After rendering, add `![demo](docs/demo.gif)`
here.

## Sandbox

When a lab starts, artifacts are laid out as **real files** in a temp directory
that mirrors real paths:

```
$TMPDIR/hollow-labs-<pid>-<id>/
├── var/log/auth.log
├── var/log/audit/audit.log
└── etc/iptables/rules.v4
```

You can inspect them with real `cat` / `grep` / `less` / `awk` from another
terminal — the path is shown on the briefing screen. For `caution/` the sandbox
also opens **real** loopback sockets (visible in `ss -tnp` / `lsof -p <pid>`)
and performs real reads of decoy files logged to
`var/log/hollow-labs-activity.log`. All of it is torn down when the lab exits.
Disable with `--no-sandbox` or the `HOLLOW_LABS_NO_SANDBOX=1` variable.

## Levels

| Level | Questions | Input | Hints | Timer |
|---|---|---|---|---|
| Beginner | 2-3 | choices only | yes | soft |
| Intermediate | 3-4 | choices + free | no | normal |
| Advanced | 4-5 | mostly free | no | strict |

The level is picked on first launch, stored in
`$XDG_CONFIG_HOME/hollow-labs/config.toml`, and changed in settings.

## Architecture

| Module | Purpose |
|---|---|
| `rng` | deterministic PRNG (xorshift128+ / splitmix64), one seed -> one stream |
| `timer` | countdown with colour phases (green -> yellow -> red + blink) |
| `validator` | answer normalization and checking (free input / choices) |
| `question` | shared question model + TOML parsing |
| `config` | user config (level) |
| `quiz` | bank loading, run state, replay |
| `scenario` | lab model, the `Generator` trait, registry, fact substitution |
| `scenario::gen` | artifact generation primitives (IPs, timestamps, ports, UAs) |
| `sandbox` | materialize artifacts to disk + real loopback sockets and decoy reads for `caution/` |
| `app` / `ui` | screen state and rendering (ratatui + crossterm) |

The contract for new scenarios and quiz banks is in [`docs/SPEC.md`](docs/SPEC.md).
The product plan is in [`docs/PLAN.md`](docs/PLAN.md).

## Tests

```sh
cargo test
```

## Status

Phases 1-6 are complete:

- core (`rng` / `timer` / `validator` / `question` / `config`), 59 tests;
- TUI on ratatui + crossterm: menu, level select, settings, Quiz, lab;
- Quiz — 4 banks (`fundamentals`, `web_attacks`, `host_forensics`,
  `detection_ops`), 30s/question, 2 attempts, results without correct answers;
- all 10 scenarios with full artifact generators
  (`safe/`: ddos, sqli, xss, csrf, phishing; `caution/`: cred_spoof, cred_leak,
  bruteforce, internal_breach, unknown_ip);
- on-disk sandbox + real loopback sockets and decoy reads for `caution/`;
- `--dump <id>` for inspecting content without the TUI;
- CI (fmt / clippy `-D warnings` / test / release), rustfmt, cross-compilation.

How to add scenarios and banks — [`docs/SPEC.md`](docs/SPEC.md). The
`scenario::stub::Stub` template is kept as a reference for new scenarios. Next
up — ideas from [`docs/PLAN.md`](docs/PLAN.md) (multiplayer Blue vs Red).

## Cross-compilation

The binary pulls in no system dependencies, so it builds for other platforms
with a single command. You just need the target and, for Windows, the
`mingw-w64` cross-linker.

```sh
# Windows x86-64 (GNU ABI)
rustup target add x86_64-pc-windows-gnu
sudo apt install mingw-w64            # or: pacman -S mingw-w64-gcc
cargo build --release --target x86_64-pc-windows-gnu
# -> target/x86_64-pc-windows-gnu/release/hollow-labs.exe

# Linux x86-64, statically linked against musl (no glibc on the target)
rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools
cargo build --release --target x86_64-unknown-linux-musl
# -> target/x86_64-unknown-linux-musl/release/hollow-labs
```

The build artifacts land in `target/<target>/release/`. The `release` profile
is already tuned for a small binary (`opt-level = "z"`, `lto`, `strip`,
`panic = "abort"`).

## CI

`.github/workflows/ci.yml` runs on every push and pull request on the stable
toolchain with cargo caching and executes:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
cargo build --release
```

Run the same commands locally before committing.
