# SPEC — how to add a scenario or a quiz bank

The contract is stable. Do not change the signatures of `Generator`,
`Question`, `RawQuestion`, `build_questions`, `Rng` without coordination — every
scenario depends on them.

## 1. A new lab scenario

File: `src/scenario/<safe|caution>/<id>.rs`. Reference — `src/scenario/safe/ddos.rs`.

### 1.1 Implement the trait

```rust
use crate::scenario::{Generator, Category, GeneratedScenario, Artifact, build_questions};
use crate::scenario::gen::*;   // primitives: public_ip, private_ip, ip_in_subnet,
                               // subnet_base, ipv4, nginx_ts, syslog_ts, clock,
                               // ephemeral_port, pid, browser_ua, tool_ua
use crate::question::{Level, Question};
use crate::rng::Rng;

pub struct Sqli;

impl Generator for Sqli {
    fn id(&self) -> &'static str { "sqli" }          // unique, snake_case
    fn title(&self) -> &'static str { "SQLi Detection" }
    fn category(&self) -> Category { Category::Safe } // Safe: 3 attempts; Caution: 2
    fn tools(&self) -> Vec<String> {                  // the pre-start briefing screen
        ["...","..."].iter().map(|s| s.to_string()).collect()
    }
    fn generate(&self, rng: &mut Rng, level: Level) -> GeneratedScenario {
        // 1. randomize parameters ONLY through rng (deterministic per seed!)
        // 2. build artifacts (logs, config snippets) — like a real system
        // 3. fill facts: BTreeMap<String,String> — keys for placeholders
        // 4. questions = build_questions(QUESTIONS, &facts, level, rng)?
    }
}

const QUESTIONS: &str = include_str!("../../../data/scenarios/safe/sqli.toml");
```

### 1.2 Rules

- **Determinism.** All randomness goes through the passed `rng`. No
  `std::time`, `SystemTime`, `rand`, or global state. One seed -> a byte-for-byte
  identical run. Add a `same_seed_same_output` test (see ddos).
- **`facts`** is the source of truth. A `{key}` placeholder in a TOML question is
  replaced with `facts["key"]`. The correct answer must always be derivable from
  the generated artifacts — never stored separately.
- **Artifacts** are multi-line strings, named like real paths
  (`/var/log/nginx/access.log`, `/etc/iptables/rules.v4`). Noise + signal: most
  lines legitimate, the attack interleaved. Laying them out on disk and running
  real side effects (loopback sockets, decoy reads for `caution/`) is done by
  `crate::sandbox` — the generator does NOT perform them, it only describes the
  artifacts.
- **False positive.** A mode where the "attack" is sometimes absent is planned
  for safe scenarios — the verdict is in `facts["verdict"]`, and the beginner
  "attack / legitimate" question should work both ways.
- **Levels.** Do not filter questions by hand — `build_questions` does it by the
  `level` field and `Level::question_count()`. Hints are dropped automatically
  on non-Beginner.
- Every generator ships with unit tests: output shape at all levels +
  determinism.

### 1.3 Register it

In `src/scenario/safe/mod.rs` or `caution/mod.rs`:

```rust
pub mod sqli;
// in generators(): remove the matching Stub, add Box::new(sqli::Sqli),
```

Any remaining stubs in `mod.rs` are marked `TODO`. The registry is checked by
the `registry_ids_are_unique` test.

## 2. Scenario question TOML

File: `data/scenarios/<safe|caution>/<id>.toml`. Format:

```toml
[[question]]
level = "beginner"        # beginner | intermediate | advanced — MINIMUM level
kind  = "choice"          # choice | free
prompt = "Which subnet is the load on {endpoint} coming from?"
options = ["option 0", "option 1"]   # choice only
answer = "1"              # choice: index of the correct one; free: canonical string (may use {placeholder})
normalize = "casefold"    # free: trim | casefold | digits | ip
accept = ["alt answer"]   # free: extra accepted strings (may use {placeholder})
hint = "..."              # opt., shown only on beginner
```

Keep 4-6 questions per scenario, covering all three levels (plan: beginner —
"attack or not", intermediate — free input of a fact, advanced — type/mechanism).

For "classify into one of N" advanced questions, do not list every option in
`accept` — that would accept any of them regardless of the actual answer. Either
drop `accept` (and state the exact expected token in the prompt) or template a
per-answer synonym via a `{..._short}` fact.

## 3. Quiz bank

File: `data/quiz/<topic>.toml`, the same `[[question]]` format but **without
placeholders** (fixed answers). Wire it into `BANKS` in `src/quiz/mod.rs`. The
app shuffles the order of questions and options itself; correct answers are not
shown in the results — do not write explanations into `prompt`.

## 4. Local check

```sh
cargo test          # registry, determinism, TOML parsing
cargo run -- --seed 1   # walk through your scenario by hand
cargo clippy
```
