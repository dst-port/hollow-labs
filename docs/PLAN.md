# HOLLOW LABS — product plan

> A TUI trainer for IR/SOC analysts, written in Rust. Simulation of real attacks
> with dynamic generation of artifacts and quizzes.

## Product structure

```
HOLLOW LABS
├── Quiz      theory, 30s per question, no correct answers in the results
├── Safe      false positives + simulation, 3 attempts, 15 minutes
└── Caution   real activity, 2 attempts, 15 minutes
```

## Mechanics

### General
- Everything in a TUI (ratatui + crossterm)
- Arrow navigation, Enter to select
- No external system dependencies, cross-compiles to Linux/Windows
- Scenarios and quizzes in TOML, parameters randomized by seed
- `--seed N` for reproducibility (groups, instructors)

### User levels
Picked on first launch, stored in the config, changed in settings.

- **Beginner** — 2-3 questions, choices only, hints allowed, simple wording
- **Intermediate** — 3-4 questions, mix of free input and choices, no hints
- **Advanced** — 4-5 questions, more free input, fewer choices, stricter timer

In the results: if you cleared every question of the level, offer the next one.

### Question types
- **Free input** — IP, port, PID, timestamp (a single answer)
- **Multiple choice** — misconfigurations, config lines, attack type, concepts
  (so you are not graded on phrasing)

### Quiz
- 30 seconds per question
- Timer changes colour: green -> yellow (15s) -> red + blink (5s)
- 2 attempts per question
- Time running out = skip (does not spend attempts)
- Results screen: correct / wrong / skipped — **the correct answer is not shown**
- Replay with a randomized order of questions and options

### Safe / Caution
- Before a lab starts — a list of recommended tools and commands
- The binary generates artifacts as close to reality as possible
- Parameters are randomized on every run (IPs, ports, filenames, timings)
- Safe: 3 attempts per answer, 15 minutes
- Caution: 2 attempts per answer, 15 minutes, a warning at start

## Development phases

1. **Architecture** — Cargo layout, modules `timer` / `validator` /
   `scenario_loader` / `quiz_loader`, TOML data formats — done
2. **TUI scaffold** — main menu (Quiz / Safe / Caution), navigation, layout — done
3. **Quiz module** — load from TOML, 30s timer, 2 attempts, skip on timeout,
   results screen without correct answers — done
4. **Safe scenarios** — artifact/log generator, randomization, dynamic question
   generation from real values — done (5/5: ddos, sqli, xss, csrf, phishing)
5. **Caution scenarios** — real system activity, a warning at start, 2 attempts —
   done (5/5: cred_spoof, cred_leak, bruteforce, internal_breach, unknown_ip).
   Real side effects (loopback sockets, decoy-file reads, laying logs out on
   disk) live in `crate::sandbox`.
6. **Polish** — done: README with examples, `--dump` for content inspection,
   CI (fmt/clippy/test/release), rustfmt, cross-compilation. Demo gif — TODO.

## Scenario classification

**`safe/`** — web attacks, generated as logs locally, with no real load on
external resources: DDoS Mitigation, SQLi, XSS, CSRF, Phishing.

**`caution/`** — local system activity (processes, filesystem, in-host network):
Credential Spoofing, Credential Leak, Bruteforce, Internal Breaches, Unknown IP
Access.

## Scenarios

### 1. DDoS Mitigation — `safe/`
Generated: a sharp spike of requests from random IPs against one endpoint; some
IPs from a single subnet (botnet hint); some traffic legitimate (noise); a
deliberately broken firewall config snippet (commented-out rate-limit /
`ACCEPT ALL` above the blocking rule / an overly wide `/16` whitelist).
Tools: `netstat`, `ss`, `tcpdump`, `iptables -L -n -v`,
`/var/log/nginx/access.log`, `/etc/nginx/nginx.conf`, `/etc/iptables/rules.v4`.
Questions: [B] DDoS or a legitimate spike · [I] which IP range the load comes
from · [A] which misconfiguration let the traffic through.

### 2. SQLi Detection — `safe/`
Web-server logs with legitimate requests (noise) + interleaved SQLi
(`' OR 1=1--`, `UNION SELECT`, `'; DROP TABLE`). Random: parameter (`id`,
`user`, `search`), endpoint, injection type. FP — strange but legitimate strings.
Tools: `/var/log/{nginx,apache2}/access.log`, `grep`, `awk`, `cut`, `less`,
`tail -f`.
Questions: [B] SQLi or legitimate · [I] which parameter carries the payload ·
[A] SQLi type (Union / Boolean / Error-based).

### 3. XSS Detection — `safe/`
Logs + XSS attempts (`<script>alert(1)</script>`, `onerror=`, `javascript:`,
`<img src=x>`). Random: parameter (`comment`, `search`, `name`, `redirect`),
endpoint, XSS type. FP — legitimate HTML characters in parameters.
Tools: `access.log`, `grep`, `awk`, `cut`, urldecode.
Questions: [B] XSS or legitimate · [I] which parameter carries the payload ·
[A] obfuscation (URL-encoded / Base64 / Plaintext).

### 4. CSRF Detection — `safe/`
Logs with legitimate POSTs + CSRF attempts (no token / invalid token / foreign
origin). Random: endpoint (`/transfer`, `/settings`, `/password`), method,
origin. FP — legitimate requests with an unusual but valid origin.
Tools: `access.log`, `grep`, `awk`, `Referer` / `Origin` headers.
Questions: [B] is there a CSRF token · [I] which origin the suspicious request
comes from · [A] why the server let the token-less request through.

### 5. Phishing Detection — `safe/`
Email logs with legitimate mail (noise) + phishing (forged sender, suspicious
links, domain mismatch). Random: domain (`paypa1.com`, `g00gle.com`), sender
name, subject, attack type. FP — legitimate marketing with suspicious-looking
links.
Tools: `/var/log/mail.log`, `grep`, `awk`, `From`, `Reply-To`, `Return-Path`,
`Received` headers.
Questions: [B] phishing or legitimate · [I] the real sender domain from the
headers · [A] technique (Typosquatting / Spoofing / Homograph).

### 6. Credential Spoofing Detection — `caution/`
Auth logs with legitimate logins (noise) + login attempts with valid
credentials but from an anomalous IP/device. Random anomaly: IP from another
country; impossible travel between two IPs; a mismatched client (always
Chrome/Windows, suddenly curl); an odd hour (login at 3 AM). Real activity: the
binary creates PAM/auth-style artifacts.
Tools: `/var/log/auth.log`, `/var/log/secure`, `last`, `lastb`, `who`.
Questions: [B] legitimate login or spoofing · [I] which IP the suspicious login
came from · [A] which anomaly exactly points to spoofing.

### 7. Credential Leak Detection — `caution/`
File-activity and network-traffic logs (noise) + an anomalous read of sensitive
files (`/etc/passwd`, `.env`, configs with passwords). Random: which file, which
process read it, where the data went (external IP / local file). Real activity:
the binary actually reads test decoy files and logs it.
Tools: `/var/log/audit/audit.log`, `auditctl`, `ausearch`, `lsof`, `inotifywait`.
Questions: [B] legitimate access or a leak · [I] which PID got access ·
[A] where the data went (external IP / local dump / unknown).

### 8. Bruteforce Detection — `caution/`
Auth logs with legitimate logins (noise) + a run of failed attempts from one or
more IPs. Random: IP, target account, interval between attempts, service
(SSH / FTP / web panel). Real activity: entries in `/var/log/auth.log`.
Tools: `/var/log/auth.log`, `/var/log/secure`, `lastb`, `fail2ban-client status`,
`grep`, `awk`, `uniq -c`, `sort`.
Questions: [B] brute force or legitimate errors · [I] how many attempts and from
which IP · [A] manual guessing or an automated tool (by the intervals).

### 9. Internal Breaches Detection — `caution/`
Internal network-activity logs (noise) + anomalous lateral movement — a user
reaching resources beyond their rights. Random: account, resources, time, access
method. Real activity: the binary creates files and connections on behalf of a
test user.
Tools: `/var/log/auth.log`, `/var/log/audit/audit.log`, `ss`, `netstat`.
Questions: [B] legitimate access or a breach · [I] which resource was accessed
without authorization · [A] method (privilege escalation / credential reuse /
misconfigured permissions).

### 10. User Access from Unknown IP — `caution/`
Network-connection logs (noise — known IPs) + a connection to internal resources
from an IP not in the history. Random: IP, time, resource, protocol
(SSH / RDP / SMB). Real activity: the binary creates real loopback connections.
Tools: `/var/log/auth.log`, `ss -tnp`, `netstat -tnp`, `last`, `who`.
Questions: [B] known IP or anomalous · [I] which IP and which resource · [A] new
legitimate user / compromised account / external attacker — what the logs show.

## Ideas for future updates

### Multiplayer — Blue vs Red
- A shared server for state synchronization
- Roles: Blue Team (defenders) vs Red Team (attackers)
- Simulation of a real SOC vs a pentester scenario
- Friends play together as a real team
