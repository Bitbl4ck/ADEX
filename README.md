```
  /$$$$$$  /$$$$$$$  /$$$$$$$$ /$$   /$$
 /$$__  $$| $$__  $$| $$_____/| $$  / $$
| $$  \ $$| $$  \ $$| $$      |  $$/ $$/
| $$$$$$$$| $$  | $$| $$$$$    \  $$$$/
| $$__  $$| $$  | $$| $$__/     >$$  $$
| $$  | $$| $$  | $$| $$       /$$/\  $$
| $$  | $$| $$$$$$$/| $$$$$$$$| $$  \ $$
|__/  |__/|_______/ |________/|__/  |__/
```

# ADEX — Active Directory EXploitation

> Bind once. Get the path to Domain Admin, the recipes to walk it, and a report you can hand to the client.

ADEX is a Linux/macOS CLI for offensive Active Directory assessment. It wraps the LDAP, Kerberos, and certificate-service primitives that pentesters already use (`impacket`, `ldap3`, `certipy`) and adds the missing layer most one-shot tools skip: it joins the dots between findings and tells you, in one report, *what your current creds are actually worth*.

Built by [**Bitbl4ck**](https://github.com/Bitbl4ck) for engagements where time-on-keyboard matters more than feature-flags.

---

## The problem ADEX is built for

A typical internal AD assessment today is a juggling act:

- `bloodhound-python` to ingest the directory.
- BloodHound GUI to visualise paths.
- `certipy find` to enumerate AD CS templates.
- `NetExec` (or a sprinkle of `impacket-*` scripts) to hunt for AS-REP and Kerberoast targets.
- `ldapdomaindump` or `bloodyAD` for ACL detail.
- A scratch text file to remember which command-line flags go with which finding.

Each of those is excellent at one slice. None of them tells you, in one place, *"with the credentials you're holding right now, here is the shortest path to Domain Admin and here is the exact command sequence to walk it."* That gap is what ADEX fills.

---

## What ADEX gives you in a single run

| Capability | What it means in practice |
|---|---|
| **Attack-path graph, inline** | Every dangerous ACL, ESC1 template, RBCD edge, Kerberoastable SPN, AS-REP candidate, and unconstrained-delegation host gets an `Edge` in an in-memory graph. ADEX BFS-walks it and emits a `CRITICAL` finding for each shortest path from your bound principal to a high-value sink (DA, EA, krbtgt, DCs, AdminSDHolder). No BloodHound import cycle, no JSON shuffling. |
| **Paste-ready exploitation recipes** | Every finding ships with the exact `impacket` / `certipy` / `bloodyAD` / `ntlmrelayx.py` invocation that exploits it, parameterised with the values just collected from the directory. |
| **Trust-aware traversal** | `--map-trusts` walks every trusted domain reachable with your creds in a single invocation. Findings are tagged per-domain; the chain analyzer sees cross-forest edges in the same graph. |
| **Risk-ranked principals** | A Top-K dangerous-principal table tells you whose ACL you'd weaponise first. |
| **Reports that diff** | JSON / HTML / TXT in one go. `adex report diff` produces a delta between two scans — useful for re-tests and for the evidence section of a report. |
| **One auth surface** | Password, NT hash (PtH), Kerberos ccache, Pass-the-Cert (LDAPS Schannel), with PKINIT and AES-key paths planned. Same flags on every subcommand. |

---

## A 90-second tour

```bash
# Install
pipx install git+https://github.com/Bitbl4ck/ADEX.git

# Recon a domain end-to-end (with trust traversal + chain inference)
adex enum -d north.sevenkingdoms.local \
          -u vagrant -p vagrant \
          --dc 192.168.56.11 \
          --map-trusts \
          -o engagement -f all
```

What you'll see is the banner, then per-module progress, then a console summary table whose first row is the headline:

```
[CRITICAL] (chain) Path to Domain Admins (3 hops)

  ME --[ASREPRoast]--> khal.drogo --[GenericWrite]--> samwell.tarly
     --[AddMember]--> Domain Admins
```

…followed by `engagement.json`, `engagement.html`, and `engagement.txt` files written next to your shell. Each underlying finding (the AS-REP user, the writable ACL, the priv-group ACE) carries its own paste-ready recipe block.

A walk-through against the [GOAD v2](https://github.com/Orange-Cyberdefense/GOAD) lab, with curated illustrative output, lives in [`docs/GOAD-walkthrough.md`](docs/GOAD-walkthrough.md).

---

## Installation

ADEX targets **Python 3.10+** on Linux and macOS.

```bash
# Recommended (isolated):
pipx install git+https://github.com/Bitbl4ck/ADEX.git

# From a clone:
git clone https://github.com/Bitbl4ck/ADEX.git
cd ADEX
pipx install .

# Hacking on it:
git clone https://github.com/Bitbl4ck/ADEX.git
cd ADEX
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Runtime dependencies (`impacket`, `ldap3`, `certipy-ad`, `rich`, `jinja2`, `cryptography`, `pycryptodome`, `dnspython`, `argcomplete`) are pulled in automatically.

Optional shell completion:

```bash
register-python-argcomplete adex >> ~/.bashrc
```

---

## The three-step workflow

ADEX is opinionated about how it should be used during an engagement.

### 1. **Recon** — `adex enum`

```bash
adex enum -d corp.local -u jdoe -p '...' --dc 10.0.0.10 --map-trusts -o baseline
```

This is the heavy lifter. It binds, runs the enabled modules, runs chain inference and risk scoring on the collected edges, and writes the report set.

### 2. **Exploit** — copy a recipe, run it, repeat

Every non-informational finding has a `recipe` block — the exact commands to walk that primitive. Recipes are intentionally explicit: the tool that gets shelled out (`impacket-secretsdump`, `certipy req`, `bloodyAD`, `impacket-ntlmrelayx`, …), the flags, the values that came from the directory. **Read each recipe before you paste it** — see Disclaimer below.

If you've already collected creds from one path and want to ask "where do these creds get me from here?", re-run `adex enum` (or use `adex chain --input <prev>.json --target "Enterprise Admins"` for what-if analysis without re-binding).

### 3. **Re-test & diff**

After the client remediates, bind again with the same flags pointing at a new output basename, then:

```bash
adex report diff --baseline baseline.json --current rerun.json --output delta
```

The delta files highlight what's new and what's resolved — useful both for re-test reports and as evidence trail.

---

## Authentication

| Flag                       | Method                                           | Notes                                  |
|----------------------------|--------------------------------------------------|----------------------------------------|
| `-p PASSWORD`              | NTLM password bind                               | Default                                |
| `-H [LM:]NT`               | Pass-the-hash                                    | LM half optional                       |
| `-k`                       | Kerberos via `KRB5CCNAME`                        | Set the env var before invoking ADEX   |
| `--pfx FILE --pass-the-cert` | LDAPS Schannel with a client cert              | Implemented in v0.2                    |
| `--pfx FILE [--pfx-pass]`  | PKINIT → TGT → bind                              | Phase 3 — for now, run `certipy auth` first and use `-k` |
| `--aes-key KEY`            | AES-128/256 long-term Kerberos key                | Phase 3                                |

`--dc IP/HOST` is auto-discovered via DNS SRV (`_ldap._tcp.dc._msdcs.<domain>`) when omitted; pass `--dns SERVER` to use a specific resolver. `--ldaps` switches to TCP/636.

---

## Modules

`adex enum -L` lists the current state at runtime. As of v0.2:

| Module        | Status | What it surfaces                                                              |
|---------------|--------|-------------------------------------------------------------------------------|
| `domain`      | impl   | Functional level, MAQ, password policy, trusts, LDAP/SMB signing              |
| `creds`       | impl   | Kerberoastable / AS-REP roastable users, gMSA, LAPS readability               |
| `rights`      | impl   | DCSync, dangerous ACEs on AdminSDHolder + privileged groups + protected users |
| `delegation`  | impl   | Unconstrained, constrained (with protocol-transition), RBCD inbound + writable |
| `adcs`        | impl   | ESC1-9, 11, 13, 15 — vulnerable templates, CA ACLs, HTTP/RPC relay, OID-to-group, EKUwu, no-security-extension |
| `accounts`    | stub   | Privileged users, adminCount, SID history, stale accounts                     |
| `gpo`         | stub   | GPO write access, local group membership via GPO                              |
| `computer`    | stub   | LAPS coverage, outdated OS, infrastructure servers                             |
| `application` | stub   | Exchange / SCCM / SCOM detection                                               |

Run a subset with `-M domain,rights,delegation`. Skip noisy checks with `--opsec`.

---

## Output, severity, exit codes

Reports are emitted as **JSON** (machine-readable, includes structured `edges` for downstream tooling), **HTML** (dark-themed, recipe blocks rendered as copyable code, chain paths visualised), and **TXT** (plain, grep-friendly). `-f json|html|txt|all` selects one or all.

Severity levels, ascending: `INFO → LOW → MEDIUM → HIGH → CRITICAL`. By default the console table hides INFO; pass `-v` to see everything, or `--min-severity high` to only see actionable items.

| Exit code | Meaning                                                  |
|-----------|----------------------------------------------------------|
| 0         | Clean run, no HIGH or CRITICAL findings                  |
| 1         | Clean run, ≥ 1 HIGH or CRITICAL finding                  |
| 2         | Authentication failure (bad creds, expired ticket, etc.) |
| 3         | Network / connection failure                             |

This makes ADEX scriptable in CI-style "is this domain still drift-free?" checks.

---

## What ADEX deliberately does *not* do

- It does not exploit. The `enum` flow is read-only against LDAP. The standalone offensive subcommands (`kerberoast`, `asreproast`, `shadow-creds`, `rbcd`) are stubs in v0.2; they ship in Phase 3.
- It does not replace BloodHound for path visualisation — for interactive graph queries on huge directories, BloodHound is still the right tool.
- It does not replace certipy for ADCS deep-dives — but it covers most of `certipy find` from a single LDAP bind: ESC1, 2, 3, 4, 5, 7, 8, 9, 11, 13, and 15. ESC6 needs an RPC bind to the CA's CertSrv; ADEX flags the CA for verification with certipy. ESC10 is registry-only on the DC.
- It does not authenticate to anything other than the directory you point it at. No telemetry, no upload, no cloud component.

---

## Roadmap

- **Phase 3 (next)** — standalone offensive commands (Kerberoast, ASREP, Shadow Credentials, RBCD) executable from the same CLI.
- **Phase 3+** — `accounts`, `gpo`, `computer`, `application` modules.
- **Later** — BloodHound JSON ingest/export so the graphs play together.

---

## Development

```bash
git clone https://github.com/Bitbl4ck/ADEX.git
cd ADEX
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest tests/ -q     # unit tests
ruff check adex/     # lint
```

The codebase is small on purpose — every module fits in your head. Reference modules (`domain`, `rights`) are intentionally short so contributors can learn the pattern from one file before writing the next one.

---

## Disclaimer

ADEX exists to support **authorized** Active Directory security work — internal red-team operations, penetration tests under written engagement scope, training environments, CTFs, and self-hosted labs that you own.

The primitives ADEX surfaces (Kerberoasting, AS-REP roasting, AD CS template abuse, Resource-Based Constrained Delegation, ACL manipulation, NTLM relay, Shadow Credentials, etc.) are routinely effective against real production directories. Running them in environments where you do not have explicit written permission is a fast route to being on the wrong side of the engagement contract — and, depending on jurisdiction, on the wrong side of the law.

Findings, attack chains, and recipes emitted by ADEX are produced by the tool's reasoning over LDAP and certificate-service metadata. They are best-effort and not exhaustive: a quiet report does not mean a clean directory, and a noisy one does not always mean an exploitable one. Treat every recipe as a piece of code to *review* before you paste it into a shell — particularly on long-running engagements where recipe inputs may have rotated since enum ran.

ADEX is provided as-is, with no warranty, express or implied. The maintainer takes no responsibility for damages, lost data, account lockouts, broken trusts, regulatory exposure, downtime, or any other consequences arising from use, misuse, or misconfiguration of this tool. By running it, you accept that responsibility for the outcomes lives entirely with you and the engagement contract under which you operate.

If you take parts of ADEX into your own tooling, please treat it the way you'd treat any defensive primitive: ship it through your own SDLC, generate the right detection-surface artefacts (Sigma rules, KQL queries, IOCs, etc.) for the operations team that will eventually have to triage what you trigger, and version-pin the dependencies you actually rely on.

---

## Credits & inspiration

ADEX stands on the shoulders of giants. In particular:

- [`impacket`](https://github.com/fortra/impacket) — the Kerberos / SMB / DCERPC plumbing.
- [`certipy`](https://github.com/ly4k/Certipy) — the ADCS reference implementation; ADEX models its ESC checks on certipy's logic.
- [`ldap3`](https://github.com/cannatag/ldap3) — pure-Python LDAP client, including the SD parsing primitives.
- [`BloodHound`](https://github.com/SpecterOps/BloodHound) — for the attack-path mental model that the chain analyzer is a thin imitation of.
- [`bloodyAD`](https://github.com/CravateRouge/bloodyAD) — a recipe staple for ACL exploitation.
- [`GOAD`](https://github.com/Orange-Cyberdefense/GOAD) by [Mayfly](https://github.com/M4yFly) at Orange Cyberdefense — for the lab the walkthrough targets.

If any of this is useful to you, support those projects upstream first.
