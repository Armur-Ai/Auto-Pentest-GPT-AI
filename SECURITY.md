# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

We take security issues in Pentest Swarm AI seriously — both bugs in our
code and any way the tool itself could be turned against the people running
it. If you've found something, please report it privately through one of
these channels:

1. **Preferred — GitHub Security Advisory.** Open a private advisory at
   <https://github.com/Armur-Ai/Pentest-Swarm-AI/security/advisories/new>.
   This is end-to-end private and keeps the disclosure tied to the
   commits / releases it affects.

2. **Email.** Send details to **akhilsails@gmail.com** with the subject
   line prefixed `[security] Pentest Swarm AI:`. PGP isn't required;
   if you want to encrypt, ask in the first message and we'll exchange
   keys.

Please include:

- A description of the issue and the impact you believe it has
- Steps to reproduce (a minimal PoC is ideal)
- The version / commit SHA you tested against
- Whether you have already disclosed this anywhere else, and by when
  you'd like a public fix

You'll get an acknowledgement within **3 business days**. We'll work with
you on a disclosure timeline — the default is 90 days from the initial
report, but we'll publish sooner if a fix is ready and slower (with your
agreement) if the issue is unusually complex.

## What's In Scope

In scope:

- The `pentestswarm` binary and everything under `internal/`, `cli/`,
  `cmd/`, `web/`, `config/`, and `playbooks/`
- The API server in `internal/api/`
- Default playbooks and prompt scaffolding that ship in the repo
- Release artifacts published from this repo (Homebrew tap, GHCR image,
  AUR `pentestswarm-bin`, GoReleaser assets)
- The CI / release workflows in `.github/workflows/` if a finding lets
  an attacker influence what we publish

Out of scope:

- Vulnerabilities in third-party security tools we wrap (`nuclei`,
  `nmap`, `sqlmap`, `dalfox`, `katana`, `dnsx`, `naabu`, etc.) — report
  those upstream. We're happy to coordinate if it affects how we invoke
  the tool.
- Findings produced *by* Pentest Swarm AI against a target — those are
  the point of the tool. Report them to the target's program.
- Issues that require an attacker to already have local code execution
  or root on the host where `pentestswarm` runs.

## Responsible Use

Pentest Swarm AI is an offensive-security tool. **Only run it against
systems you are authorized to test** — your own infrastructure, a bug
bounty program scope you're enrolled in, a CTF, or an engagement
covered by a signed agreement. Using it against systems without
permission may be illegal in your jurisdiction. We will not assist with
unauthorized use, and findings reported to us that originate from
unauthorized scans will be ignored (or, depending on context, reported
to the relevant parties).

## Hall of Fame

When a researcher reports a valid vulnerability and is happy to be
named, we'll credit them in the release notes for the fix and in this
file. Bounties aren't currently offered, but that may change.
