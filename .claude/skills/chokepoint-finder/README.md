# Chokepoint Finder Skill

A Claude skill that turns any Claude with access to your findings into a remediation
decision engine: **the smallest set of actions that eliminates the largest share of
risk, with the evidence to defend each one.**

Related repositories:
[chokepoint-finder](https://github.com/tarhou/chokepoint-finder) (agent definition) ·
[chokepoint-finder-playbook](https://github.com/tarhou/chokepoint-finder-playbook)
(operating playbook) ·
[chokepoint-finder-mcp](https://github.com/tarhou/chokepoint-finder-mcp) (optional MCP
server implementing the same method as typed tools).

## Install

Installing the skill is a folder copy. Put the contents of this repository at one of:

- **User scope**, available in all your projects: `~/.claude/skills/chokepoint-finder/`
- **Project scope**, one project only: `<project>/.claude/skills/chokepoint-finder/`

For example:

```bash
git clone https://github.com/tarhou/chokepoint-finder-skill.git \
  ~/.claude/skills/chokepoint-finder
```

There are no packages to install and the skill holds no credentials, but there is one
runtime prerequisite: a `python3` interpreter on `PATH`. The bundled
`scripts/chokepoint.py` imports only the standard library (`argparse`, `hashlib`,
`json`, `math`, `sys`, `unicodedata`, `collections`), so no third-party packages
are ever needed. Python 3.11 or newer is
required (CI exercises 3.11, 3.12 and 3.13). Data access happens through whatever MCP servers
you already have (Tenable, AWS, or plain CSV/JSON exports).

## Try it in ten seconds

Installed at user scope, these commands work from any directory:

```bash
python3 ~/.claude/skills/chokepoint-finder/scripts/chokepoint.py --demo
python3 ~/.claude/skills/chokepoint-finder/scripts/chokepoint.py --sample
```

`--demo` ranks a deterministic built-in estate; `--sample` prints the input schema by
example. Rank your own estate with
`python3 ~/.claude/skills/chokepoint-finder/scripts/chokepoint.py estate.json`, adding
`--json` for machine-readable output. (Working from a checkout instead, run the same
flags as `python3 scripts/chokepoint.py --demo` from the repository root.)
The Markdown view keeps titles bounded and one-line, shows only a short opaque digest,
and reports identifier counts. The `--json` view retains the complete finding and
target arrays for machine use.

Build the uploadable artifact deterministically with `python3 scripts/package_skill.py`.
The result is `dist/chokepoint-finder.zip`, rooted at `chokepoint-finder/`.

The bundled script is a single stdlib-only file: it groups findings by the fix they
share and ranks the ordered shortlist by marginal risk coverage. Everything else,
gathering data, pre-flight safety checks, the CTI out-of-band policy, per-step human
approvals, per-site rollout waves, and verification before closure, is the skill's
operating discipline: read `SKILL.md`.

## What you ask

"What should we fix first?" and Claude runs the loop: gather findings through your
MCPs, rank the chokepoints, pre-flight every action, get your approval step by step,
route execution through your own tools, and prove the risk moved before the change
record closes.

## Limitations

What the bundled script does NOT do:

- **It ranks; it does nothing else.** No data collection, no ticketing, no execution,
  no verification. Those steps are Claude's operating discipline in `SKILL.md`, driven
  through your connected MCP servers, with you approving every mutating step. The
  script never holds credentials and never mutates anything. Its ranking is not an
  approval artifact: execution requires a separately constructed canonical manifest
  containing the exact desired-state payload and executor arguments. Both output modes
  explicitly report that execution is unauthorized and no approval hash exists.
- **Input quality bounds output quality.** Findings without fix-sharing keys
  (`patch_key`, `base_image`, `iam_role`, `security_group`) cannot converge into
  chokepoints, and the script does no fuzzy matching or cross-source deduplication:
  keys must match exactly.
- **No attack-path modelling.** The script reports one coverage number, the share of
  total weighted finding risk retired, which by construction can never exceed 100%.
  The optional MCP server additionally models attack paths and reports path disruption
  as a separate metric with its own denominator; the script does not.
- **Greedy, not exact.** The default risk ranking runs to the requested `--top`
  cardinality and is the classical greedy for weighted
  max-coverage, with its (1 - 1/e) approximation guarantee; `--effort-weighted` is a
  cost-benefit heuristic with no approximation guarantee. `--top` defines the
  cardinality k and does not disable the guarantee; the library-only
  `target_share < 1` early stop does.
- **Site mapping fails closed.** Patch rollout waves select the lowest-risk eligible
  non-crown-jewel site as canary. Missing/nonconforming site names, missing explicit
  crown-jewel or criticality classifications, or an all-crown-jewel target set produce
  HOLD and no execution waves.
- **Bundled threat intel is a pinned snapshot.** The demo and sample kev flags were
  validated against the CISA Known Exploited Vulnerabilities catalog, version
  2026.08.03; EPSS and CVSS figures are illustrative and frozen for determinism. Check
  live sources before acting on a real estate.
- **The demo estate is synthetic.** Its convergence is realistic in shape, but every
  number it produces is illustrative.

Authors: Zane K ([@zkilling](https://github.com/zkilling)), Tarek H ([@tarhou](https://github.com/tarhou)). MIT license, see `LICENSE`.
