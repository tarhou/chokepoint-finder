# Chokepoint Finder agent

This repository is a drop-in AI security agent for Claude (Claude Code or Cowork). It
turns thousands of vulnerability findings into the few fixes that remove the most risk,
gates them for safety, returns an approval-bound manifest to your own executor, and puts a human checkpoint on
every change, and verifies the result before closing.

## What's in here

- `.claude/agents/chokepoint-finder.md` — the agent definition (its operating loop and
  hard rules). Claude Code loads it as a subagent; Cowork reads it as the agent persona.
- `.claude/skills/chokepoint-finder/` — the discoverable, vendored Chokepoint Finder
  skill the agent preloads, including its standard-library ranking script. Bundled so the agent is
  self-contained; the canonical copy is
  [chokepoint-finder-skill](https://github.com/tarhou/chokepoint-finder-skill).

## Use it

Claude Code loads subagents from `<project-root>/.claude/agents/` and `~/.claude/agents/`
only — a clone nested inside another project is not discovered. Either open this repo as
your Claude Code project, or install user-wide:

```bash
mkdir -p ~/.claude/agents ~/.claude/skills/chokepoint-finder
cp .claude/agents/chokepoint-finder.md ~/.claude/agents/
cp -R .claude/skills/chokepoint-finder/. ~/.claude/skills/chokepoint-finder/
```

The README's Install section has the per-project variant. Then ask Claude "what should we
fix first?" The agent gathers findings through your connected MCP servers (a Tenable MCP
server, the AWS MCP Server from Agent Toolkit for AWS, or an export), ranks the
chokepoints, pre-flights each action, and walks you through execution and verification
with an approval at every mutating step.

Try the engine with zero setup:

```bash
python3 .claude/skills/chokepoint-finder/scripts/chokepoint.py --demo
```

## The family

This agent is one of four shapes of the same idea on the CyberAgents Exchange:

- **Agent** (this repo) — the drop-in agent
- **Skill** ([chokepoint-finder-skill](https://github.com/tarhou/chokepoint-finder-skill)) — the skill on its own, to add to an existing setup
- **Playbook** ([chokepoint-finder-playbook](https://github.com/tarhou/chokepoint-finder-playbook)) — the multi-tool chain with a human checkpoint
- **MCP server** ([chokepoint-finder-mcp](https://github.com/tarhou/chokepoint-finder-mcp)) — the engine as ten typed tools

Authors: Zane K ([@zkilling](https://github.com/zkilling)), Tarek H ([@tarhou](https://github.com/tarhou)). MIT license.
