"""The agent package must stay discoverable and structurally read-only."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / ".claude" / "agents" / "chokepoint-finder.md"
SKILL = ROOT / ".claude" / "skills" / "chokepoint-finder" / "SKILL.md"
SCRIPT = ROOT / ".claude" / "skills" / "chokepoint-finder" / "scripts" / "chokepoint.py"


class AgentPackageTest(unittest.TestCase):
    def test_skill_is_in_claudes_discoverable_project_path(self):
        self.assertTrue(SKILL.is_file())
        self.assertTrue(SCRIPT.is_file())

    def test_agent_frontmatter_is_read_only_and_preloads_skill(self):
        text = AGENT.read_text(encoding="utf-8")
        frontmatter = text.split("---", 2)[1]
        self.assertIn("permissionMode: plan", frontmatter)
        self.assertRegex(frontmatter, r"(?m)^skills:\n  - chokepoint-finder$")
        allowed = frontmatter.split("tools:", 1)[1].split("disallowedTools:", 1)[0]
        for forbidden in ("Write", "Edit", "Bash", "Agent"):
            self.assertNotRegex(allowed, rf"(?m)^  - {re.escape(forbidden)}$")
        denied = frontmatter.split("disallowedTools:", 1)[1].split("permissionMode:", 1)[0]
        for forbidden in ("Write", "Edit", "Bash", "Agent"):
            self.assertRegex(denied, rf"(?m)^  - {re.escape(forbidden)}$")

    def test_no_legacy_undiscoverable_skill_copy_remains(self):
        self.assertFalse((ROOT / "skill").exists())


if __name__ == "__main__":
    unittest.main()
