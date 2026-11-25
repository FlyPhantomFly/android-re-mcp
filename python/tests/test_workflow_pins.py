"""CI actions must be pinned to full commit SHAs with a version comment."""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
USES = re.compile(r"^\s*-?\s*uses:\s*([^#\s]+)\s*(#.*)?$")


def test_every_action_is_pinned_to_a_full_sha_with_a_comment():
    problems = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            match = USES.match(line)
            if not match:
                continue
            ref, comment = match.group(1), match.group(2)
            if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", ref):
                problems.append(f"{path.name}:{lineno}: not a full-SHA pin: {ref}")
            if not comment or not comment.strip("# ").strip():
                problems.append(f"{path.name}:{lineno}: missing version comment")
    assert not problems, problems
