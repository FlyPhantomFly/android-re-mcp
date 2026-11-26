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


def test_workflow_jobs_declare_a_timeout():
    """F6: a hung step must not eat the default 6-hour job limit.

    the publish-pypi publish job gets 20: the reviewer-approval wait happens
    before the job starts, so the limit covers the minutes it actually runs.
    """
    problems = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text()
        runs_on = len(re.findall(r"^\s*runs-on:", text, re.MULTILINE))
        timeouts = len(re.findall(r"^\s*timeout-minutes:\s*\d+\s*$", text, re.MULTILINE))
        if runs_on < 1 or timeouts != runs_on:
            problems.append(f"{path.name}: {runs_on} jobs, {timeouts} timeout-minutes")
    assert not problems, problems


def test_jar_download_uses_a_socket_timeout_with_sha_and_cleanup():
    text = (WORKFLOWS / "ci.yml").read_text()
    assert "urlretrieve(" not in text, "urlretrieve has no socket timeout"
    assert re.search(r"urlopen\(\s*url,\s*timeout=\d+", text), "socket timeout required"
    # the .part staging, SHA-256 verification and cleanup must survive refactors
    assert "part.replace(target)" in text
    assert "part.unlink(missing_ok=True)" in text
    assert "sha256" in text
