"""The documentation is part of the product, so it is tested like code.

Its links resolve, every finished phase of the roadmap has its guide, and the security model's
permission tables are the ones the code enforces - a role or key change that forgets the
documentation fails here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from argus.security.permissions import API_KEY_SCOPES, ORG_ROLE_PERMISSIONS, OrgRole, Permission

ROOT = Path(__file__).resolve().parents[2]
DOCUMENTS = sorted([ROOT / "README.md", *(ROOT / "docs").rglob("*.md")])
LINK = re.compile(r"\]\(([^)\s]+)\)")
SCHEME = re.compile(r"[a-z][a-z0-9+.-]*:")
CODE_BLOCK = re.compile(r"```.*?```", re.DOTALL)


def relative_links(path: Path) -> list[str]:
    text = CODE_BLOCK.sub("", path.read_text(encoding="utf-8"))  # examples, not links
    return [
        target
        for target in LINK.findall(text)
        if not SCHEME.match(target) and not target.startswith("#")
    ]


@pytest.mark.parametrize("path", DOCUMENTS, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_every_relative_link_resolves(path: Path) -> None:
    missing = [
        target
        for target in relative_links(path)
        if not (path.parent / target.split("#", 1)[0]).exists()
    ]
    assert not missing, missing


def test_every_finished_phase_has_its_guide() -> None:
    roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    rows = re.findall(r"^\| (\d+) \| [^|]+ \| (\S+) \| (.+?) \|$", roadmap, flags=re.MULTILINE)
    assert [int(number) for number, _, _ in rows] == list(range(1, 26))
    for number, status, guide in rows:
        assert status in {"✅", "⏭", "🔄", "⏳"}, (number, status)
        if status == "✅":
            link = LINK.search(guide)
            assert link is not None, f"phase {number} has no guide"
            assert (ROOT / "docs" / link.group(1)).exists(), link.group(1)


ROLES = ("owner", "admin", "analyst", "viewer")


def documented_role_matrix() -> dict[str, set[str]]:
    text = (ROOT / "docs" / "security" / "security-model.md").read_text(encoding="utf-8")
    header = "| Permission | owner | admin | analyst | viewer |"
    lines = text[text.index(header) :].splitlines()[2:]
    matrix: dict[str, set[str]] = {role: set() for role in ROLES}
    for line in lines:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        permissions = re.findall(r"`([a-z_]+:[a-z_]+)`", cells[0])
        assert permissions, line
        for role, cell in zip(ROLES, cells[1:], strict=True):
            assert cell in {"✓", ""}, line
            if cell:
                matrix[role].update(permissions)
    return matrix


def test_the_documented_role_matrix_is_the_enforced_one() -> None:
    documented = documented_role_matrix()
    assert documented["owner"] == {str(p) for p in Permission}, "every permission is listed"
    for role in ROLES:
        enforced = {str(p) for p in ORG_ROLE_PERMISSIONS[OrgRole(role)]}
        assert documented[role] == enforced, role


def test_the_documented_api_key_exclusions_are_the_enforced_ones() -> None:
    text = (ROOT / "docs" / "security" / "security-model.md").read_text(encoding="utf-8")
    sentence = text[text.index("Some permissions can never be given to") :]
    sentence = sentence[: sentence.index(" - a leaked key")]
    documented = set(re.findall(r"`([a-z_]+:[a-z_]+)`", sentence))
    assert documented == {str(p) for p in set(Permission) - API_KEY_SCOPES}
