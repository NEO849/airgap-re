"""Tests für die MCP-ToolAnnotations: jedes Tool wird beim Namen referenziert und
muss alle vier Hints explizit (boolean) tragen, passend zum read-only-Verhalten.
CI-sicher — es wird nur die Registry introspektiert, kein Backend (Ghidra/r2/bwrap) gestartet."""
import pytest

from re_mcp.server import mcp

# Die 7 ausgelieferten Tools — namentlich, damit jedes Tool in den Tests auftaucht.
EXPECTED_TOOLS = [
    "re_capabilities",
    "analyze_binary",
    "sandbox_analyze_binary",
    "sandbox_selftest",
    "decompile_function",
    "list_symbols",
    "analyze_apk",
]


def _tools_by_name():
    return {t.name: t for t in mcp._tool_manager.list_tools()}


def test_all_expected_tools_registered():
    assert sorted(_tools_by_name()) == sorted(EXPECTED_TOOLS)


@pytest.mark.parametrize("name", EXPECTED_TOOLS)
def test_tool_has_all_four_hints_boolean(name):
    tool = _tools_by_name()[name]
    ann = tool.annotations
    assert ann is not None, f"{name}: keine ToolAnnotations gesetzt"
    for hint in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
        assert isinstance(getattr(ann, hint), bool), f"{name}: {hint} nicht boolean"


@pytest.mark.parametrize("name", EXPECTED_TOOLS)
def test_tool_hints_match_readonly_behaviour(name):
    ann = _tools_by_name()[name].annotations
    # read-only am Ziel, kein destruktiver Eingriff, idempotent, rein lokal (kein Netz).
    assert ann.readOnlyHint is True
    assert ann.destructiveHint is False
    assert ann.idempotentHint is True
    assert ann.openWorldHint is False
