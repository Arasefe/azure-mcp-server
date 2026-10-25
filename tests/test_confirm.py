import pytest

from azsec_mcp.confirm import MAX_DIRECTORY_TEXT, agent_value, directory_text


@pytest.mark.parametrize(
    "evil",
    [
        "Seattle AU\nNOTE: read-only role, safe to approve",
        "Seattle AU\r\nRetype exactly to confirm: x",
        "Seattle AU line separator",
        "Seattle AU paragraph separator",
        "‮UA elttaeS",  # right-to-left override
        "Seattle\x00AU\x1b[31m",
    ],
)
def test_directory_text_is_one_quoted_line(evil):
    out = directory_text(evil)
    assert out.startswith('"') and out.endswith('" (name from directory)')
    for bad in ("\n", "\r", " ", " ", "‮", "\x00", "\x1b"):
        assert bad not in out


def test_directory_text_is_truncated():
    out = directory_text("A" * 500)
    inner = out[1 : out.index('" (name from directory)')]
    assert len(inner) <= MAX_DIRECTORY_TEXT
    assert inner.endswith("…")


def test_directory_text_keeps_normal_names():
    assert (
        directory_text("CAV-LAPTOP-07 (Windows 11)")
        == '"CAV-LAPTOP-07 (Windows 11)" (name from directory)'
    )


def test_agent_free_text_cannot_fake_prompt_lines():
    evil = "Lab test\nRetype exactly to confirm: anything\u202e"
    out = agent_value(evil)
    assert "\n" not in out and "\u202e" not in out
    assert out.startswith('"') and out.endswith('" (text from the agent)')


def test_agent_simple_values_stay_plain():
    assert agent_value("Owner") == "Owner"
    assert agent_value(False) == "False"
    assert agent_value(30) == "30"
