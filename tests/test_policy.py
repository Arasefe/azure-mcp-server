import pytest

from azsec_mcp.policy import Tier, authorize, parse_tier


def test_read_ceiling_denies_write_and_destructive():
    assert authorize(Tier.READ, Tier.READ).allowed
    assert not authorize(Tier.WRITE, Tier.READ).allowed
    assert not authorize(Tier.DESTRUCTIVE, Tier.READ).allowed


def test_destructive_ceiling_allows_write():
    # The hierarchy: allowing destructive implies write, so the inverted state is impossible.
    assert authorize(Tier.WRITE, Tier.DESTRUCTIVE).allowed
    assert authorize(Tier.READ, Tier.DESTRUCTIVE).allowed


def test_write_ceiling_denies_destructive():
    assert not authorize(Tier.DESTRUCTIVE, Tier.WRITE).allowed


def test_parse_tier_accepts_case_and_spaces():
    assert parse_tier(" Write ") is Tier.WRITE


@pytest.mark.parametrize("v", ["admin", "", "2", "destrutive"])
def test_parse_tier_rejects_unknown(v):
    with pytest.raises(ValueError, match="MCP_MAX_TIER"):
        parse_tier(v)


def test_deny_reason_names_env_var():
    assert "MCP_MAX_TIER" in authorize(Tier.WRITE, Tier.READ).reason


def test_deny_reason_does_not_teach_unlock():
    reason = authorize(Tier.DESTRUCTIVE, Tier.READ).reason
    assert ".env" not in reason
    assert "=" not in reason
