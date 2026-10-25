import pytest

from azsec_mcp.config import load_settings

BASE = {
    "AZURE_TENANT_ID": "11111111-1111-1111-1111-111111111111",
    "AZURE_CLIENT_ID": "22222222-2222-2222-2222-222222222222",
    "AZURE_SUBSCRIPTION_ID": "33333333-3333-3333-3333-333333333333",
    "SENTINEL_RESOURCE_GROUP": "rg-sentinel",
    "SENTINEL_WORKSPACE_NAME": "law-test",
}


def test_missing_required_var_raises():
    env = {k: v for k, v in BASE.items() if k != "AZURE_TENANT_ID"}
    with pytest.raises(ValueError, match="AZURE_TENANT_ID"):
        load_settings(env)


def test_max_tier_defaults_to_read():
    assert load_settings(BASE).max_tier == "read"


def test_cert_path_defaults_to_repo_pem():
    assert load_settings(BASE).cert_path.name == "cavalry-sp.combined.pem"


def test_settings_repr_has_no_ids():
    text = repr(load_settings(BASE))
    for name in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_SUBSCRIPTION_ID"):
        assert BASE[name] not in text
