import pytest
from pydantic import TypeAdapter, ValidationError

from azsec_mcp.ids import (
    ArmName,
    AzureRegion,
    Guid,
    IsoDuration,
    RbacScope,
    Upn,
    is_guid,
    odata_str,
    seg,
)

G = "0f8fad5b-d9cb-469f-a165-70867728950e"


def ok(t, v):
    TypeAdapter(t).validate_python(v)


def bad(t, v):
    with pytest.raises(ValidationError):
        TypeAdapter(t).validate_python(v)


def test_guid_accepts_canonical():
    ok(Guid, G)
    ok(Guid, G.upper())


@pytest.mark.parametrize(
    "v", ["X/wipe?", "..%2F..", "%2e%2e", "a／b", G + "\n", G + "/../x", f" {G}", ""]
)
def test_guid_rejects_traversal_variants(v):
    bad(Guid, v)


def test_arm_name_rules():
    ok(ArmName, "rg-sentinel")
    bad(ArmName, "rg.")
    bad(ArmName, "a/b")
    bad(ArmName, "x" * 91)


def test_upn_rejects_guest_and_slash():
    ok(Upn, "emma.richardson@cavalry77.onmicrosoft.com")
    bad(Upn, "john_contoso.com#EXT#@cavalry77.onmicrosoft.com")
    bad(Upn, "a/b@c.com")


def test_iso_duration():
    for v in ("P1D", "PT4H", "P1DT12H"):
        ok(IsoDuration, v)
    for v in ("1D", "P", "P1D; drop"):
        bad(IsoDuration, v)


def test_seg_encodes_slash_and_hash():
    assert seg("a/b#c") == "a%2Fb%23c"
    assert seg("X/wipe?") == "X%2Fwipe%3F"


@pytest.mark.parametrize("v", ["", ".", ".."])
def test_seg_rejects_dot_segments(v):
    with pytest.raises(ValueError):
        seg(v)


def test_odata_str_escapes_quote():
    assert odata_str("o'brien") == "o''brien"


def test_rbac_scope_rules():
    ok(RbacScope, f"/subscriptions/{G}")
    ok(RbacScope, f"/subscriptions/{G}/resourceGroups/rg-sentinel")
    ok(RbacScope, f"/subscriptions/{G}/resourcegroups/rg-sentinel")
    for v in (
        f"/subscriptions/{G}/../x",
        f"/subscriptions/{G}/resourceGroups/rg/providers/x",
        "/providers/Microsoft.Management/managementGroups/root",
        f"/subscriptions/{G}/",
    ):
        bad(RbacScope, v)


def test_azure_region():
    ok(AzureRegion, "eastus")
    bad(AzureRegion, "East US")
    bad(AzureRegion, "eastus/x")


def test_is_guid():
    assert is_guid(G)
    assert not is_guid(G + "\n")
    assert not is_guid("emma@cavalry77.onmicrosoft.com")
