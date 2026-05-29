"""Unit tests for the ADCS module's per-ESC detection logic.

These tests don't bind to a real DC — they construct synthetic template /
CA dicts with the relevant flag combinations and assert that the right
findings are emitted.
"""

from __future__ import annotations

from adex.modules.adcs import (
    AUTH_EKUS,
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
    CT_FLAG_NO_SECURITY_EXTENSION,
    CT_FLAG_PEND_ALL_REQUESTS,
    EKU_ANY_PURPOSE,
    EKU_CERT_REQUEST_AGENT,
    EKU_CLIENT_AUTH,
    SCHEMA_V1,
    AdcsModule,
)


# Tiny stand-in for RunContext that holds only what _check_template uses.
class _Ctx:
    def __init__(self):
        from adex.auth import Auth
        self.principal_sids = {"S-1-5-21-x-1101"}
        self.auth = Auth(domain="corp.local", username="jdoe", password="P@ss")
        self.dc = "10.0.0.10"
        self.me_node = "ME"
        self.domain_context = ""


def _bypass_acl_helpers(monkeypatch):
    """The synthetic SDs we build aren't real Microsoft SDs, so stub the
    ACL parsers to return what each test wants."""
    monkeypatch.setattr(AdcsModule, "_enroll_acl_grants",
                        staticmethod(lambda sd, sids: True))
    monkeypatch.setattr(AdcsModule, "_template_write_grants",
                        staticmethod(lambda sd, sids: []))


def _tpl(**kwargs) -> dict:
    base = {
        "cn": "TestTemplate",
        "dn": "CN=TestTemplate,CN=Certificate Templates,...",
        "displayName": "Test Template",
        "name_flag": 0,
        "enroll_flag": 0,
        "schema": 4,
        "ekus": set(),
        "policies": [],
        "ra_policies": [],
        "sd_raw": b"\x00",  # presence checked, content stubbed
    }
    base.update(kwargs)
    return base


def _ca(name="TEST-CA"):
    return {"cn": name, "dn": f"CN={name},...", "dns": "ca.corp.local",
            "templates": ["testtemplate"], "displayName": name, "sd_raw": None}


def test_esc1_detected(monkeypatch):
    _bypass_acl_helpers(monkeypatch)
    mod = AdcsModule()
    ctx = _Ctx()
    tpl = _tpl(name_flag=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
               ekus={EKU_CLIENT_AUTH})
    findings = mod._check_template(ctx, tpl, _ca(), {})
    titles = [f.title for f in findings]
    assert any("ESC1" in t for t in titles)


def test_esc1_not_emitted_when_manager_approval(monkeypatch):
    _bypass_acl_helpers(monkeypatch)
    mod = AdcsModule()
    tpl = _tpl(name_flag=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
               enroll_flag=CT_FLAG_PEND_ALL_REQUESTS,
               ekus={EKU_CLIENT_AUTH})
    findings = mod._check_template(_Ctx(), tpl, _ca(), {})
    assert not any("ESC1" in f.title for f in findings)


def test_esc2_any_purpose(monkeypatch):
    _bypass_acl_helpers(monkeypatch)
    mod = AdcsModule()
    tpl = _tpl(ekus={EKU_ANY_PURPOSE})
    findings = mod._check_template(_Ctx(), tpl, _ca(), {})
    assert any("ESC2" in f.title for f in findings)


def test_esc2_subca_empty_eku(monkeypatch):
    _bypass_acl_helpers(monkeypatch)
    mod = AdcsModule()
    tpl = _tpl(ekus=set())  # SubCA-equivalent
    findings = mod._check_template(_Ctx(), tpl, _ca(), {})
    assert any("ESC2" in f.title for f in findings)


def test_esc3_enrollment_agent(monkeypatch):
    _bypass_acl_helpers(monkeypatch)
    mod = AdcsModule()
    tpl = _tpl(ekus={EKU_CERT_REQUEST_AGENT})
    findings = mod._check_template(_Ctx(), tpl, _ca(), {})
    assert any("ESC3" in f.title for f in findings)


def test_esc4_template_acl(monkeypatch):
    """ESC4 fires regardless of enroll permission — pure write on template."""
    monkeypatch.setattr(AdcsModule, "_enroll_acl_grants",
                        staticmethod(lambda sd, sids: False))
    monkeypatch.setattr(AdcsModule, "_template_write_grants",
                        staticmethod(lambda sd, sids: [("S-1-5-21-x-1101", 0xF01FF)]))
    mod = AdcsModule()
    findings = mod._check_template(_Ctx(), _tpl(), _ca(), {})
    assert any("ESC4" in f.title for f in findings)


def test_esc9_no_security_extension(monkeypatch):
    _bypass_acl_helpers(monkeypatch)
    mod = AdcsModule()
    tpl = _tpl(enroll_flag=CT_FLAG_NO_SECURITY_EXTENSION,
               ekus={EKU_CLIENT_AUTH})
    findings = mod._check_template(_Ctx(), tpl, _ca(), {})
    assert any("ESC9" in f.title for f in findings)


def test_esc15_ekuwu(monkeypatch):
    _bypass_acl_helpers(monkeypatch)
    mod = AdcsModule()
    tpl = _tpl(schema=SCHEMA_V1, name_flag=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
               ekus={EKU_CLIENT_AUTH})
    findings = mod._check_template(_Ctx(), tpl, _ca(), {})
    titles = [f.title for f in findings]
    assert any("ESC15" in t for t in titles)
    # ESC1 must NOT fire on schema-v1 (we route v1 to ESC15 instead)
    assert not any(t.startswith("ESC1: ") for t in titles)


def test_esc13_oid_to_group(monkeypatch):
    _bypass_acl_helpers(monkeypatch)
    mod = AdcsModule()
    tpl = _tpl(policies=["1.3.6.1.4.1.311.21.8.12345.5678"],
               ekus={EKU_CLIENT_AUTH})
    oid_groups = {"1.3.6.1.4.1.311.21.8.12345.5678": "CN=Special Group,DC=corp,DC=local"}
    findings = mod._check_template(_Ctx(), tpl, _ca(), oid_groups)
    assert any("ESC13" in f.title for f in findings)


def test_clean_template_emits_nothing_dangerous(monkeypatch):
    _bypass_acl_helpers(monkeypatch)
    mod = AdcsModule()
    # Plain template: client-auth EKU but no supplies-subject, no any-purpose
    tpl = _tpl(ekus={EKU_CLIENT_AUTH})
    findings = mod._check_template(_Ctx(), tpl, _ca(), {})
    titles = [f.title for f in findings]
    assert not any(t.startswith(("ESC1:", "ESC2:", "ESC3:", "ESC9:", "ESC15:"))
                   for t in titles)


def test_auth_ekus_constant_sanity():
    # Compile-time guard: AUTH_EKUS must include the well-known auth-suitable OIDs
    assert EKU_CLIENT_AUTH in AUTH_EKUS
    assert EKU_ANY_PURPOSE in AUTH_EKUS
