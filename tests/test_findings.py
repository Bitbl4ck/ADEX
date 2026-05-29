import pytest

from adex.findings import Edge, Finding, FindingCollector, Severity


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_severity_parse():
    assert Severity.parse("high") is Severity.HIGH
    assert Severity.parse("CRITICAL") is Severity.CRITICAL
    assert Severity.parse(3) is Severity.HIGH
    assert Severity.parse(Severity.LOW) is Severity.LOW


def test_finding_to_dict_and_back():
    f = Finding(
        severity=Severity.HIGH,
        module="rights",
        title="DCSync",
        description="x",
        target="DC=corp,DC=local",
        evidence={"sid": "S-1-5-21-1-1-1-500"},
        references=["http://example/"],
        recipe=["impacket-secretsdump corp.local/jdoe:p -dc-ip 1.2.3.4 -just-dc"],
        edges=[Edge(src="ME", dst="S-1-5-21-x-512", type="DCSync",
                    dst_label="Domain Admins", cost=1)],
        domain_context="north.sevenkingdoms.local",
    )
    d = f.to_dict()
    assert d["severity"] == "HIGH"
    assert d["module"] == "rights"
    assert "fingerprint" in d
    assert d["recipe"][0].startswith("impacket-secretsdump")
    assert d["edges"][0]["type"] == "DCSync"
    g = Finding.from_dict(d)
    assert g.severity is Severity.HIGH
    assert g.module == "rights"
    assert g.fingerprint() == f.fingerprint()
    assert g.edges and g.edges[0].type == "DCSync"
    assert g.recipe == f.recipe
    assert g.domain_context == "north.sevenkingdoms.local"


def test_collector_filter_summary_and_edges():
    c = FindingCollector()
    c.add(Finding(Severity.INFO, "m", "i"))
    c.add(Finding(Severity.HIGH, "m", "h",
                  edges=[Edge(src="ME", dst="X", type="GenericAll", dst_label="X")]))
    c.add(Finding(Severity.CRITICAL, "m", "c",
                  edges=[Edge(src="ME", dst="Y", type="DCSync", dst_label="Y")]))
    assert len(c) == 3
    assert len(c.filtered(Severity.HIGH)) == 2
    by = c.by_severity()
    assert by["HIGH"] == 1 and by["CRITICAL"] == 1 and by["INFO"] == 1
    assert len(c.all_edges()) == 2


def test_fingerprint_stable_and_domain_aware():
    a = Finding(Severity.LOW, "m", "t", target="x")
    b = Finding(Severity.HIGH, "m", "t", target="x")
    assert a.fingerprint() == b.fingerprint()  # severity is not part of identity
    c = Finding(Severity.LOW, "m", "t", target="x", domain_context="north")
    assert c.fingerprint() != a.fingerprint()  # domain_context IS part of identity


def test_edge_rejects_unknown_type():
    with pytest.raises(ValueError):
        Edge(src="ME", dst="X", type="NotAThing")
