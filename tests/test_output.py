import json

from adex.findings import Edge, Finding, Severity
from adex.output import write_html, write_json, write_outputs, write_txt


def _sample():
    return [
        Finding(Severity.CRITICAL, "rights", "DCSync rights granted",
                description="DA-equivalent",
                target="DC=corp,DC=local",
                evidence={"sid": "S-1-5-21-1-2-3-500"},
                references=["https://example/"],
                recipe=["impacket-secretsdump corp.local/jdoe:p -dc-ip 1.2.3.4 -just-dc"],
                edges=[Edge(src="ME", dst="S-1-5-21-512", type="DCSync",
                            dst_label="Domain")]),
        Finding(Severity.MEDIUM, "domain", "Weak password policy",
                target="DC=corp,DC=local",
                evidence={"minPwdLength": 6},
                domain_context="north.sevenkingdoms.local"),
        Finding(Severity.CRITICAL, "chain", "Path to Domain Admins (2 hops)",
                target="Domain Admins",
                evidence={"render": "ME --[ASREPRoast]--> user --[GenericWrite]--> DA",
                          "hops": 2}),
    ]


def test_write_json(tmp_path):
    p = write_json(tmp_path / "r.json", _sample())
    data = json.loads(p.read_text())
    assert data["count"] == 3
    assert "fingerprint" in data["findings"][0]
    # Edges round-trip
    rights_finding = next(f for f in data["findings"] if f["module"] == "rights")
    assert rights_finding["edges"][0]["type"] == "DCSync"
    assert rights_finding["recipe"][0].startswith("impacket-secretsdump")


def test_write_txt(tmp_path):
    p = write_txt(tmp_path / "r.txt", _sample())
    text = p.read_text()
    assert "DCSync rights granted" in text
    assert "[CRITICAL]" in text
    assert "minPwdLength" in text
    assert "recipe:" in text
    assert "impacket-secretsdump" in text
    # domain_context tag in TXT
    assert "(north.sevenkingdoms.local)" in text


def test_write_html(tmp_path):
    p = write_html(tmp_path / "r.html", _sample())
    html = p.read_text()
    assert "<html" in html.lower()
    assert "DCSync rights granted" in html
    assert "CRITICAL" in html
    # Recipe block
    assert "Recipe" in html
    assert "impacket-secretsdump" in html
    # Chain path block
    assert "ASREPRoast" in html
    # Domain context pill
    assert "north.sevenkingdoms.local" in html


def test_write_outputs_all(tmp_path):
    paths = write_outputs(str(tmp_path / "r"), _sample(), ["all"])
    suffixes = sorted(p.suffix for p in paths)
    assert suffixes == [".html", ".json", ".txt"]
    for p in paths:
        assert p.exists() and p.stat().st_size > 0
