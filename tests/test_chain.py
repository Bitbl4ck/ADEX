from adex.chain import compute_chains
from adex.findings import Edge, Severity


def test_chain_finds_da_path():
    edges = [
        # ME -> khal.drogo (we can ASREP-roast)
        Edge(src="ME", dst="khal.drogo", type="ASREPRoast",
             dst_label="khal.drogo", cost=2),
        # khal.drogo -> samwell.tarly (GenericWrite from khal's group reach)
        Edge(src="khal.drogo", dst="samwell.tarly", type="GenericWrite",
             dst_label="samwell.tarly"),
        # samwell.tarly is in Domain Admins -> AddMember -> Domain Admins
        Edge(src="samwell.tarly", dst="DA-SID", type="AddMember",
             dst_label="Domain Admins"),
    ]
    sinks = {"DA-SID": "Domain Admins"}
    graph, findings = compute_chains(edges, sources={"ME"}, sinks=sinks)
    assert findings, "expected at least one chain finding"
    f = findings[0]
    assert f.severity is Severity.CRITICAL
    assert "Domain Admins" in f.title
    assert "khal.drogo" in f.evidence["render"]
    assert f.evidence["hops"] == 3


def test_chain_no_path_emits_nothing():
    edges = [
        Edge(src="ME", dst="user1", type="ASREPRoast", dst_label="user1"),
    ]
    sinks = {"DA-SID": "Domain Admins"}
    _g, findings = compute_chains(edges, sources={"ME"}, sinks=sinks)
    assert findings == []
