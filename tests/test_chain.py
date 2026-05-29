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


def test_esc1_alone_reaches_da_via_win_edge():
    """ESC1 means 'mint a cert as anyone' — even if the only edge in the
    graph is ME → ESC1 node, the chain analyzer should auto-wire that to
    every sink and find a 1-hop CRITICAL path."""
    edges = [
        Edge(src="ME", dst="ESC1:VulnTemplate", type="ESC1",
             dst_label="ESC1 via VulnTemplate", cost=1),
    ]
    sinks = {"DA-SID": "Domain Admins", "krbtgt-SID": "krbtgt"}
    _g, findings = compute_chains(edges, sources={"ME"}, sinks=sinks)
    assert findings, "ESC1 should reach a sink via auto-wired win edge"
    assert any("Domain Admins" in f.title for f in findings)


def test_dcsync_edge_alone_wins():
    """A DCSync edge to the domain DN should chain to the krbtgt sink."""
    edges = [
        Edge(src="ME", dst="DC=corp,DC=local", type="DCSync",
             dst_label="Domain (DCSync)", cost=1),
    ]
    sinks = {"krbtgt-SID": "krbtgt", "DA-SID": "Domain Admins"}
    _g, findings = compute_chains(edges, sources={"ME"}, sinks=sinks)
    assert findings


def test_acl_chain_only_no_win_edge():
    """Sanity: pure ACL chains still work (regression for win-edge addition
    not breaking the existing path-finding)."""
    edges = [
        Edge(src="ME", dst="user", type="GenericAll", dst_label="user"),
        Edge(src="user", dst="DA-SID", type="AddMember", dst_label="Domain Admins"),
    ]
    sinks = {"DA-SID": "Domain Admins"}
    _g, findings = compute_chains(edges, sources={"ME"}, sinks=sinks)
    assert findings
    assert findings[0].evidence["hops"] == 2
