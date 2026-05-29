from adex.findings import Edge
from adex.graph import Graph


def _e(src, dst, t="GenericWrite", cost=1):
    return Edge(src=src, dst=dst, type=t, dst_label=dst, cost=cost)


def test_graph_add_and_neighbors():
    g = Graph()
    g.add_edge(_e("A", "B"))
    g.add_edge(_e("A", "C"))
    g.add_edge(_e("B", "D"))
    assert sorted(g.nodes()) == ["A", "B", "C", "D"]
    nbrs = [n.dst for n in g.neighbors("A")]
    assert sorted(nbrs) == ["B", "C"]


def test_bfs_shortest_path():
    g = Graph()
    g.add_edges([
        _e("A", "B"), _e("B", "C"), _e("C", "D"),  # 3 hops
        _e("A", "X"), _e("X", "D"),                 # 2 hops
    ])
    paths = g.bfs_paths("A", "D")
    assert paths
    assert len(paths[0]) == 2  # shortest


def test_bfs_no_path():
    g = Graph()
    g.add_edges([_e("A", "B"), _e("C", "D")])
    assert g.bfs_paths("A", "D") == []


def test_find_paths_multi_source_sink():
    g = Graph()
    g.add_edges([
        _e("ME", "S1"), _e("ME", "S2"),
        _e("S1", "T1"), _e("S2", "T2"),
        _e("S1", "T2", cost=10),
    ])
    out = g.find_paths(["ME"], ["T1", "T2"])
    # 2 distinct shortest paths (via S1 and via S2)
    assert len(out) == 2
    # Sorted by length then cost — shortest first
    assert len(out[0]) == 2
