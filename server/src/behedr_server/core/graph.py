# server/core/graph.py — Per-system directed process graph (networkx)
"""
Hard cap at GRAPH_MAX_NODES — prune oldest edge on overflow.
Chain detection only re-runs when topology changes (_new_edge set).
"""
import networkx as nx
from collections import defaultdict
from behedr_server.config import GRAPH_MAX_NODES

_graphs:   dict = defaultdict(nx.DiGraph)
_new_edge: set  = set()


def add_event(e):
    sid = e["system_id"]
    G   = _graphs[sid]
    p, c = e["parent"], e["child"]

    if G.number_of_nodes() >= GRAPH_MAX_NODES:
        oldest = min(G.edges(data=True), key=lambda x: x[2].get("first_seen", 0), default=None)
        if oldest:
            G.remove_edge(oldest[0], oldest[1])
            for node in [oldest[0], oldest[1]]:
                if G.degree(node) == 0:
                    G.remove_node(node)

    if not G.has_node(p): G.add_node(p)
    if not G.has_node(c): G.add_node(c)

    if G.has_edge(p, c):
        G[p][c]["weight"] += 1
    else:
        G.add_edge(p, c, weight=1, first_seen=e.get("time", 0))
        _new_edge.add(sid)


def rebuild_from_db():
    from behedr_server.database.storage import get_all_events_for_graph
    events = get_all_events_for_graph()
    for e in events:
        add_event({
            "system_id": e["system_id"],
            "parent":    e["parent"],
            "child":     e["child"],
            "time":      e["timestamp"],
        })
    if events:
        print(f"[GRAPH] Rebuilt {len(_graphs)} system graph(s) from {len(events)} events.")


def get_chains(system_id, min_len=4):
    """Find suspicious chains. Only re-runs when topology changed."""
    G = _graphs[system_id]
    if G.number_of_nodes() < min_len:
        return []
    if system_id not in _new_edge:
        return []
    _new_edge.discard(system_id)

    chains = []
    roots  = [n for n in G.nodes() if G.in_degree(n) == 0] or list(G.nodes())[:3]
    for src in roots:
        for dst in G.nodes():
            if src == dst:
                continue
            try:
                for path in nx.all_simple_paths(G, src, dst, cutoff=7):
                    if len(path) >= min_len:
                        chains.append(path)
                        if len(chains) >= 100:
                            return chains
            except nx.NetworkXError:
                pass
    return chains


def to_json(system_id):
    G = _graphs[system_id]
    return {
        "nodes": [{"id": n} for n in G.nodes()],
        "edges": [
            {"source": u, "target": v, "weight": d.get("weight", 1)}
            for u, v, d in G.edges(data=True)
        ],
    }
