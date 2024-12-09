from pydot import Dot, Node, Edge

from grammar.my_types import HandleNode, KeyNode


def convert_graph_to_dot(graph: dict[int, HandleNode | KeyNode]) -> Dot:
    dot = Dot(graph_type="digraph", labeljust="right")

    for n, attr in graph.items():
        if isinstance(attr, HandleNode):
            node = Node(
                n,
                label=f"id={n}, points_to={attr.points_to}",
                shape="box",
                style="filled",
                fillcolor="lightblue",
                peripheries=2 if attr.initial else 1)
            dot.add_node(node)
        elif isinstance(attr, KeyNode):
            node = Node(
                n,
                label=f"id={n}, value={attr.value}",
                shape="box",
                style="filled",
                fillcolor="lightgreen",
                peripheries=2 if attr.initial else 1)
            dot.add_node(node)

    for n, attr in graph.items():
        if isinstance(attr, HandleNode):
            match attr.unwrap_in:
                case (e1, e2):
                    edge1 = Edge(e1, n, label=f"unwrap({e1},{e2})")
                    edge2 = Edge(e2, n, label=f"unwrap({e1},{e2})")
                    dot.add_edge(edge1)
                    dot.add_edge(edge2)
        elif isinstance(attr, KeyNode):
            for e in attr.handle_in:
                edge = Edge(e, n, label="handle")
                dot.add_edge(edge)
            for (e1, e2) in attr.wrap_in:
                edge1 = Edge(e1, n, label=f"wrap({e1},{e2})")
                edge2 = Edge(e2, n, label=f"wrap({e1},{e2})")
                dot.add_edge(edge1)
                dot.add_edge(edge2)
            for (e1, e2) in attr.encrypt_in:
                edge1 = Edge(e1, n, label=f"encrypt({e1},{e2})")
                edge2 = Edge(e2, n, label=f"encrypt({e1},{e2})")
                dot.add_edge(edge1)
                dot.add_edge(edge2)
            for (e1, e2) in attr.decrypt_in:
                edge1 = Edge(e1, n, label=f"decrypt({e1},{e2})")
                edge2 = Edge(e2, n, label=f"decrypt({e1},{e2})")
                dot.add_edge(edge1)
                dot.add_edge(edge2)
            for (e1, e2) in attr.intruder_decrypt_in:
                edge1 = Edge(e1, n, label=f"intruderdecrypt({e1},{e2})")
                edge2 = Edge(e2, n, label=f"intruderdecrypt({e1},{e2})")
                dot.add_edge(edge1)
                dot.add_edge(edge2)

    return dot


def visualize_graph(graph: dict[int, HandleNode | KeyNode], file: str):
    """
    Visualize the graph using pydot in PNG format
    :param graph:
    :param file: name of the file without extension
    """
    dot = convert_graph_to_dot(graph)
    dot.write(f"{file}.png", format="png")
