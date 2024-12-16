from pydot import Dot, Node, Edge

from grammar.my_types import HandleNode, KeyNode, Security


def convert_graph_to_dot(graph: dict[int, HandleNode | KeyNode],
                         true_nodes: list[int] = None,
                         visible_wrap_implications: list[tuple[int, int, int]] = None,
                         visible_unwrap_implications: list[tuple[int, int, int]] = None,
                         visible_encrypt_implications: list[tuple[int, int, int]] = None,
                         visible_decrypt_implications: list[tuple[int, int, int]] = None,
                         visible_intruder_decrypt_implications: list[tuple[int, int, int]] = None) -> Dot:
    if true_nodes is None:
        true_nodes = list(graph.keys())

    if visible_wrap_implications is None:
        visible_wrap_implications = []
        for n, attr in graph.items():
            if isinstance(attr, KeyNode):
                for (e1, e2) in attr.wrap_in:
                    visible_wrap_implications.append((e1, e2, n))
    if visible_unwrap_implications is None:
        visible_unwrap_implications = []
        for n, attr in graph.items():
            if isinstance(attr, HandleNode):
                match attr.unwrap_in:
                    case (e1, e2):
                        visible_unwrap_implications.append((e1, e2, n))
    if visible_encrypt_implications is None:
        visible_encrypt_implications = []
        for n, attr in graph.items():
            if isinstance(attr, KeyNode):
                for (e1, e2) in attr.encrypt_in:
                    visible_encrypt_implications.append((e1, e2, n))
    if visible_decrypt_implications is None:
        visible_decrypt_implications = []
        for n, attr in graph.items():
            if isinstance(attr, KeyNode):
                for (e1, e2) in attr.decrypt_in:
                    visible_decrypt_implications.append((e1, e2, n))
    if visible_intruder_decrypt_implications is None:
        visible_intruder_decrypt_implications = []
        for n, attr in graph.items():
            if isinstance(attr, KeyNode):
                for (e1, e2) in attr.intruder_decrypt_in:
                    visible_intruder_decrypt_implications.append((e1, e2, n))

    dot = Dot(graph_type="digraph", labeljust="right")

    for n, attr in graph.items():
        if isinstance(attr, HandleNode):
            node = Node(
                n,
                label=f"id={n}, points_to={attr.points_to}",
                shape="box",
                style="filled" if n in true_nodes else "invis",
                fillcolor="lightblue",
                peripheries=2 if attr.initial else 1)
            dot.add_node(node)
        elif isinstance(attr, KeyNode):
            node = Node(
                n,
                label=f"id={n}, value={attr.value}",
                shape="box",
                style="filled" if n in true_nodes else "invis",
                fillcolor="lightgreen",
                peripheries=2 if attr.initial else 1,
                penwidth=1 if attr.security == Security.LOW else 2.5)
            dot.add_node(node)

    for n, attr in graph.items():
        if isinstance(attr, HandleNode):
            match attr.unwrap_in:
                case (e1, e2):
                    edge1 = Edge(e1, n, label=f"<unwrap(<u>{e1}</u>,{e2})>")
                    edge2 = Edge(e2, n, label=f"<unwrap({e1},<u>{e2}</u>)>")
                    if (e1, e2, n) not in visible_unwrap_implications:
                        edge1.set_style("invis")
                    if (e1, e2, n) not in visible_unwrap_implications:
                        edge2.set_style("invis")
                    dot.add_edge(edge1)
                    dot.add_edge(edge2)
        elif isinstance(attr, KeyNode):
            for e in attr.handle_in:
                edge = Edge(e, n, label="handle")
                if n not in true_nodes or e not in true_nodes:
                    edge.set_style("invis")
                dot.add_edge(edge)
            for (e1, e2) in attr.wrap_in:
                edge1 = Edge(e1, n, label=f"<wrap(<u>{e1}</u>,{e2})>")
                edge2 = Edge(e2, n, label=f"<wrap({e1},<u>{e2}</u>)>")
                if (e1, e2, n) not in visible_wrap_implications:
                    edge1.set_style("invis")
                if (e1, e2, n) not in visible_wrap_implications:
                    edge2.set_style("invis")
                dot.add_edge(edge1)
                dot.add_edge(edge2)
            for (e1, e2) in attr.encrypt_in:
                edge1 = Edge(e1, n, label=f"<encrypt(<u>{e1}</u>,{e2})>")
                edge2 = Edge(e2, n, label=f"<encrypt({e1},<u>{e2}</u>)>")
                if (e1, e2, n) not in visible_encrypt_implications:
                    edge1.set_style("invis")
                if (e1, e2, n) not in visible_encrypt_implications:
                    edge2.set_style("invis")
                dot.add_edge(edge1)
                dot.add_edge(edge2)
            for (e1, e2) in attr.decrypt_in:
                edge1 = Edge(e1, n, label=f"<decrypt(<u>{e1}</u>,{e2})>")
                edge2 = Edge(e2, n, label=f"<decrypt({e1},<u>{e2}</u>)>")
                if (e1, e2, n) not in visible_decrypt_implications:
                    edge1.set_style("invis")
                if (e1, e2, n) not in visible_decrypt_implications:
                    edge2.set_style("invis")
                dot.add_edge(edge1)
                dot.add_edge(edge2)
            for (e1, e2) in attr.intruder_decrypt_in:
                edge1 = Edge(e1, n, label=f"<intruderdecrypt(<u>{e1}</u>,{e2})>")
                edge2 = Edge(e2, n, label=f"<intruderdecrypt({e1},<u>{e2}</u>)>")
                if (e1, e2, n) not in visible_intruder_decrypt_implications:
                    edge1.set_style("invis")
                if (e1, e2, n) not in visible_intruder_decrypt_implications:
                    edge2.set_style("invis")
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
    dot.write(f"{file}.svg", format="svg")
