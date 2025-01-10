from pydot import Dot, Node, Edge

from grammar.my_types import HandleNode, KeyNode, Security, \
    UnwrapImplication, WrapImplication, EncryptImplication, DecryptImplication, IntruderDecryptImplication


def convert_graph_to_dot(graph: dict[int, HandleNode | KeyNode],
                         true_nodes: list[int] = None,
                         visible_wrap_implications: list[WrapImplication] = None,
                         visible_unwrap_implications: list[UnwrapImplication] = None,
                         visible_encrypt_implications: list[EncryptImplication] = None,
                         visible_decrypt_implications: list[DecryptImplication] = None,
                         visible_intruder_decrypt_implications: list[IntruderDecryptImplication] = None) -> Dot:
    if true_nodes is None:
        true_nodes = list(graph.keys())

    if visible_wrap_implications is None:
        visible_wrap_implications = []
        for n, attr in graph.items():
            if isinstance(attr, KeyNode):
                for implication in attr.wrap_in:
                    visible_wrap_implications.append(implication)
    if visible_unwrap_implications is None:
        visible_unwrap_implications = []
        for n, attr in graph.items():
            if isinstance(attr, HandleNode):
                if attr.unwrap_in is not None:
                    visible_unwrap_implications.append(attr.unwrap_in)

    if visible_encrypt_implications is None:
        visible_encrypt_implications = []
        for n, attr in graph.items():
            if isinstance(attr, KeyNode):
                for implication in attr.encrypt_in:
                    visible_encrypt_implications.append(implication)
    if visible_decrypt_implications is None:
        visible_decrypt_implications = []
        for n, attr in graph.items():
            if isinstance(attr, KeyNode):
                for implication in attr.decrypt_in:
                    visible_decrypt_implications.append(implication)
    if visible_intruder_decrypt_implications is None:
        visible_intruder_decrypt_implications = []
        for n, attr in graph.items():
            if isinstance(attr, KeyNode):
                for implication in attr.intruder_decrypt_in:
                    visible_intruder_decrypt_implications.append(implication)

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
            if attr.unwrap_in is not None:
                edge1 = Edge(attr.unwrap_in.handle_of_unwrapping_key, n,
                             label=f"<unwrap(<u>{attr.unwrap_in.handle_of_unwrapping_key}</u>,{attr.unwrap_in.key_to_be_unwrapped})={n}>")
                edge2 = Edge(attr.unwrap_in.key_to_be_unwrapped, n,
                             label=f"<unwrap({attr.unwrap_in.handle_of_unwrapping_key},<u>{attr.unwrap_in.key_to_be_unwrapped}</u>)={n}>")
                if attr.unwrap_in not in visible_unwrap_implications:
                    edge1.set_style("invis")
                    edge2.set_style("invis")
                dot.add_edge(edge1)
                dot.add_edge(edge2)
        elif isinstance(attr, KeyNode):
            for e in attr.handle_in:
                edge = Edge(e, n, label="handle")
                if n not in true_nodes or e not in true_nodes:
                    edge.set_style("invis")
                dot.add_edge(edge)
            for implication in attr.wrap_in:
                edge1 = Edge(implication.handle_of_wrapping_key, n,
                             label=f"<wrap(<u>{implication.handle_of_wrapping_key}</u>,{implication.handle_of_key_to_be_wrapped})={n}>")
                edge2 = Edge(implication.handle_of_key_to_be_wrapped, n,
                             label=f"<wrap({implication.handle_of_wrapping_key},<u>{implication.handle_of_key_to_be_wrapped}</u>)={n}>")
                if implication not in visible_wrap_implications:
                    edge1.set_style("invis")
                    edge2.set_style("invis")
                dot.add_edge(edge1)
                dot.add_edge(edge2)
            for implication in attr.encrypt_in:
                edge1 = Edge(implication.handle_of_encryption_key, n,
                             label=f"<encrypt(<u>{implication.handle_of_encryption_key}</u>,{implication.key_to_be_encrypted})={n}>")
                edge2 = Edge(implication.key_to_be_encrypted, n,
                             label=f"<encrypt({implication.handle_of_encryption_key},<u>{implication.key_to_be_encrypted}</u>)={n}>")
                if implication not in visible_encrypt_implications:
                    edge1.set_style("invis")
                    edge2.set_style("invis")
                dot.add_edge(edge1)
                dot.add_edge(edge2)
            for implication in attr.decrypt_in:
                edge1 = Edge(implication.handle_of_decryption_key, n,
                             label=f"<decrypt(<u>{implication.handle_of_decryption_key}</u>,{implication.key_to_be_decrypted})={n}>")
                edge2 = Edge(implication.key_to_be_decrypted, n,
                             label=f"<decrypt({implication.handle_of_decryption_key},<u>{implication.key_to_be_decrypted}</u>)={n}>")
                if implication not in visible_decrypt_implications:
                    edge1.set_style("invis")
                    edge2.set_style("invis")
                dot.add_edge(edge1)
                dot.add_edge(edge2)
            for implication in attr.intruder_decrypt_in:
                edge1 = Edge(implication.decryption_key, n,
                             label=f"<intruderdecrypt(<u>{implication.decryption_key}</u>,{implication.key_to_be_decrypted})={n}>")
                edge2 = Edge(implication.key_to_be_decrypted, n,
                             label=f"<intruderdecrypt({implication.decryption_key},<u>{implication.key_to_be_decrypted}</u>)={n}>")
                if implication not in visible_intruder_decrypt_implications:
                    edge1.set_style("invis")
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
