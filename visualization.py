import typing

from aalpy import MealyMachine, MealyState
from networkx.classes import MultiDiGraph
from pydot import Dot, Node, Edge

from my_types import KnowledgeBase, PKCS11_FunctionArguments, \
    PKCS11_WrapArguments, \
    PKCS11_UnwrapArguments, \
    PKCS11_EncryptArguments, \
    PKCS11_DecryptArguments, \
    IntruderDecryptArguments
from pkcs11_sul_inputs import NOT_APPLICABLE


def convert_knowledege_base_to_dot(kb: KnowledgeBase, initial_nodes: set[int]) -> Dot:
    dot = Dot(kb_type="dikb", labeljust="right")

    for n, attr in kb.handles.items():
        node = Node(str(n),
                    label=f"id={n}, value={attr.value}",
                    shape="box",
                    style="filled",
                    fillcolor="lightblue",
                    peripheries=2 if n in initial_nodes else 1)
        dot.add_node(node)
    for n, attr in kb.keys.items():
        node = Node(str(n),
                    label=f"id={n}, value={attr.value}",
                    shape="box",
                    peripheries=2 if n in initial_nodes else 1)
        dot.add_node(node)

    for wrapped_key, wrap_arguments_list in kb.wrap_arguments_list.items():
        for arguments in wrap_arguments_list:
            edge1 = Edge(str(arguments.handle_of_wrapping_key), str(wrapped_key),
                         label=f"<wrap(<u>{arguments.handle_of_wrapping_key}</u>,{arguments.handle_of_key_to_be_wrapped})={wrapped_key}>")
            edge2 = Edge(str(arguments.handle_of_key_to_be_wrapped), str(wrapped_key),
                         label=f"<wrap({arguments.handle_of_wrapping_key},<u>{arguments.handle_of_key_to_be_wrapped}</u>)={wrapped_key}>")
            dot.add_edge(edge1)
            dot.add_edge(edge2)

    for handle_of_recovered_key, arguments in kb.unwrap_arguments.items():
        edge1 = Edge(str(arguments.handle_of_unwrapping_key), str(handle_of_recovered_key),
                     label=f"<unwrap(<u>{arguments.handle_of_unwrapping_key}</u>,{arguments.key_to_be_unwrapped})={handle_of_recovered_key}>")
        edge2 = Edge(str(arguments.key_to_be_unwrapped), str(handle_of_recovered_key),
                     label=f"<unwrap({arguments.handle_of_unwrapping_key},<u>{arguments.key_to_be_unwrapped}</u>)={handle_of_recovered_key}>")
        dot.add_edge(edge1)
        dot.add_edge(edge2)

    for encrypted_key, encrypt_arguments_list in kb.encrypt_arguments_list.items():
        for arguments in encrypt_arguments_list:
            edge1 = Edge(str(arguments.handle_of_encryption_key), str(encrypted_key),
                         label=f"<encrypt(<u>{arguments.handle_of_encryption_key}</u>,{arguments.key_to_be_encrypted})={encrypted_key}>")
            edge2 = Edge(str(arguments.key_to_be_encrypted), str(encrypted_key),
                         label=f"<encrypt({arguments.handle_of_encryption_key},<u>{arguments.key_to_be_encrypted}</u>)={encrypted_key}>")
            dot.add_edge(edge1)
            dot.add_edge(edge2)

    for decrypted_key, decrypt_arguments_list in kb.decrypt_arguments_list.items():
        for arguments in decrypt_arguments_list:
            edge1 = Edge(str(arguments.handle_of_decryption_key), str(decrypted_key),
                         label=f"<decrypt(<u>{arguments.handle_of_decryption_key}</u>,{arguments.key_to_be_decrypted})={decrypted_key}>")
            edge2 = Edge(str(arguments.key_to_be_decrypted), str(decrypted_key),
                         label=f"<decrypt({arguments.handle_of_decryption_key},<u>{arguments.key_to_be_decrypted}</u>)={decrypted_key}>")
            dot.add_edge(edge1)
            dot.add_edge(edge2)

    for decrypted_key, arguments in kb.intruder_decrypt_arguments.items():
        edge1 = Edge(str(arguments.decryption_key), str(decrypted_key),
                     label=f"<intruderdecrypt(<u>{arguments.decryption_key}</u>,{arguments.key_to_be_decrypted})={decrypted_key}>")
        edge2 = Edge(str(arguments.key_to_be_decrypted), str(decrypted_key),
                     label=f"<intruderdecrypt({arguments.decryption_key},<u>{arguments.key_to_be_decrypted}</u>)={decrypted_key}>")
        dot.add_edge(edge1)
        dot.add_edge(edge2)

    return dot


def convert_model_to_dot_compact(kb: KnowledgeBase, initial_nodes: set[int], model: MultiDiGraph) -> Dot:
    dot = Dot(graph_type="digraph", labeljust="right")

    # First, draw the nodes.

    for n in model.nodes:
        handlenode = kb.handles.get(n)
        if handlenode is not None:
            node = Node(str(n),
                        label=f"id={n}, value={handlenode.value}",
                        shape="box",
                        style="filled",
                        fillcolor="lightblue",
                        peripheries=2 if n in initial_nodes else 1)
            dot.add_node(node)

        keynode = kb.keys.get(n)
        if keynode is not None:
            node = Node(str(n),
                        label=f"id={n}, value={keynode.value}",
                        shape="box",
                        peripheries=2 if n in initial_nodes else 1)
            dot.add_node(node)

    # Then, draw the edges.

    for n, node in model.nodes(data=True):
        if n not in initial_nodes:
            # By construction, if n is not an initial node, then the networkx node has the attribute "arguments".
            # Therefore, we could equivalently check that check node.get("arguments") is not None.
            arguments: PKCS11_FunctionArguments = node["arguments"]

            match arguments:
                case PKCS11_WrapArguments(handle_of_wrapping_key, handle_of_key_to_be_wrapped):
                    wrapped_key = n
                    edge1 = Edge(str(handle_of_wrapping_key), str(wrapped_key),
                                 label=f"<wrap(<u>{handle_of_wrapping_key}</u>,{handle_of_key_to_be_wrapped})={wrapped_key}>")
                    edge2 = Edge(str(handle_of_key_to_be_wrapped), str(wrapped_key),
                                 label=f"<wrap({handle_of_wrapping_key},<u>{handle_of_key_to_be_wrapped}</u>)={wrapped_key}>")
                    dot.add_edge(edge1)
                    dot.add_edge(edge2)
                case PKCS11_UnwrapArguments(handle_of_unwrapping_key, key_to_be_unwrapped):
                    handle_of_recovered_key = n
                    edge1 = Edge(str(handle_of_unwrapping_key), str(handle_of_recovered_key),
                                 label=f"<unwrap(<u>{handle_of_unwrapping_key}</u>,{key_to_be_unwrapped})={handle_of_recovered_key}>")
                    edge2 = Edge(str(key_to_be_unwrapped), str(handle_of_recovered_key),
                                 label=f"<unwrap({handle_of_unwrapping_key},<u>{key_to_be_unwrapped}</u>)={handle_of_recovered_key}>")
                    dot.add_edge(edge1)
                    dot.add_edge(edge2)
                case PKCS11_EncryptArguments(handle_of_encryption_key, key_to_be_encrypted):
                    encrypted_key = n
                    edge1 = Edge(str(handle_of_encryption_key), str(encrypted_key),
                                 label=f"<encrypt(<u>{handle_of_encryption_key}</u>,{key_to_be_encrypted})={encrypted_key}>")
                    edge2 = Edge(str(key_to_be_encrypted), str(encrypted_key),
                                 label=f"<encrypt({handle_of_encryption_key},<u>{key_to_be_encrypted}</u>)={encrypted_key}>")
                    dot.add_edge(edge1)
                    dot.add_edge(edge2)
                case PKCS11_DecryptArguments(handle_of_decryption_key, key_to_be_decrypted):
                    decrypted_key = n
                    edge1 = Edge(str(handle_of_decryption_key), str(decrypted_key),
                                 label=f"<decrypt(<u>{handle_of_decryption_key}</u>,{key_to_be_decrypted})={decrypted_key}>")
                    edge2 = Edge(str(key_to_be_decrypted), str(decrypted_key),
                                 label=f"<decrypt({handle_of_decryption_key},<u>{key_to_be_decrypted}</u>)={decrypted_key}>")
                    dot.add_edge(edge1)
                    dot.add_edge(edge2)
                case IntruderDecryptArguments(decryption_key, key_to_be_decrypted):
                    decrypted_key = n
                    edge1 = Edge(str(decryption_key), str(decrypted_key),
                                 label=f"<intruderdecrypt(<u>{decryption_key}</u>,{key_to_be_decrypted})={decrypted_key}>")
                    edge2 = Edge(str(key_to_be_decrypted), str(decrypted_key),
                                 label=f"<intruderdecrypt({decryption_key},<u>{key_to_be_decrypted}</u>)={decrypted_key}>")
                    dot.add_edge(edge1)
                    dot.add_edge(edge2)
                case _:
                    typing.assert_never(arguments)

    return dot


def remove_not_applicable_transitions(mealy: MealyMachine):
    source: MealyState
    for source in mealy.states:
        destination: MealyState
        for _transition, _destination in source.transitions.items():
            pass
        for transition, output in source.output_fun.copy().items():
            if output == NOT_APPLICABLE:
                del source.transitions[transition]
                del source.output_fun[transition]
