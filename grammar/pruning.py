from grammar.invariants import check_all_implied_nodes_are_present, check_all_implicant_nodes_are_present
from grammar.my_types import HandleNode, KeyNode, Security
from grammar.visualization import visualize_graph

DEBUG = False


def prune_graph(graph: dict[int, HandleNode | KeyNode]) -> dict[int, HandleNode | KeyNode]:
    it = 0
    while True:
        non_implying_handle_nodes: list[tuple[int, HandleNode]] = [(n, attr) for n, attr in graph.items() if
                                                                   isinstance(attr, HandleNode) and
                                                                   not attr.implies_other_nodes()]
        non_implying_key_nodes: list[tuple[int, KeyNode]] = [(n, attr) for n, attr in graph.items() if
                                                             isinstance(attr, KeyNode) and
                                                             not attr.implies_other_nodes()]
        changed = False

        for (n1, attr1) in non_implying_handle_nodes:
            n1: int
            attr1: HandleNode
            attr2: KeyNode = graph[attr1.points_to]
            if attr1.initial:
                assert attr2.initial
                if attr1.unwrap_in is not None:
                    if attr1.copy.unwrap_in is None:
                        ne1: HandleNode = graph[attr1.unwrap_in.handle_of_unwrapping_key]
                        ne2: KeyNode = graph[attr1.unwrap_in.key_to_be_unwrapped]
                        ne1.unwrap_out.remove(attr1.unwrap_in)
                        ne2.unwrap_out.remove(attr1.unwrap_in)
                        attr1.unwrap_in = None
                        changed = True
                    elif attr1.copy.unwrap_in == attr1.unwrap_in:
                        pass
            else:  # not attr1.initial
                assert attr1.unwrap_in is not None
                ne1: HandleNode = graph[attr1.unwrap_in.handle_of_unwrapping_key]
                ne2: KeyNode = graph[attr1.unwrap_in.key_to_be_unwrapped]
                ne1.unwrap_out.remove(attr1.unwrap_in)
                ne2.unwrap_out.remove(attr1.unwrap_in)
                del graph[n1]
                attr2.handle_in.remove(n1)
                changed = True

        for (n1, attr1) in non_implying_key_nodes:
            n1: int
            attr1: KeyNode
            if attr1.security == Security.LOW:
                if attr1.initial:
                    for implication in attr1.wrap_in.copy():
                        if implication not in attr1.copy.wrap_in:
                            ne1: HandleNode = graph[implication.handle_of_wrapping_key]
                            ne2: HandleNode = graph[implication.handle_of_key_to_be_wrapped]
                            ne1.wrap_out.remove(implication)
                            ne2.wrap_out.remove(implication)
                            attr1.wrap_in.remove(implication)
                            changed = True
                    for implication in attr1.encrypt_in.copy():
                        if implication not in attr1.copy.encrypt_in:
                            ne1: HandleNode = graph[implication.handle_of_encryption_key]
                            ne2: KeyNode = graph[implication.key_to_be_encrypted]
                            ne1.encrypt_out.remove(implication)
                            ne2.encrypt_out.remove(implication)
                            attr1.encrypt_in.remove(implication)
                            changed = True
                    for implication in attr1.decrypt_in.copy():
                        if implication not in attr1.copy.decrypt_in:
                            ne1: HandleNode = graph[implication.handle_of_decryption_key]
                            ne2: KeyNode = graph[implication.key_to_be_decrypted]
                            ne1.decrypt_out.remove(implication)
                            ne2.decrypt_out.remove(implication)
                            attr1.decrypt_in.remove(implication)
                            changed = True
                    for implication in attr1.intruder_decrypt_in.copy():
                        if implication not in attr1.copy.intruder_decrypt_in:
                            ne1: KeyNode = graph[implication.decryption_key]
                            ne2: KeyNode = graph[implication.key_to_be_decrypted]
                            ne1.intruder_decrypt_out.remove(implication)
                            ne2.intruder_decrypt_out.remove(implication)
                            attr1.intruder_decrypt_in.remove(implication)
                            changed = True
                    attr1.known = attr1.copy.known
                    # keep attr1.handle_in unchanged
                else:  # not attr1.initial
                    if len(attr1.handle_in) == 0:  # case 5
                        for implication in attr1.wrap_in.copy():
                            ne1: HandleNode = graph[implication.handle_of_wrapping_key]
                            ne2: HandleNode = graph[implication.handle_of_key_to_be_wrapped]
                            ne1.wrap_out.remove(implication)
                            ne2.wrap_out.remove(implication)
                            attr1.wrap_in.remove(implication)
                        for implication in attr1.encrypt_in.copy():
                            ne1: HandleNode = graph[implication.handle_of_encryption_key]
                            ne2: KeyNode = graph[implication.key_to_be_encrypted]
                            ne1.encrypt_out.remove(implication)
                            ne2.encrypt_out.remove(implication)
                            attr1.encrypt_in.remove(implication)
                        for implication in attr1.decrypt_in.copy():
                            ne1: HandleNode = graph[implication.handle_of_decryption_key]
                            ne2: KeyNode = graph[implication.key_to_be_decrypted]
                            ne1.decrypt_out.remove(implication)
                            ne2.decrypt_out.remove(implication)
                            attr1.decrypt_in.remove(implication)
                        for implication in attr1.intruder_decrypt_in.copy():
                            ne1: KeyNode = graph[implication.decryption_key]
                            ne2: KeyNode = graph[implication.key_to_be_decrypted]
                            ne1.intruder_decrypt_out.remove(implication)
                            ne2.intruder_decrypt_out.remove(implication)
                            attr1.intruder_decrypt_in.remove(implication)
                        del graph[n1]
                        changed = True
                    else:
                        for implication in attr1.wrap_in.copy():
                            ne1: HandleNode = graph[implication.handle_of_wrapping_key]
                            ne2: HandleNode = graph[implication.handle_of_key_to_be_wrapped]
                            ne1.wrap_out.remove(implication)
                            ne2.wrap_out.remove(implication)
                            attr1.wrap_in.remove(implication)
                            changed = True
                        for implication in attr1.encrypt_in.copy():
                            ne1: HandleNode = graph[implication.handle_of_encryption_key]
                            ne2: KeyNode = graph[implication.key_to_be_encrypted]
                            ne1.encrypt_out.remove(implication)
                            ne2.encrypt_out.remove(implication)
                            attr1.encrypt_in.remove(implication)
                            changed = True
                        for implication in attr1.decrypt_in.copy():
                            ne1: HandleNode = graph[implication.handle_of_decryption_key]
                            ne2: KeyNode = graph[implication.key_to_be_decrypted]
                            ne1.decrypt_out.remove(implication)
                            ne2.decrypt_out.remove(implication)
                            attr1.decrypt_in.remove(implication)
                            changed = True
                        for implication in attr1.intruder_decrypt_in.copy():
                            ne1: KeyNode = graph[implication.decryption_key]
                            ne2: KeyNode = graph[implication.key_to_be_decrypted]
                            ne1.intruder_decrypt_out.remove(implication)
                            ne2.intruder_decrypt_out.remove(implication)
                            attr1.intruder_decrypt_in.remove(implication)
                            changed = True
                        attr1.known = False
                        # keep attr1.handle_in unchanged

        check_all_implicant_nodes_are_present(graph)
        check_all_implied_nodes_are_present(graph)

        if changed:
            if DEBUG:
                visualize_graph(graph, f"pruning_{it}")
            it += 1
        else:
            break

    return graph
