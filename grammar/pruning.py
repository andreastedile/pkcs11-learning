from copy import deepcopy
from itertools import count

from grammar.my_types import HandleNode, KeyNode, Security
from grammar.visualization import visualize_graph


def implies_other_nodes(graph: dict[int, HandleNode | KeyNode], n1: int) -> bool:
    """
    A node is said to imply another node if there is a wrap, unwrap, encrypt, decrypt edge from the node to the other.
    Thus, a handle node that only points to a key node is not considered as an implying node.
    :param graph:
    :param n1:
    :return:
    """
    attr1 = graph[n1]

    if isinstance(attr1, HandleNode):
        for n2, attr2 in graph.items():
            if n1 == n2:
                continue
            if isinstance(attr2, HandleNode):
                match attr2.unwrap_in:
                    case (e1, e2):
                        if e1 == n1:  # unwrap(n1, ?) = n2
                            return True
                        if e2 == n1:  # unwrap(?, n1) = n2 impossible
                            raise TypeError
            elif isinstance(attr2, KeyNode):
                for (e1, e2) in attr2.wrap_in:
                    if e1 == n1:  # wrap(n1, ?) = n2
                        return True
                    if e2 == n1:  # wrap(?, n1) = n2
                        return True
                for (e1, e2) in attr2.encrypt_in:
                    if e1 == n1:  # encrypt(n1, ?) = n2
                        return True
                    if e2 == n1:  # encrypt(?, n1) = n2 impossible
                        raise TypeError
                for (e1, e2) in attr2.decrypt_in:
                    if e1 == n1:  # decrypt(n1, ?) = n2
                        return True
                    if e2 == n1:  # decrypt(?, n1) = n2 impossible
                        raise TypeError
    elif isinstance(attr1, KeyNode):
        for n2, attr2 in graph.items():
            if n1 == n2:
                continue
            if isinstance(attr2, HandleNode):
                match attr2.unwrap_in:
                    case (e1, e2):
                        if e1 == n1:  # unwrap(n1, ?) = n2 impossible
                            raise TypeError
                        if e2 == n1:  # unwrap(?, n1) = n2
                            return True
            elif isinstance(attr2, KeyNode):
                for (e1, e2) in attr2.wrap_in:
                    if e1 == n1:  # wrap(n1, ?) = n2 impossible
                        raise TypeError
                    if e2 == n1:  # wrap(?, n1) = n2
                        return True
                for (e1, e2) in attr2.encrypt_in:
                    if e1 == n1:  # encrypt(n1, ?) = n2 impossible
                        raise TypeError
                    if e2 == n1:  # encrypt(?, n1) = n2
                        return True
                for (e1, e2) in attr2.decrypt_in:
                    if e1 == n1:  # decrypt(n1, ?) = n2 impossible
                        raise TypeError
                    if e2 == n1:  # decrypt(?, n1) = n2
                        return True
                for (e1, e2) in attr2.intruder_decrypt_in:
                    if e1 == n1:  # intruder_decrypt(n1, ?) = n2
                        return True
                    if e2 == n1:  # intruder_decrypt(?, n1) = n2
                        return True
    return False


def prune_graph(graph: dict[int, HandleNode | KeyNode], debug=False) -> \
        dict[int, HandleNode | KeyNode]:
    graph = deepcopy(graph)
    counter = count()

    while True:
        non_implying_handle_nodes: list[tuple[int, HandleNode]] = [(n, attr) for n, attr in graph.items() if
                                                                   isinstance(attr, HandleNode) and
                                                                   not attr.implies_other_nodes()]
        non_implying_key_nodes: list[tuple[int, KeyNode]] = [(n, attr) for n, attr in graph.items() if
                                                             isinstance(attr, KeyNode) and
                                                             not attr.implies_other_nodes()]
        changed = False

        for (n1, attr1) in non_implying_handle_nodes:
            attr2: KeyNode = graph[attr1.points_to]
            if attr1.initial:
                assert attr2.initial
                match attr1.unwrap_in:
                    case (e1, e2) if attr1.copy.unwrap_in is None:
                        ne1: HandleNode = graph[e1]
                        ne2: KeyNode = graph[e2]
                        ne1.unwrap_out.remove((e2, n1))
                        ne2.unwrap_out.remove((e1, n1))
                        attr1.unwrap_in = None
                        changed = True
                    case (e1, e2) if attr1.copy.unwrap_in == (e1, e2):
                        pass
                    case None:
                        pass
                    case other:
                        raise ValueError(other)
            else:  # not attr1.initial
                match attr1.unwrap_in:
                    case (e1, e2):
                        ne1: HandleNode = graph[e1]
                        ne2: KeyNode = graph[e2]
                        ne1.unwrap_out.remove((e2, n1))
                        ne2.unwrap_out.remove((e1, n1))
                        del graph[n1]
                        attr2.handle_in.remove(n1)
                        changed = True
                    case None:
                        raise ValueError

        for (n1, attr1) in non_implying_key_nodes:
            if attr1.security == Security.LOW:
                if attr1.initial:
                    for (e1, e2) in attr1.wrap_in:
                        if (e1, e2) not in attr1.copy.wrap_in:
                            ne1: HandleNode = graph[e1]
                            ne2: HandleNode = graph[e2]
                            ne1.wrap_out.remove((e2, n1))
                            ne2.wrap_out.remove((e1, n1))
                            attr1.wrap_in.remove((e1, e2))
                            changed = True
                    for (e1, e2) in attr1.encrypt_in:
                        if (e1, e2) not in attr1.copy.encrypt_in:
                            ne1: HandleNode = graph[e1]
                            ne2: KeyNode = graph[e2]
                            ne1.encrypt_out.remove((e2, n1))
                            ne2.encrypt_out.remove((e1, n1))
                            attr1.encrypt_in.remove((e1, e2))
                            changed = True
                    for (e1, e2) in attr1.decrypt_in:
                        if (e1, e2) not in attr1.copy.decrypt_in:
                            ne1: HandleNode = graph[e1]
                            ne2: KeyNode = graph[e2]
                            ne1.decrypt_out.remove((e2, n1))
                            ne2.decrypt_out.remove((e1, n1))
                            attr1.decrypt_in.remove((e1, e2))
                            changed = True
                    for (e1, e2) in attr1.intruder_decrypt_in:
                        if (e1, e2) not in attr1.copy.intruder_decrypt_in:
                            ne1: KeyNode = graph[e1]
                            ne2: KeyNode = graph[e2]
                            ne1.intruder_decrypt_out.remove((e2, n1))
                            ne2.intruder_decrypt_out.remove((e1, n1))
                            attr1.intruder_decrypt_in.remove((e1, e2))
                            changed = True
                    attr1.known = attr1.copy.known
                    # keep attr1.handle_in unchanged
                else:  # not attr1.initial
                    if len(attr1.handle_in) == 0:  # case 5
                        for (e1, e2) in attr1.wrap_in:
                            ne1: HandleNode = graph[e1]
                            ne2: HandleNode = graph[e2]
                            ne1.wrap_out.remove((e2, n1))
                            ne2.wrap_out.remove((e1, n1))
                            attr1.wrap_in.remove((e1, e2))
                        for (e1, e2) in attr1.encrypt_in:
                            ne1: HandleNode = graph[e1]
                            ne2: KeyNode = graph[e2]
                            ne1.encrypt_out.remove((e2, n1))
                            ne2.encrypt_out.remove((e1, n1))
                            attr1.encrypt_in.remove((e1, e2))
                        for (e1, e2) in attr1.decrypt_in:
                            ne1: HandleNode = graph[e1]
                            ne2: KeyNode = graph[e2]
                            ne1.decrypt_out.remove((e2, n1))
                            ne2.decrypt_out.remove((e1, n1))
                            attr1.decrypt_in.remove((e1, e2))
                        for (e1, e2) in attr1.intruder_decrypt_in:
                            ne1: KeyNode = graph[e1]
                            ne2: KeyNode = graph[e2]
                            ne1.intruder_decrypt_out.remove((e2, n1))
                            ne2.intruder_decrypt_out.remove((e1, n1))
                            attr1.intruder_decrypt_in.remove((e1, e2))
                        del graph[n1]
                        changed = True
                    else:
                        for (e1, e2) in attr1.wrap_in:
                            ne1: HandleNode = graph[e1]
                            ne2: HandleNode = graph[e2]
                            ne1.wrap_out.remove((e2, n1))
                            ne2.wrap_out.remove((e1, n1))
                            attr1.wrap_in.remove((e1, e2))
                            changed = True
                        for (e1, e2) in attr1.encrypt_in:
                            ne1: HandleNode = graph[e1]
                            ne2: KeyNode = graph[e2]
                            ne1.encrypt_out.remove((e2, n1))
                            ne2.encrypt_out.remove((e1, n1))
                            attr1.encrypt_in.remove((e1, e2))
                            changed = True
                        for (e1, e2) in attr1.decrypt_in:
                            ne1: HandleNode = graph[e1]
                            ne2: KeyNode = graph[e2]
                            ne1.decrypt_out.remove((e2, n1))
                            ne2.decrypt_out.remove((e1, n1))
                            attr1.decrypt_in.remove((e1, e2))
                            changed = True
                        for (e1, e2) in attr1.intruder_decrypt_in:
                            ne1: KeyNode = graph[e1]
                            ne2: KeyNode = graph[e2]
                            ne1.intruder_decrypt_out.remove((e2, n1))
                            ne2.intruder_decrypt_out.remove((e1, n1))
                            attr1.intruder_decrypt_in.remove((e1, e2))
                            changed = True
                        attr1.known = False
                        # keep attr1.handle_in unchanged

        if changed and debug:
            visualize_graph(graph, f"pruning_{next(counter)}")

        if not changed:
            break

    return graph
