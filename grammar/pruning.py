from copy import deepcopy
from itertools import count

from grammar.my_types import HandleNode, KeyNode
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
    return False


def prune_graph(graph: dict[int, HandleNode | KeyNode], blocked_node_ids: set[int] = None, debug=False) -> \
        dict[int, HandleNode | KeyNode]:
    graph = deepcopy(graph)
    counter = count()

    if blocked_node_ids is None:
        blocked_node_ids = set()

    while True:
        non_blocked_non_implying_nodes = [n for n, attr in graph.items() if
                                          n not in blocked_node_ids and not implies_other_nodes(graph, n)]

        if len(non_blocked_non_implying_nodes) == 0:
            break
        else:
            print("non-blocked non-implying nodes:", non_blocked_non_implying_nodes)

            for n1 in non_blocked_non_implying_nodes:
                attr1 = graph[n1]
                if isinstance(attr1, HandleNode):
                    # once we remove a handle node, we must update the pointed key node
                    # so that it is no longer pointed by the handle
                    n2 = attr1.points_to
                    attr2: KeyNode = graph.get(n2)
                    if attr2 is not None:  # perhaps it was removed in a previous iteration
                        attr2.handle_in.remove(n1)

            for n in non_blocked_non_implying_nodes:
                del graph[n]

            if debug:
                visualize_graph(graph, f"pruning_{next(counter)}")

    return graph
