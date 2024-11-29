from collections.abc import Iterator, Callable
from copy import deepcopy

from grammar.types import HandleNode, KeyNode


def wrap(graph: dict[int, HandleNode | KeyNode], id_generator: Iterator[int]) -> dict[int, HandleNode | KeyNode]:
    graph_copy = deepcopy(graph)

    for n1, attr1 in [(n, attr) for n, attr in graph.items() if isinstance(attr, HandleNode)]:
        attr2: KeyNode
        n2, attr2 = attr1.points_to, graph[attr1.points_to]

        for n3, attr3 in [(n, attr) for n, attr in graph.items() if isinstance(attr, HandleNode)]:
            attr4: KeyNode
            n4, attr4 = attr3.points_to, graph[attr3.points_to]

            match [n for n, attr in graph_copy.items() if
                   isinstance(attr, KeyNode) and attr.value == (attr4.value, attr2.value)]:
                case []:
                    n5 = next(id_generator)
                    attr5 = KeyNode((deepcopy(attr4.value), deepcopy(attr2.value)), True, [], [(n1, n3)], [], [])
                    graph_copy[n5] = attr5
                case [n5]:
                    attr5: KeyNode = graph_copy[n5]
                    if (n1, n3) not in attr5.wrap_in:
                        attr5.wrap_in.append((n1, n3))
                    if not attr5.known:
                        attr5.known = True
                case other:
                    raise ValueError(other)

    return graph_copy


def encrypt(graph: dict[int, HandleNode | KeyNode], id_generator: Iterator[int]) -> dict[int, HandleNode | KeyNode]:
    graph_copy = deepcopy(graph)

    for n1, attr1 in [(n, attr) for n, attr in graph.items() if isinstance(attr, HandleNode)]:
        attr2: KeyNode
        n2, attr2 = attr1.points_to, graph[attr1.points_to]

        for n3, attr3 in [(n, attr) for n, attr in graph.items() if isinstance(attr, KeyNode) and attr.known]:
            match [n for n, attr in graph_copy.items() if
                   isinstance(attr, KeyNode) and attr.value == (attr3.value, attr2.value)]:
                case []:
                    n4 = next(id_generator)
                    attr4 = KeyNode((deepcopy(attr3.value), deepcopy(attr2.value)), True, [], [], [(n1, n3)], [])
                    graph_copy[n4] = attr4
                case [n4]:
                    attr4: KeyNode = graph_copy[n4]
                    if (n1, n3) not in attr4.encrypt_in:
                        attr4.encrypt_in.append((n1, n3))
                    if not attr4.known:
                        attr4.known = True
                case other:
                    raise ValueError(other)

    return graph_copy


def decrypt(graph: dict[int, HandleNode | KeyNode], id_generator: Iterator[int]) -> dict[int, HandleNode | KeyNode]:
    graph_copy = deepcopy(graph)

    for n1, attr1 in [(n, attr) for n, attr in graph.items() if isinstance(attr, HandleNode)]:
        attr2: KeyNode
        n2, attr2 = attr1.points_to, graph[attr1.points_to]

        for n3, attr3 in [(n, attr) for n, attr in graph.items() if isinstance(attr, KeyNode) and attr.known]:
            match attr3.value:
                case (inner, outer) if outer == attr2.value:
                    match [n for n, attr in graph_copy.items() if isinstance(attr, KeyNode) and attr.value == inner]:
                        case []:
                            n4 = next(id_generator)
                            attr4 = KeyNode(deepcopy(inner), True, [], [], [], [(n1, n3)])
                            graph_copy[n4] = attr4
                        case [n4]:
                            attr4: KeyNode = graph_copy[n4]
                            if (n1, n3) not in attr4.decrypt_in:
                                attr4.decrypt_in.append((n1, n3))
                            if not attr4.known:
                                attr4.known = True
                        case other:
                            raise ValueError(other)

    return graph_copy


def standard_unwrap_func(n: int | None, graph: dict[int, HandleNode | KeyNode]) -> int:
    # noinspection PyPep8Naming
    MAX_HANDLE_NODES_POINTING_TO_KEY_NODE = 2
    if n is None:
        return MAX_HANDLE_NODES_POINTING_TO_KEY_NODE
    else:
        attr: KeyNode = graph[n]
        return MAX_HANDLE_NODES_POINTING_TO_KEY_NODE - len(attr.handle_in)


def unwrap(graph: dict[int, HandleNode | KeyNode], id_generator: Iterator[int],
           unwrap_func: Callable[[int | None, dict[int, HandleNode | KeyNode]], int] = standard_unwrap_func) \
        -> dict[int, HandleNode | KeyNode]:
    graph_copy = deepcopy(graph)

    for n1, attr1 in [(n, attr) for n, attr in graph.items() if isinstance(attr, HandleNode)]:
        attr2: KeyNode
        n2, attr2 = attr1.points_to, graph[attr1.points_to]

        for n3, attr3 in [(n, attr) for n, attr in graph.items() if isinstance(attr, KeyNode) and attr.known]:
            match attr3.value:
                case (inner, outer) if outer == attr2.value:
                    match [n for n, attr in graph_copy.items() if isinstance(attr, KeyNode) and attr.value == inner]:
                        case []:
                            n_new_handles = unwrap_func(None, graph_copy)
                            if n_new_handles > 0:
                                # we create the key node if we create one or more handle nodes pointing to it as well.
                                n4 = next(id_generator)
                                attr4 = KeyNode(deepcopy(inner), False, [], [], [], [])
                                graph_copy[n4] = attr4

                                for i in range(n_new_handles):
                                    n5 = next(id_generator)
                                    attr5 = HandleNode(n4, (n1, n3))
                                    graph_copy[n5] = attr5

                                    attr4.handle_in.append(n5)
                        case [n4]:
                            attr4: KeyNode = graph_copy[n4]

                            n_new_handles = unwrap_func(n4, graph_copy)
                            if n_new_handles > 0:
                                n5 = next(id_generator)
                                attr5 = HandleNode(n4, (n1, n3))
                                graph_copy[n5] = attr5

                                attr4.handle_in.append(n5)
                        case other:
                            raise ValueError(other)

    return graph_copy
