from collections.abc import Callable
from itertools import count

from grammar.invariants import check_all_key_nodes_have_different_values
from grammar.types import HandleNode, KeyNode
from grammar.visualization import visualize_graph
from grammar.graph import decrypt, unwrap, encrypt, wrap


def expand_graph(graph: dict[int, HandleNode | KeyNode],
                 n_iter: int,
                 new_handle_cond: Callable[[KeyNode | None, list[HandleNode]], bool] = lambda _1, _2: True,
                 debug=False) -> dict[int, HandleNode | KeyNode]:
    check_all_key_nodes_have_different_values(graph)

    # generates ids for new nodes in the graph
    id_generator = count(max(graph.keys()) + 1)

    for i in range(n_iter):
        graph = decrypt(graph, id_generator)
        check_all_key_nodes_have_different_values(graph)

        graph = unwrap(graph, id_generator, new_handle_cond)
        check_all_key_nodes_have_different_values(graph)

        graph = encrypt(graph, id_generator)
        check_all_key_nodes_have_different_values(graph)

        graph = wrap(graph, id_generator)
        check_all_key_nodes_have_different_values(graph)

        if debug:
            visualize_graph(graph, f"expand_{i}")

    return graph
