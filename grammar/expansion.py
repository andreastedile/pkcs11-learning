from collections.abc import Callable
from copy import deepcopy
from itertools import count

from grammar.invariants import check_all_key_nodes_have_different_values
from grammar.my_types import HandleNode, KeyNode
from grammar.visualization import visualize_graph
from grammar.graph import decrypt, unwrap, encrypt, wrap, standard_unwrap_func


def expand_graph(graph: dict[int, HandleNode | KeyNode],
                 n_iter: int,
                 unwrap_func: Callable[[int | None, dict[int, HandleNode | KeyNode]], int] = standard_unwrap_func,
                 debug=False) -> dict[int, HandleNode | KeyNode]:
    check_all_key_nodes_have_different_values(graph)

    # generates ids for new nodes in the graph
    id_generator = count(max(graph.keys()) + 1)

    input_graph = graph

    for i in range(n_iter):
        output_graph = deepcopy(input_graph)

        decrypt(input_graph, output_graph, id_generator)
        check_all_key_nodes_have_different_values(graph)

        unwrap(input_graph, output_graph, id_generator, unwrap_func)
        check_all_key_nodes_have_different_values(graph)

        encrypt(input_graph, output_graph, id_generator)
        check_all_key_nodes_have_different_values(graph)

        wrap(input_graph, output_graph, id_generator)
        check_all_key_nodes_have_different_values(graph)

        if debug:
            visualize_graph(output_graph, f"expand_{i}")

        input_graph = output_graph

    return input_graph
