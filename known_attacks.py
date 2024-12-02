from copy import deepcopy
from itertools import count

from grammar.graph import wrap, decrypt, encrypt, unwrap, intruder_decrypt
from grammar.my_types import HandleNode, KeyNode
from grammar.pruning import prune_graph
from grammar.visualization import visualize_graph


def clulow():
    graph = {
        0: KeyNode(0, False, [1], [], [], [], []),
        1: HandleNode(0, None, False),
        2: KeyNode(1, False, [3], [], [], [], []),
        3: HandleNode(2, None, True)
    }

    visualize_graph(graph, "clulow")

    id_generator = count(max(graph.keys()) + 1)

    output_graph = deepcopy(graph)
    wrap(graph, output_graph, id_generator)
    graph = output_graph

    output_graph = deepcopy(graph)
    decrypt(graph, output_graph, id_generator)
    graph = output_graph

    output_graph = prune_graph(graph, {0})

    visualize_graph(output_graph, "clulow_expanded")


def dks_experiment_2():
    graph = {
        0: KeyNode(1, False, [1], [], [], [], []),
        1: HandleNode(0, None, False),
        2: KeyNode(2, False, [3], [], [], [], []),
        3: HandleNode(2, None, True),
        4: KeyNode(3, True, [], [], [], [], [])
    }

    visualize_graph(graph, "dks_experiment_2")

    id_generator = count(max(graph.keys()) + 1)

    output_graph = deepcopy(graph)
    encrypt(graph, output_graph, id_generator)
    graph = output_graph

    output_graph = deepcopy(graph)
    unwrap(graph, output_graph, id_generator)
    graph = output_graph

    output_graph = deepcopy(graph)
    wrap(graph, output_graph, id_generator)
    graph = output_graph

    output_graph = deepcopy(graph)
    intruder_decrypt(graph, output_graph, id_generator)
    graph = output_graph

    output_graph = prune_graph(graph, {0})

    visualize_graph(output_graph, "dks_experiment_2_expanded")


def dks_experiment_3():
    graph = {
        0: KeyNode(1, False, [1], [], [], [], []),
        1: HandleNode(0, None, False),
        2: KeyNode(2, False, [3], [], [], [], []),
        3: HandleNode(2, None, True)
    }

    visualize_graph(graph, "dks_experiment_3")

    id_generator = count(max(graph.keys()) + 1)

    output_graph = deepcopy(graph)
    wrap(graph, output_graph, id_generator)
    graph = output_graph

    output_graph = deepcopy(graph)
    unwrap(graph, output_graph, id_generator)
    graph = output_graph

    output_graph = deepcopy(graph)
    wrap(graph, output_graph, id_generator)
    graph = output_graph

    output_graph = deepcopy(graph)
    decrypt(graph, output_graph, id_generator)
    graph = output_graph

    output_graph = prune_graph(graph, {0})

    visualize_graph(output_graph, "dks_experiment_3_expanded")


if __name__ == "__main__":
    clulow()
    dks_experiment_2()
    dks_experiment_3()
