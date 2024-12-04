from copy import deepcopy
from itertools import count

from grammar.graph import wrap, decrypt, encrypt, unwrap, intruder_decrypt
from grammar.my_types import HandleNode, KeyNode
from grammar.pruning import prune_graph
from grammar.visualization import visualize_graph


def clulow():
    graph = {
        0: KeyNode(True, 0, False, [1], [], [], [], []),
        1: HandleNode(True, 0, False, None),
        2: KeyNode(True, 1, False, [3], [], [], [], []),
        3: HandleNode(True, 2, True, None)
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
        0: KeyNode(True, 1, False, [1], [], [], [], []),
        1: HandleNode(True, 0, False, None),
        2: KeyNode(True, 2, False, [3], [], [], [], []),
        3: HandleNode(True, 2, True, None),
        4: KeyNode(True, 3, True, [], [], [], [], [])
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
        0: KeyNode(True, 1, False, [1], [], [], [], []),
        1: HandleNode(True, 0, False, None),
        2: KeyNode(True, 2, False, [3], [], [], [], []),
        3: HandleNode(True, 2, True, None)
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


def fls_re_import_attack_2():
    graph = {
        0: KeyNode(True, 1, False, [1], [], [], [], []),
        1: HandleNode(True, 0, False, None),
        2: KeyNode(True, 2, False, [3], [], [], [], []),
        3: HandleNode(True, 2, True, None),
        4: KeyNode(True, (3, 2), True, [], [], [], [], [])
    }

    visualize_graph(graph, "fls_re_import_attack_2")

    id_generator = count(max(graph.keys()) + 1)

    output_graph = deepcopy(graph)
    unwrap(graph, output_graph, id_generator)
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

    visualize_graph(output_graph, "fls_re_import_attack_2_expanded")


if __name__ == "__main__":
    clulow()
    dks_experiment_2()
    dks_experiment_3()
    fls_re_import_attack_2()
