from copy import deepcopy
from itertools import count

from grammar.graph import wrap, decrypt, encrypt, unwrap, intruder_decrypt
from grammar.my_types import HandleNode, KeyNode, Security
from grammar.pruning import prune_graph
from grammar.visualization import visualize_graph


def clulow():
    graph = {
        0: KeyNode(True, 0, False, Security.HIGH, [1], [], [], [], []),
        1: HandleNode(True, 0, False, None),
        2: KeyNode(True, 1, False, Security.LOW, [3], [], [], [], []),
        3: HandleNode(True, 2, True, None)
    }

    visualize_graph(graph, "clulow_initial")

    id_generator = count(max(graph.keys()) + 1)

    output_graph = deepcopy(graph)
    wrap(graph, output_graph, id_generator)
    graph = output_graph

    output_graph = deepcopy(graph)
    decrypt(graph, output_graph, id_generator)
    graph = output_graph

    visualize_graph(output_graph, "clulow_expanded")

    output_graph = prune_graph(graph)

    visualize_graph(output_graph, "clulow_pruned")


def dks_experiment_2():
    graph = {
        0: KeyNode(True, 1, False, Security.HIGH, [1], [], [], [], []),
        1: HandleNode(True, 0, False, None),
        2: KeyNode(True, 2, False, Security.LOW, [3], [], [], [], []),
        3: HandleNode(True, 2, True, None),
        4: KeyNode(True, 3, True, Security.LOW, [], [], [], [], [])
    }

    visualize_graph(graph, "dks_experiment_2_initial")

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

    visualize_graph(output_graph, "dks_experiment_2_expanded")

    output_graph = prune_graph(graph)

    visualize_graph(output_graph, "dks_experiment_2_pruned")


def dks_experiment_3():
    graph = {
        0: KeyNode(True, 1, False, Security.HIGH, [1], [], [], [], []),
        1: HandleNode(True, 0, False, None),
        2: KeyNode(True, 2, False, Security.LOW, [3], [], [], [], []),
        3: HandleNode(True, 2, True, None)
    }

    visualize_graph(graph, "dks_experiment_3_initial")

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

    visualize_graph(output_graph, "dks_experiment_3_expanded")

    output_graph = prune_graph(graph)

    visualize_graph(output_graph, "dks_experiment_3_pruned")


def fls_re_import_attack_2():
    graph = {
        0: KeyNode(True, 1, False, Security.HIGH, [1], [], [], [], []),
        1: HandleNode(True, 0, False, None),
        2: KeyNode(True, 2, False, Security.LOW, [3], [], [], [], []),
        3: HandleNode(True, 2, True, None),
        4: KeyNode(True, (3, 2), True, Security.LOW, [], [], [], [], [])
    }

    visualize_graph(graph, "fls_re_import_attack_2_initial")

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

    visualize_graph(output_graph, "fls_re_import_attack_2_expanded")

    output_graph = prune_graph(graph)

    visualize_graph(output_graph, "fls_re_import_attack_2_pruned")


if __name__ == "__main__":
    clulow()
    dks_experiment_2()
    dks_experiment_3()
    fls_re_import_attack_2()
