import typing
from typing import Generator

import networkx as nx
from networkx.algorithms.isomorphism.isomorph import is_isomorphic
from networkx.classes import MultiDiGraph

from my_types import PKCS11_FunctionArguments, KnowledgeBase, \
    PKCS11_WrapArguments, \
    PKCS11_UnwrapArguments, \
    PKCS11_EncryptArguments, \
    PKCS11_DecryptArguments, \
    IntruderDecryptArguments


def is_circular_dependency(model: MultiDiGraph, n: int, arguments: PKCS11_FunctionArguments) -> bool:
    if arguments[0] in model and nx.has_path(model, n, arguments[0]):
        return True
    if arguments[1] in model and nx.has_path(model, n, arguments[1]):
        return True
    return False


def add_antecedents_to_new_model(kb: KnowledgeBase, model: MultiDiGraph, n: int,
                                 arguments: PKCS11_FunctionArguments) -> MultiDiGraph:
    new_model = model.copy()

    match arguments:
        case PKCS11_WrapArguments(handle_of_wrapping_key, handle_of_key_to_be_wrapped):
            new_model.add_node(handle_of_wrapping_key,
                               nodetype="handle",
                               value=kb.handles[handle_of_wrapping_key].value)
            new_model.add_node(handle_of_key_to_be_wrapped,
                               nodetype="handle",
                               value=kb.handles[handle_of_key_to_be_wrapped].value)
            new_model.add_edge(handle_of_wrapping_key, n)
            new_model.add_edge(handle_of_key_to_be_wrapped, n)
        case PKCS11_UnwrapArguments(handle_of_unwrapping_key, key_to_be_unwrapped):
            new_model.add_node(handle_of_unwrapping_key,
                               nodetype="handle",
                               value=kb.handles[handle_of_unwrapping_key].value)
            new_model.add_node(key_to_be_unwrapped,
                               nodetype="key",
                               value=kb.keys[key_to_be_unwrapped].value)
            new_model.add_edge(handle_of_unwrapping_key, n)
            new_model.add_edge(key_to_be_unwrapped, n)
        case PKCS11_EncryptArguments(handle_of_encryption_key, key_to_be_encrypted):
            new_model.add_node(handle_of_encryption_key,
                               nodetype="handle",
                               value=kb.handles[handle_of_encryption_key].value)
            new_model.add_node(key_to_be_encrypted,
                               nodetype="key",
                               value=kb.keys[key_to_be_encrypted].value)
            new_model.add_edge(handle_of_encryption_key, n)
            new_model.add_edge(key_to_be_encrypted, n)
        case PKCS11_DecryptArguments(handle_of_decryption_key, key_to_be_decrypted):
            new_model.add_node(handle_of_decryption_key,
                               nodetype="handle",
                               value=kb.handles[handle_of_decryption_key].value)
            new_model.add_node(key_to_be_decrypted,
                               nodetype="key",
                               value=kb.keys[key_to_be_decrypted].value)
            new_model.add_edge(handle_of_decryption_key, n)
            new_model.add_edge(key_to_be_decrypted, n)
        case IntruderDecryptArguments(decryption_key, key_to_be_decrypted):
            new_model.add_node(decryption_key,
                               nodetype="key",
                               value=kb.keys[decryption_key].value)
            new_model.add_node(key_to_be_decrypted,
                               nodetype="key",
                               value=kb.keys[key_to_be_decrypted].value)
            new_model.add_edge(decryption_key, n)
            new_model.add_edge(key_to_be_decrypted, n)
        case _:
            typing.assert_never(arguments)

    new_model.nodes[n]["arguments"] = arguments

    return new_model


def compute_all_models_rec(kb: KnowledgeBase,
                           initial_nodes: set[int],
                           candidate: MultiDiGraph,
                           cache: list[MultiDiGraph]) -> Generator[MultiDiGraph, None, None]:
    """
    :param kb: Attacker knowledge.
    :param initial_nodes: Nodes in the initial attacker knowledge which need not be derived through implications.
    :param candidate: Candidate model being computed.
    :param cache: Cache of models computed so far. 
    """
    nodes_without_antecedents = set(n for n in candidate.nodes if candidate.in_degree(n) == 0)

    # Frontier of nodes.
    # Better to use a set than a list: the arguments to some node can be the same; for example, wrap(x,x)=y.
    # By using a set, when processing y and recursing, x will not appear twice.
    non_initial_nodes_without_antecedents = set(n for n in nodes_without_antecedents if n not in initial_nodes)

    if len(non_initial_nodes_without_antecedents) == 0:  # base case: all nodes without antecedents are initial
        # if we do not already have this model, add them to the solutions
        if not any(is_isomorphic(candidate, model) for model in cache):
            cache.append(candidate)
            yield candidate
    else:  # recursive cases: compute a solution for all implications which do not form circular dependencies  
        for n in non_initial_nodes_without_antecedents:
            for arguments in kb.wrap_arguments_list[n]:
                if not is_circular_dependency(candidate, n, arguments):
                    new_candidate_model = add_antecedents_to_new_model(kb, candidate, n, arguments)
                    yield from compute_all_models_rec(kb, initial_nodes, new_candidate_model, cache)

            arguments = kb.unwrap_arguments.get(n)
            if arguments is not None:
                if not is_circular_dependency(candidate, n, arguments):
                    new_candidate_model = add_antecedents_to_new_model(kb, candidate, n, arguments)
                    yield from compute_all_models_rec(kb, initial_nodes, new_candidate_model, cache)

            for arguments in kb.encrypt_arguments_list[n]:
                if not is_circular_dependency(candidate, n, arguments):
                    new_candidate_model = add_antecedents_to_new_model(kb, candidate, n, arguments)
                    yield from compute_all_models_rec(kb, initial_nodes, new_candidate_model, cache)

            for arguments in kb.decrypt_arguments_list[n]:
                if not is_circular_dependency(candidate, n, arguments):
                    new_candidate_model = add_antecedents_to_new_model(kb, candidate, n, arguments)
                    yield from compute_all_models_rec(kb, initial_nodes, new_candidate_model, cache)

            arguments = kb.intruder_decrypt_arguments.get(n)
            if arguments is not None:
                if not is_circular_dependency(candidate, n, arguments):
                    new_candidate_model = add_antecedents_to_new_model(kb, candidate, n, arguments)
                    yield from compute_all_models_rec(kb, initial_nodes, new_candidate_model, cache)


def compute_all_models(kb: KnowledgeBase, initial_nodes: set[int], target_node: int) \
        -> Generator[MultiDiGraph, None, None]:
    """
    :param kb: Attacker knowledge.
    :param initial_nodes: Nodes in the initial attacker knowledge which need not be derived through implications.
    :param target_node:
    """
    candidate_model = MultiDiGraph()

    if target_node in kb.handles:
        candidate_model.add_node(target_node, nodetype="handle", value=kb.handles[target_node].value)
    else:
        # sanity check
        assert target_node in kb.keys
        candidate_model.add_node(target_node, nodetype="key", value=kb.keys[target_node].value)

    models = []
    yield from compute_all_models_rec(kb, initial_nodes, candidate_model, models)
