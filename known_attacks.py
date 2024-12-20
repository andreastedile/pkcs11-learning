import argparse
from copy import deepcopy
from itertools import count

import pkcs11
from aalpy import RandomWalkEqOracle, MealyMachine, run_Lstar, visualize_automaton
from pkcs11 import Token, Attribute, KeyType, Session, SecretKey

from grammar.graph import wrap, decrypt, encrypt, unwrap, intruder_decrypt
from grammar.my_types import HandleNode, KeyNode, Security
from grammar.pruning import prune_graph
from grammar.visualization import visualize_graph
from model_checking.enumeration import enumerate_models, print_model
from model_checking.visualization import visualize_model
from pkcs11_sul import PKCS11_SUL
from pkcs11_sul_alphabet import convert_model_to_alphabet


def clulow(so,
           token_label,
           user_pin,
           display_same_state_trans: bool):
    print("clulow")

    graph = {
        0: KeyNode(True, 0, False, Security.HIGH, [1], [], [], [], [], [], [], [], []),
        1: HandleNode(True, 0, False, None, [], [], [], []),
        2: KeyNode(True, 1, False, Security.LOW, [3], [], [], [], [], [], [], [], []),
        3: HandleNode(True, 2, True, None, [], [], [], [])
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

    models = enumerate_models(output_graph, 0)

    print(f"found {len(models)} models:")
    for i, model in enumerate(models):
        print(f"model {i}:")
        print_model(model)

    for i, model in enumerate(models):
        visualize_model(output_graph, model, f"clulow_model_{i}")

    for i, model in enumerate(models):
        print(f"convert model {i} to alphabet")

        alphabet = convert_model_to_alphabet(graph, model)

        lib = pkcs11.lib(so)
        token: Token = lib.get_token(token_label)
        with token.open(user_pin=user_pin) as session:
            def clulow_initial_knowledge_factory(session: Session) -> dict[int, SecretKey | bytes]:
                return {
                    1: session.generate_key(KeyType.DES3, label="1", template={
                        Attribute.SENSITIVE: True,
                        Attribute.EXTRACTABLE: True
                    }),
                    3: session.generate_key(KeyType.DES3, label="3", template={
                        Attribute.WRAP: True,
                        Attribute.DECRYPT: True
                    }),
                }

            sul = PKCS11_SUL(session, clulow_initial_knowledge_factory)

            eq_oracle = RandomWalkEqOracle(alphabet, sul, num_steps=100, reset_after_cex=True, reset_prob=0.09)

            print(f"start learning model {i}")
            learned_pkcs11: MealyMachine = run_Lstar(alphabet, sul, eq_oracle=eq_oracle, automaton_type="mealy",
                                                     cache_and_non_det_check=True, print_level=2)

            visualize_automaton(learned_pkcs11, path=f"clulow_learned_{i}",
                                display_same_state_trans=display_same_state_trans)


def dks_experiment_2(so,
                     token_label,
                     user_pin,
                     display_same_state_trans: bool):
    print("dks_experiment_2")

    graph = {
        0: KeyNode(True, 1, False, Security.HIGH, [1], [], [], [], [], [], [], [], []),
        1: HandleNode(True, 0, False, None, [], [], [], []),
        2: KeyNode(True, 2, False, Security.LOW, [3], [], [], [], [], [], [], [], []),
        3: HandleNode(True, 2, True, None, [], [], [], []),
        4: KeyNode(True, 3, True, Security.LOW, [], [], [], [], [], [], [], [], [])
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

    models = enumerate_models(output_graph, 0)

    print(f"found {len(models)} models:")
    for i, model in enumerate(models):
        print(f"model {i}:")
        print_model(model)

    for i, model in enumerate(models):
        visualize_model(output_graph, model, f"dks_experiment_2_model_{i}")

    for i, model in enumerate(models):
        print(f"convert model {i} to alphabet")

        alphabet = convert_model_to_alphabet(graph, model)

        lib = pkcs11.lib(so)
        token: Token = lib.get_token(token_label=token_label)
        with token.open(user_pin=user_pin) as session:
            def dks_experiment_2_factory(session: Session) -> dict[int, SecretKey | bytes]:
                return {
                    1: session.generate_key(KeyType.DES3, label="1", template={
                        Attribute.SENSITIVE: True,
                        Attribute.EXTRACTABLE: True
                    }),
                    3: session.generate_key(KeyType.DES3, label="3", template={
                        Attribute.UNWRAP: True,
                        Attribute.ENCRYPT: True
                    }),
                    4: b'4' * 8 + b'G' * 8 + b'T' * 8
                }

            sul = PKCS11_SUL(session, dks_experiment_2_factory)

            eq_oracle = RandomWalkEqOracle(alphabet, sul, num_steps=100, reset_after_cex=True, reset_prob=0.09)

            print(f"start learning model {i}")
            learned_pkcs11: MealyMachine = run_Lstar(alphabet, sul, eq_oracle=eq_oracle, automaton_type="mealy",
                                                     cache_and_non_det_check=True, print_level=2)

            visualize_automaton(learned_pkcs11, path=f"dks_experiment_2_{i}",
                                display_same_state_trans=display_same_state_trans)


def dks_experiment_3(so,
                     token_label,
                     user_pin,
                     display_same_state_trans: bool):
    print("dks_experiment_3")

    graph = {
        0: KeyNode(True, 1, False, Security.HIGH, [1], [], [], [], [], [], [], [], []),
        1: HandleNode(True, 0, False, None, [], [], [], []),
        2: KeyNode(True, 2, False, Security.LOW, [3], [], [], [], [], [], [], [], []),
        3: HandleNode(True, 2, True, None, [], [], [], [])
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

    models = enumerate_models(output_graph, 0)

    print(f"found {len(models)} models:")
    for i, model in enumerate(models):
        print(f"model {i}:")
        print_model(model)

    for i, model in enumerate(models):
        visualize_model(output_graph, model, f"dks_experiment_3_model_{i}")

    for i, model in enumerate(models):
        print(f"convert model {i} to alphabet")

        alphabet = convert_model_to_alphabet(graph, model)

        lib = pkcs11.lib(so)
        token: Token = lib.get_token(token_label=token_label)
        with token.open(user_pin=user_pin) as session:
            def dks_experiment_3_factory(session: Session) -> dict[int, SecretKey | bytes]:
                return {
                    1: session.generate_key(KeyType.DES3, label="1", template={
                        Attribute.SENSITIVE: True,
                        Attribute.EXTRACTABLE: True
                    }),
                    3: session.generate_key(KeyType.DES3, label="3", template={
                        Attribute.EXTRACTABLE: True
                    })
                }

            sul = PKCS11_SUL(session, dks_experiment_3_factory)

            eq_oracle = RandomWalkEqOracle(alphabet, sul, num_steps=100, reset_after_cex=True, reset_prob=0.09)

            print(f"start learning model {i}")
            learned_pkcs11: MealyMachine = run_Lstar(alphabet, sul, eq_oracle=eq_oracle, automaton_type="mealy",
                                                     cache_and_non_det_check=True, print_level=2)

            visualize_automaton(learned_pkcs11, path=f"dks_experiment_3_{i}",
                                display_same_state_trans=display_same_state_trans)


def fls_re_import_attack_2():
    print("fls_re_import_attack_2")

    graph = {
        0: KeyNode(True, 1, False, Security.HIGH, [1], [], [], [], [], [], [], [], []),
        1: HandleNode(True, 0, False, None, [], [], [], []),
        2: KeyNode(True, 2, False, Security.LOW, [3], [], [], [], [], [], [], [], []),
        3: HandleNode(True, 2, True, None, [], [], [], []),
        4: KeyNode(True, (3, 2), True, Security.LOW, [], [], [], [], [], [], [], [], [])
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

    models = enumerate_models(output_graph, 0)

    print(f"found {len(models)} models:")
    for i, model in enumerate(models):
        print(f"model {i}:")
        print_model(model)

    for i, model in enumerate(models):
        visualize_model(output_graph, model, f"fls_re_import_attack_2_model_{i}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PKCS#11 automaton learning")

    parser.add_argument("so", help="Shared object")
    parser.add_argument("token_label", help="Token label")
    parser.add_argument("user_pin", help="User PIN")
    parser.add_argument("--display_same_state_trans", help="Display same state transitions",
                        action="store_true")

    args = parser.parse_args()

    so = args.so
    token_label = args.token_label
    user_pin = args.user_pin
    display_same_state_trans: bool = args.display_same_state_trans

    clulow(so, token_label, user_pin, display_same_state_trans)
    dks_experiment_2(so, token_label, user_pin, display_same_state_trans)
    dks_experiment_3(so, token_label, user_pin, display_same_state_trans)
    fls_re_import_attack_2()
