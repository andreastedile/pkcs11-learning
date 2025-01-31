import argparse

import pkcs11
from aalpy import RandomWalkEqOracle, MealyMachine, run_Lstar, save_automaton_to_file
from pkcs11 import Token, Session, SecretKey, KeyType, Attribute

from graph_rewriting import expand_knowledge_base
from models import compute_all_models
from my_types import KnowledgeBase, HandleNode
from pkcs11_sul import PKCS11_SUL
from pkcs11_sul_alphabet import extract_alphabet_from_model
from visualization import convert_knowledege_base_to_dot, convert_model_to_dot_compact


def clulow():
    parser = argparse.ArgumentParser(description="PKCS#11 automaton learning")

    parser.add_argument("so", help="Shared object")
    parser.add_argument("token_label", help="Token label")
    parser.add_argument("user_pin", help="User PIN")
    parser.add_argument("--n_iter", type=int, required=True, help="Number of graph expansion iterations (int)")
    parser.add_argument("--visualize_automaton", help="Visualize the PKCS #11 automaton in the browser after learning",
                        action="store_true")
    parser.add_argument("--hide_same_state_trans", help="Hide same state transitions",
                        action="store_true")

    args = parser.parse_args()

    so = args.so
    token_label = args.token_label
    user_pin = args.user_pin
    n_iter: int = args.n_iter
    visualize: bool = args.visualize_automaton
    hide_same_state_trans: bool = args.hide_same_state_trans

    initial_kb = KnowledgeBase()
    n0 = HandleNode(0, False)
    n1 = HandleNode(1, True)
    initial_kb.handles[0] = n0
    initial_kb.handles[1] = n1

    initial_nodes = {0, 1}

    dot = convert_knowledege_base_to_dot(initial_kb, initial_nodes)
    dot.write("clulow_initial.svg", format="svg")

    expanded_kb = expand_knowledge_base(initial_kb, n_iter)

    dot = convert_knowledege_base_to_dot(expanded_kb, initial_nodes)
    dot.write("clulow_expanded.svg", format="svg")

    target_node = [n for n, node in expanded_kb.keys.items() if node.value == 1]
    if len(target_node) == 0:
        print("found no attacks; exiting")
        return
    assert len(target_node) == 1

    print("compute all models")
    models = []
    generator = compute_all_models(expanded_kb, initial_nodes, target_node[0])
    for i, model in enumerate(generator):
        models.append(model)

        dot = convert_model_to_dot_compact(expanded_kb, initial_nodes, model)
        dot.write(f"clulow_model_{i}.svg", format="svg")

        print(f"found {i + 1} models so far")

    lib = pkcs11.lib(so)
    token: Token = lib.get_token(token_label=token_label)

    for i, model in enumerate(models):
        print(f"convert model {i} to alphabet")

        alphabet = extract_alphabet_from_model(model)
        if len(alphabet) == 0:
            print("alphabet is empty, cannot learn")
            return

        with token.open(user_pin=user_pin) as session:
            def initial_knowledge_factory(session: Session) -> tuple[dict[int, SecretKey], dict[int, bytes]]:
                n1 = session.generate_key(KeyType.DES3, label="1", template={
                    Attribute.SENSITIVE: True,
                    Attribute.EXTRACTABLE: True
                })
                n2 = session.generate_key(KeyType.DES3, label="2", template={
                    Attribute.WRAP: True,
                    Attribute.DECRYPT: True
                })
                return {1: n1, 2: n2}, {}

            sul = PKCS11_SUL(session, initial_knowledge_factory)

            eq_oracle = RandomWalkEqOracle(alphabet, sul, num_steps=100, reset_after_cex=True, reset_prob=0.09)

            print("start learning")
            learned_pkcs11: MealyMachine = run_Lstar(alphabet, sul, eq_oracle=eq_oracle, automaton_type="mealy",
                                                     cache_and_non_det_check=True, print_level=2)

            save_automaton_to_file(learned_pkcs11,
                                   path=f"clulow_automaton_{i}",
                                   file_type="pdf",
                                   display_same_state_trans=not hide_same_state_trans,
                                   visualize=visualize)


if __name__ == "__main__":
    clulow()
