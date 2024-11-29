import argparse

from aalpy.automata import MealyMachine
from aalpy import RandomWalkEqOracle, run_Lstar, save_automaton_to_file, \
    visualize_automaton as aalpy_visualize_automaton
import pkcs11
from pkcs11 import Token, Session, SecretKey, KeyType, Attribute

from grammar.my_types import HandleNode, KeyNode
from grammar.visualization import visualize_graph
from pkcs11_sul import PKCS11_SUL
from pkcs11_sul_alphabet import compute_alphabet


def main():
    parser = argparse.ArgumentParser(description="PKCS#11 automaton learning")

    parser.add_argument("so", help="Shared object")
    parser.add_argument("token_label", help="Token label")
    parser.add_argument("user_pin", help="User PIN")
    parser.add_argument("--debug", help="Save the graph generation steps to PNG for debugging", action="store_true")
    parser.add_argument("--visualize_automaton", help="Visualize the PKCS #11 automaton after learning",
                        action="store_true")
    parser.add_argument("--display_same_state_trans", help="Display same state transitions",
                        action="store_true")

    args = parser.parse_args()

    so = args.so
    token_label = args.token_label
    user_pin = args.user_pin
    debug: bool = args.debug
    visualize_automaton: bool = args.visualize_automaton
    display_same_state_trans: bool = args.display_same_state_trans

    clulow_graph = {
        0: KeyNode(0, False, [1], [], [], []),
        1: HandleNode(0, None, False),
        2: KeyNode(1, False, [3], [], [], []),
        3: HandleNode(2, None, True),
    }

    if debug:
        visualize_graph(clulow_graph, "clulow_initial_graph")

    blocked_node_ids = set(clulow_graph.keys())

    alphabet = compute_alphabet(clulow_graph, 2, True, blocked_node_ids, debug=debug)

    if len(alphabet) == 0:
        print("alphabet is empty, cannot learn")
        return
    else:
        print(f"alphabet has {len(alphabet)} inputs:")
        for input in alphabet:
            print(input)

    lib = pkcs11.lib(so)
    token: Token = lib.get_token(token_label=token_label)

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

        print("\nstart learning")
        learned_pkcs11: MealyMachine = run_Lstar(alphabet, sul, eq_oracle=eq_oracle, automaton_type="mealy",
                                                 cache_and_non_det_check=True, print_level=2)

        save_automaton_to_file(learned_pkcs11)

        if visualize_automaton:
            aalpy_visualize_automaton(learned_pkcs11, display_same_state_trans=display_same_state_trans)


if __name__ == "__main__":
    main()
