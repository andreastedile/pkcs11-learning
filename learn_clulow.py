import argparse

from aalpy.automata import MealyMachine
from aalpy import RandomWalkEqOracle, run_Lstar, save_automaton_to_file, \
    visualize_automaton as aalpy_visualize_automaton
import pkcs11
from pkcs11 import Token, Session, SecretKey, KeyType, Attribute

from grammar.expansion import expand_graph
from grammar.my_types import HandleNode, KeyNode, Security
from grammar.pruning import prune_graph
from grammar.visualization import visualize_graph
from pkcs11_sul import PKCS11_SUL
from pkcs11_sul_alphabet import extract_alphabet


def main():
    parser = argparse.ArgumentParser(description="PKCS#11 automaton learning")

    parser.add_argument("so", help="Shared object")
    parser.add_argument("token_label", help="Token label")
    parser.add_argument("user_pin", help="User PIN")
    parser.add_argument("--n_iter", type=int, required=True, help="Number of graph expansion iterations (int)")
    parser.add_argument("--no_pruning", help="Disable graph pruning", action="store_true")
    parser.add_argument("--debug", help="Save the graph generation steps to PNG for debugging", action="store_true")
    parser.add_argument("--visualize_automaton", help="Visualize the PKCS #11 automaton after learning",
                        action="store_true")
    parser.add_argument("--display_same_state_trans", help="Display same state transitions",
                        action="store_true")

    args = parser.parse_args()

    so = args.so
    token_label = args.token_label
    user_pin = args.user_pin
    n_iter: int = args.n_iter
    no_pruning: bool = args.no_pruning
    debug: bool = args.debug
    visualize_automaton: bool = args.visualize_automaton
    display_same_state_trans: bool = args.display_same_state_trans

    clulow_graph = {
        0: KeyNode(True, 0, False, Security.HIGH, [1], [], [], [], [], [], [], [], []),
        1: HandleNode(True, 0, False, None, [], [], [], []),
        2: KeyNode(True, 1, False, Security.LOW, [3], [], [], [], [], [], [], [], []),
        3: HandleNode(True, 2, True, None, [], [], [], []),
    }

    if debug:
        visualize_graph(clulow_graph, "clulow_initial_graph")

    print("expand graph")
    clulow_graph = expand_graph(clulow_graph, n_iter, debug=debug)
    print("number of handle nodes:", len([attr for attr in clulow_graph.values() if isinstance(attr, HandleNode)]))
    print("number of key nodes:   ", len([attr for attr in clulow_graph.values() if isinstance(attr, KeyNode)]))

    if not no_pruning:
        print("pruning")
        clulow_graph = prune_graph(clulow_graph, debug)
        print("number of handle nodes:", len([attr for attr in clulow_graph.values() if isinstance(attr, HandleNode)]))
        print("number of key nodes:   ", len([attr for attr in clulow_graph.values() if isinstance(attr, KeyNode)]))

    alphabet = extract_alphabet(clulow_graph)
    if len(alphabet) == 0:
        print("alphabet is empty, cannot learn")
        return

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
