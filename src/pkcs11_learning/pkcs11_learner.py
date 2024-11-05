import argparse
import logging
import timeit

from aalpy.automata import MealyMachine
from aalpy import RandomWalkEqOracle, run_Lstar, save_automaton_to_file, visualize_automaton
import pkcs11
from pkcs11 import Token

from pkcs11_learning.alphabet import generate_alphabet
from pkcs11_learning.pkcs11_sul import PKCS11_SUL
from pkcs11_learning.graph import HandleNode, KeyNode

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="PKCS#11 automaton learning")

    parser.add_argument("so", help="Shared object")
    parser.add_argument("token_label", help="Token label")
    parser.add_argument("user_pin", help="User PIN")

    args = parser.parse_args()

    so = args.so
    token_label = args.token_label
    user_pin = args.user_pin

    lib = pkcs11.lib(so)
    token: Token = lib.get_token(token_label=token_label)

    with token.open(user_pin=user_pin) as session:
        nodes = {
            0: KeyNode(0, known=False),
            1: HandleNode(0),
            2: KeyNode(1, known=False),
            3: HandleNode(2),
        }

        commands = generate_alphabet(nodes, 2)

        sul = PKCS11_SUL(session, nodes)
        eq_oracle = RandomWalkEqOracle(commands, sul, num_steps=100, reset_after_cex=True, reset_prob=0.09)

        logger.info("start learning")
        start = timeit.default_timer()
        learned_pkcs: MealyMachine = run_Lstar(commands, sul, eq_oracle=eq_oracle, automaton_type="mealy",
                                               cache_and_non_det_check=True, print_level=2)
        stop = timeit.default_timer()

        execution_time_s = stop - start
        print(f"Learning took {execution_time_s} seconds")

        logger.info("save to file")
        save_automaton_to_file(learned_pkcs, "learnedpkcs.dot")

        logger.info("save to file")
        visualize_automaton(learned_pkcs, display_same_state_trans=True)


if __name__ == "__main__":
    main()
