import argparse
import typing
from pathlib import Path

from PyKCS11 import PyKCS11Lib, Session
from aalpy import RandomWalkEqOracle, run_Lstar, save_automaton_to_file, MealyMachine
from aalpy.learning_algs import run_Lsharp

import dks_2
import dks_6
import fls_2
import wrap_and_decrypt
from configuration import Configuration
from conversion_to_pykcs11 import convert_configuration_to_pykcs11_command_list
from pykcs11_knowledge_set import PyKCS11KnowledgeSet
from pykcs11_sul import PyKCS11SUL
from visualization import remove_not_applicable_transitions


def learn_attack(session: Session,
                 path: Path,
                 knowledge_set: PyKCS11KnowledgeSet,
                 reset_knowledge_set: typing.Callable[[Session, PyKCS11KnowledgeSet], None]):
    path = Path(path)
    for file in path.rglob("*.toml"):
        assert isinstance(file, Path)

        configuration = Configuration.load_from_file(file)
        alphabet = convert_configuration_to_pykcs11_command_list(configuration)

        # print("run_Lstar")
        # sul = PyKCS11SUL(session, knowledge_set, reset_knowledge_set)
        # eq_oracle = RandomWalkEqOracle(alphabet, sul)
        # lstar_automaton = run_Lstar(alphabet, sul, eq_oracle, "mealy")
        # assert isinstance(lstar_automaton, MealyMachine)
        # 
        # save_automaton_to_file(lstar_automaton, file.with_name(file.stem + "_Lstar"))
        # lstar_automaton_without_unapplicable_transitions = remove_not_applicable_transitions(lstar_automaton)
        # save_automaton_to_file(lstar_automaton_without_unapplicable_transitions,
        #                        file.with_name(file.stem + "_Lstar"), "svg")

        # reset_knowledge_set(session, knowledge_set)

        print("run_Lsharp")
        sul = PyKCS11SUL(session, knowledge_set, reset_knowledge_set)
        eq_oracle = RandomWalkEqOracle(alphabet, sul)
        lsharp_automaton = run_Lsharp(alphabet, sul, eq_oracle, "mealy")
        assert isinstance(lsharp_automaton, MealyMachine)

        save_automaton_to_file(lsharp_automaton, file.with_name(file.stem + "_Lsharp"))
        lsharp_automaton_without_unapplicable_transitions = remove_not_applicable_transitions(lsharp_automaton)
        save_automaton_to_file(lsharp_automaton_without_unapplicable_transitions,
                               file.with_name(file.stem + "_Lsharp"), "svg")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PKCS#11 automaton learning")

    parser.add_argument("so", help="Shared object")
    parser.add_argument("token_label", help="Token label")
    parser.add_argument("user_pin", help="User PIN")

    args = parser.parse_args()

    so = args.so
    token_label = args.token_label
    user_pin = args.user_pin

    pkcs11 = PyKCS11Lib()
    lib = pkcs11.load(so)
    slot = 3

    session = lib.openSession(slot)

    learn_attack(session,
                 Path("known_attacks", "wrap_and_decrypt"),
                 wrap_and_decrypt.create_knowledge_set(session),
                 wrap_and_decrypt.reset_knowledge_set)

    learn_attack(session,
                 Path("known_attacks", "dks_2"),
                 dks_2.dks_experiment_2_initial_knowledge_factory)

    # learn_attack(session,
    #              Path("known_attacks", "dks_6"),
    #              dks_6.dks_experiment_6_initial_knowledge_factory)

    # learn_attack(session,
    #              Path("known_attacks", "fls_2"),
    #              fls_2.fls_2_initial_knowledge_factory)

    session.closeSession()
