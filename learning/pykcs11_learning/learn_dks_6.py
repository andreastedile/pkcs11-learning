import argparse
from pathlib import Path

from PyKCS11 import PyKCS11Lib, Session
from aalpy import RandomWalkEqOracle, run_Lstar, MealyMachine, save_automaton_to_file
from dotenv import dotenv_values

from knowledge_sets.dks_6 import create_initial_knowledge_set, reset_knowledge_set
from pkcs11_learning.core import *
from pkcs11_learning.pykcs11_adapt import *


def learn_dks_6_aes_ecb_rsa_pkcs(lib: PyKCS11Lib, so: str, slot: int, pin: str, input_file: Path, output_path: Path):
    configuration = Configuration.load_from_file(input_file)
    alphabet = convert_configuration_to_pykcs11_commands(configuration, AESECBParams(), RSAPKCSParams())

    def _learn_dks_6_aes_ecb_rsa_pkcs(session: Session) -> MealyMachine:
        knowledge_set = create_initial_knowledge_set(session)
        sul = PyKCS11SUL(session, knowledge_set, reset_knowledge_set)
        eq_oracle = RandomWalkEqOracle(alphabet, sul)
        return run_Lstar(alphabet, sul, eq_oracle, "mealy")

    automaton = run(lib, so, slot, pin, _learn_dks_6_aes_ecb_rsa_pkcs)

    name = input_file.stem + "_AES-ECB"
    save_automaton_to_file(automaton, output_path / name)
    automaton_without_unapplicable_transitions = remove_not_applicable_transitions(automaton)
    save_automaton_to_file(automaton_without_unapplicable_transitions, output_path / name, "svg")


def learn_dks_6_aes_gcm_rsa_pkcs_oaep(lib: PyKCS11Lib, so: str, slot: int, pin: str, input_file: Path,
                                      output_path: Path):
    configuration = Configuration.load_from_file(input_file)
    alphabet = convert_configuration_to_pykcs11_commands(configuration, AESGCMParams.default(),
                                                         RSAPKCSOAEPParams.default())

    def _learn_dks_6_aes_ecb(session: Session) -> MealyMachine:
        knowledge_set = create_initial_knowledge_set(session)
        sul = PyKCS11SUL(session, knowledge_set, reset_knowledge_set)
        eq_oracle = RandomWalkEqOracle(alphabet, sul)
        return run_Lstar(alphabet, sul, eq_oracle, "mealy")

    automaton = run(lib, so, slot, pin, _learn_dks_6_aes_ecb)

    name = input_file.stem + "_AES-GCM"
    save_automaton_to_file(automaton, output_path / name)
    automaton_without_unapplicable_transitions = remove_not_applicable_transitions(automaton)
    save_automaton_to_file(automaton_without_unapplicable_transitions, output_path / name, "svg")


def learn_opencryptoki(input_path: Path):
    output_path = input_path / "opencryptoki"
    output_path.mkdir(exist_ok=True)

    values = dotenv_values("opencryptoki.env")
    so, slot, pin = values["SO"], int(values["SLOT"]), values["PIN"]

    lib = PyKCS11Lib()

    for input_file in input_path.glob("*.toml"):
        learn_dks_6_aes_ecb_rsa_pkcs(lib, so, slot, pin, input_file, output_path)
        learn_dks_6_aes_gcm_rsa_pkcs_oaep(lib, so, slot, pin, input_file, output_path)


def main():
    parser = argparse.ArgumentParser(description="Learn DKS 6 attack")
    parser.add_argument("--opencryptoki", action="store_true", default=False)
    args = parser.parse_args()

    input_path = Path("examples", "dks_6")

    if args.opencryptoki:
        learn_opencryptoki(input_path)


if __name__ == "__main__":
    main()
