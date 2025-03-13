import argparse
import typing
from os import listdir, path

import pkcs11
from Crypto.Cipher import DES3
from aalpy import RandomWalkEqOracle, run_Lstar, save_automaton_to_file, Automaton
from pkcs11 import Session, KeyType, Attribute, Token

from conversion_to_python_pkcs11 import convert_configuration_to_python_pkcs11_command_list
from configuration import Configuration
from python_pkcs11_commands import PythonPKCS11Command
from python_pkcs11_knowledge_set import PythonPKCS11KnowledgeSet
from python_pkcs11_sul import PythonPKCS11SUL
from visualization import remove_not_applicable_transitions


def wrap_and_decrypt_initial_knowledge_factory(session: Session) -> PythonPKCS11KnowledgeSet:
    n0 = session.generate_key(KeyType.DES3, label="0", template={
        Attribute.SENSITIVE: True,
        Attribute.EXTRACTABLE: True
    })
    n1 = session.generate_key(KeyType.DES3, label="1", template={
        Attribute.WRAP: True,
        Attribute.DECRYPT: True
    })

    ks = PythonPKCS11KnowledgeSet()
    ks.handle_of_secret_key_dict[0] = n0
    ks.handle_of_secret_key_dict[1] = n1

    return ks


def fls_2_initial_knowledge_factory(session: Session) -> PythonPKCS11KnowledgeSet:
    n0 = session.generate_key(KeyType.DES3, label="0", template={
        Attribute.SENSITIVE: True,
        Attribute.EXTRACTABLE: True
    })
    n1 = session.generate_key(KeyType.DES3, label="1", template={
        Attribute.SENSITIVE: False,
        Attribute.EXTRACTABLE: True
    })

    k0 = n1[Attribute.VALUE]
    k1 = b'4' * 8 + b'G' * 8 + b'T' * 8
    cipher = DES3.new(k0, DES3.MODE_ECB)
    k2 = cipher.encrypt(k1)

    ks = PythonPKCS11KnowledgeSet()
    ks.handle_of_secret_key_dict[0] = n0
    ks.handle_of_secret_key_dict[1] = n1
    ks.senc_dict[2] = k2

    return ks


def dks_experiment_2_initial_knowledge_factory(session: Session) -> PythonPKCS11KnowledgeSet:
    n0 = session.generate_key(KeyType.DES3, label="0", template={
        Attribute.SENSITIVE: True,
        Attribute.EXTRACTABLE: True
    })
    n1 = session.generate_key(KeyType.DES3, label="1", template={
        Attribute.EXTRACTABLE: True
    })
    n2 = b'4' * 8 + b'G' * 8 + b'T' * 8

    ks = PythonPKCS11KnowledgeSet()
    ks.handle_of_secret_key_dict[0] = n0
    ks.handle_of_secret_key_dict[1] = n1
    ks.secret_key_dict[2] = n2

    return ks


def dks_experiment_3_initial_knowledge_factory(session: Session) -> PythonPKCS11KnowledgeSet:
    n0 = session.generate_key(KeyType.DES3, label="0", template={
        Attribute.SENSITIVE: True,
        Attribute.EXTRACTABLE: True
    })
    n1 = session.generate_key(KeyType.DES3, label="1", template={
        Attribute.EXTRACTABLE: True
    })

    ks = PythonPKCS11KnowledgeSet()
    ks.handle_of_secret_key_dict[0] = n0
    ks.handle_of_secret_key_dict[1] = n1

    return ks


def run_learning(session: Session,
                 initial_knowledge_factory: typing.Callable[[Session], PythonPKCS11KnowledgeSet],
                 alphabet: list[PythonPKCS11Command]) -> Automaton:
    sul = PythonPKCS11SUL(session, initial_knowledge_factory)

    eq_oracle = RandomWalkEqOracle(alphabet, sul, num_steps=100, reset_after_cex=True, reset_prob=0.09)

    print("start learning")
    # MealyMachine
    learned_pkcs11 = run_Lstar(alphabet,
                               sul,
                               eq_oracle,
                               "mealy",
                               cache_and_non_det_check=True,
                               print_level=2)
    assert isinstance(learned_pkcs11, Automaton)

    learned_pkcs11 = remove_not_applicable_transitions(learned_pkcs11)

    return learned_pkcs11


if __name__ == "__main__":
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

    session = token.open(user_pin=user_pin)

    for filename in listdir(path.join("known_attacks", "wrap_and_decrypt")):
        if filename.endswith(".toml"):
            base_name = path.splitext(filename)[0]
            configuration = Configuration.load_from_file(path.join("known_attacks", "wrap_and_decrypt", filename))
            alphabet = convert_configuration_to_python_pkcs11_command_list(configuration)
            automaton = run_learning(session, wrap_and_decrypt_initial_knowledge_factory, alphabet)
            save_automaton_to_file(automaton, path.join("known_attacks", "wrap_and_decrypt", base_name), "dot")
            save_automaton_to_file(automaton, path.join("known_attacks", "wrap_and_decrypt", base_name), "svg")

    for filename in listdir(path.join("known_attacks", "dks_2")):
        if filename.endswith(".toml"):
            base_name = path.splitext(filename)[0]
            configuration = Configuration.load_from_file(path.join("known_attacks", "dks_2", filename))
            alphabet = convert_configuration_to_python_pkcs11_command_list(configuration)
            automaton = run_learning(session, dks_experiment_2_initial_knowledge_factory, alphabet)
            save_automaton_to_file(automaton, path.join("known_attacks", "dks_2", base_name), "dot")
            save_automaton_to_file(automaton, path.join("known_attacks", "dks_2", base_name), "svg")

    for filename in listdir(path.join("known_attacks", "dks_3")):
        if filename.endswith(".toml"):
            base_name = path.splitext(filename)[0]
            configuration = Configuration.load_from_file(path.join("known_attacks", "dks_3", filename))
            alphabet = convert_configuration_to_python_pkcs11_command_list(configuration)
            automaton = run_learning(session, dks_experiment_3_initial_knowledge_factory, alphabet)
            save_automaton_to_file(automaton, path.join("known_attacks", "dks_3", base_name), "dot")
            save_automaton_to_file(automaton, path.join("known_attacks", "dks_3", base_name), "svg")

    for filename in listdir(path.join("known_attacks", "fls_2")):
        if filename.endswith(".toml"):
            base_name = path.splitext(filename)[0]
            configuration = Configuration.load_from_file(path.join("known_attacks", "fls_2", filename))
            alphabet = convert_configuration_to_python_pkcs11_command_list(configuration)
            automaton = run_learning(session, fls_2_initial_knowledge_factory, alphabet)
            save_automaton_to_file(automaton, path.join("known_attacks", "fls_2", base_name), "dot")
            save_automaton_to_file(automaton, path.join("known_attacks", "fls_2", base_name), "svg")

    session.close()
