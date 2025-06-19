import argparse
import typing
from pathlib import Path

from PyKCS11 import PyKCS11Lib, Session, MechanismAESGENERATEKEY
from PyKCS11.LowLevel import *
from aalpy import RandomWalkEqOracle, save_automaton_to_file, MealyMachine, run_Lstar
from dotenv import dotenv_values

from pkcs11_learning.core import *
from pkcs11_learning.pykcs11_adapt import *


def learn_attack_Lstar(session: Session,
                       file: Path,
                       knowledge_set: PyKCS11KnowledgeSet,
                       reset_knowledge_set: typing.Callable[[Session, PyKCS11KnowledgeSet], None],
                       scp: SymmetricCryptographyParams | None,
                       acp: AsymmetricCryptographyParams | None):
    """
    :param session: PKCS11 session.
    :param file: Path of the toml file from which to read the configuration of the attack.
    :param knowledge_set: Initial knowledge set for the configuration; that is, the knowledge set in the initial state.
    :param reset_knowledge_set: Function for resetting the knowledge set to the initial state.
        In particular, it should either set the attributes of the key handles to their initial values,
        or delete the handles and recreate them with the initial values.
    :param scp: Symmetric cryptography mechanism and its parameters to be used by the symmetric cryptographic operations, if any.
    :param acp: Asymmetric cryptography mechanism and its parameters to be used by the asymmetric cryptographic operations, if any.
    """
    configuration = Configuration.load_from_file(file)
    alphabet = convert_configuration_to_pykcs11_commands(configuration, scp, acp)

    sul = PyKCS11SUL(session, knowledge_set, reset_knowledge_set)
    eq_oracle = RandomWalkEqOracle(alphabet, sul, num_steps=5000)

    automaton = run_Lstar(alphabet, sul, eq_oracle, "mealy")
    assert isinstance(automaton, MealyMachine)

    name = file.stem
    if scp is not None:
        name = name + "_" + str(scp)
    if acp is not None:
        name = name + "_" + str(acp)
    save_automaton_to_file(automaton, file.with_name(name))
    automaton_without_unapplicable_transitions = remove_not_applicable_transitions(automaton)
    save_automaton_to_file(automaton_without_unapplicable_transitions, file.with_name(name), "svg")


def learn_wrap_and_decrypt(session: Session):
    from knowledge_sets.wrap_and_decrypt import create_initial_knowledge_set, reset_knowledge_set

    path = Path("examples", "wrap_and_decrypt")
    for file in path.rglob("*.toml"):
        print(f"learn {file.stem} with AES-ECB")
        learn_attack_Lstar(session,
                           file,
                           create_initial_knowledge_set(session),
                           reset_knowledge_set,
                           AESECBParams(),
                           None)

        print(f"learn {file.stem} with AES-GCM")
        learn_attack_Lstar(session,
                           file,
                           create_initial_knowledge_set(session),
                           reset_knowledge_set,
                           AESGCMParams.default(),
                           None)


def learn_dks_2(session: Session):
    from knowledge_sets.dks_2 import create_initial_knowledge_set, reset_knowledge_set

    path = Path("examples", "dks_2")
    for file in path.rglob("*.toml"):
        print(f"learn {file.stem} with AES-ECB")
        learn_attack_Lstar(session,
                           file,
                           create_initial_knowledge_set(session),
                           reset_knowledge_set,
                           AESECBParams(),
                           None)

        print(f"learn {file.stem} with AES-GCM")
        learn_attack_Lstar(session,
                           file,
                           create_initial_knowledge_set(session),
                           reset_knowledge_set,
                           AESGCMParams.default(),
                           None)


def learn_dks_3(session: Session):
    from knowledge_sets.dks_3 import create_initial_knowledge_set, reset_knowledge_set

    path = Path("examples", "dks_3")
    for file in path.rglob("*.toml"):
        print(f"learn {file.stem} with AES-ECB")
        learn_attack_Lstar(session,
                           file,
                           create_initial_knowledge_set(session),
                           reset_knowledge_set,
                           AESECBParams(),
                           None)

        print(f"learn {file.stem} with AES-GCM")
        learn_attack_Lstar(session,
                           file,
                           create_initial_knowledge_set(session),
                           reset_knowledge_set,
                           AESGCMParams.default(),
                           None)


def learn_dks_6(session: Session):
    from knowledge_sets.dks_6 import create_initial_knowledge_set, reset_knowledge_set

    path = Path("examples", "dks_6")
    for file in path.rglob("*.toml"):
        print(f"learn {file.stem} with AES-ECB and RSA-PKCS")
        learn_attack_Lstar(session,
                           file,
                           create_initial_knowledge_set(session),
                           reset_knowledge_set,
                           AESECBParams(),
                           RSAPKCSParams())

        print(f"learn {file.stem} with AES-GCM and RSA-PKCS-OAEP")
        learn_attack_Lstar(session,
                           file,
                           create_initial_knowledge_set(session),
                           reset_knowledge_set,
                           AESGCMParams.default(),
                           RSAPKCSOAEPParams.default())


def learn_fls_2(session: Session):
    from knowledge_sets.fls_2_aes_ecb import create_initial_knowledge_set_aes_ecb, reset_knowledge_set_aes_ecb
    from knowledge_sets.fls_2_aes_gcm import create_initial_knowledge_set_aes_gcm, reset_knowledge_set_aes_gcm

    path = Path("examples", "fls_2")
    for file in path.rglob("*.toml"):
        print(f"learn {file.stem} with AES-ECB and RSA-PKCS")
        learn_attack_Lstar(session,
                           file,
                           create_initial_knowledge_set_aes_ecb(session),
                           reset_knowledge_set_aes_ecb,
                           AESECBParams(),
                           None)

        print(f"learn {file.stem} with AES-GCM and RSA-PKCS-OAEP")
        learn_attack_Lstar(session,
                           file,
                           create_initial_knowledge_set_aes_gcm(session, AESGCMParams.default()),
                           reset_knowledge_set_aes_gcm,
                           AESGCMParams.default(),
                           None)


def create_trusted_key(lib: PyKCS11Lib, so: str, slot: int, pin: str):
    """
    Creates the trusted key, and overwrites the previous if it already exists.
    """
    lib.load(so)
    session = lib.openSession(slot, CKF_RW_SESSION)
    session.login(pin, CKU_SO)

    existing = session.findObjects([(CKA_LABEL, "dks6")])
    if len(existing) > 0:
        session.destroyObject(existing[0])

    template = [
        (CKA_LABEL, "dks6"),
        (CKA_VALUE_LEN, 16),
        (CKA_EXTRACTABLE, CK_TRUE),
        (CKA_TRUSTED, CK_TRUE),
        (CKA_PRIVATE, CK_FALSE),
        (CKA_TOKEN, CK_TRUE),
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    session.generateKey(template, MechanismAESGENERATEKEY)

    session.logout()
    session.closeSession()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Learn known PKCS#11 attacks")
    parser.add_argument("--opencryptoki", action="store_true", default=False)
    parser.add_argument("--securosys", action="store_true", default=False)
    args = parser.parse_args()

    if args.opencryptoki:
        values = dotenv_values("opencryptoki.env")
        so, slot, pin = values["SO"], int(values["SLOT"]), values["PIN"]

        lib = PyKCS11Lib()

        print("learning attacks using openCryptoki")
        print("learning wrap and decrypt")
        run(lib, so, slot, pin, learn_wrap_and_decrypt)
        print("learning dks 2")
        run(lib, so, slot, pin, learn_dks_2)
        print("learning dks 3")
        run(lib, so, slot, pin, learn_dks_3)
        print("learning dks 6")
        create_trusted_key(lib, so, slot, "12345678")
        run(lib, so, slot, pin, learn_dks_6)
        print("learning fls 2")
        run(lib, so, slot, pin, learn_fls_2)

    if args.securosys:
        values = dotenv_values("opencryptoki.env")
        so, slot, pin = values["SO"], int(values["SLOT"]), values["PIN"]

        lib = PyKCS11Lib()

        print("learning attacks using Securosys")
        print("learning wrap and decrypt")
        run(lib, so, slot, pin, learn_wrap_and_decrypt)
        print("learning dks 2")
        run(lib, so, slot, pin, learn_dks_2)
        print("learning dks 3")
        run(lib, so, slot, pin, learn_dks_3)
        print("learning fls 2")
        run(lib, so, slot, pin, learn_fls_2)
