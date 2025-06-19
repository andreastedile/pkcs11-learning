from pkcs11_learning.core.configuration import Configuration
from pkcs11_learning.core.cryptographic_parameters import SymmetricCryptographyParams, AsymmetricCryptographyParams
from .pykcs11_command.command import PyKCS11Command
from .pykcs11_command import *


def convert_configuration_to_pykcs11_commands(config: Configuration,
                                              scp: SymmetricCryptographyParams,
                                              acp: AsymmetricCryptographyParams) -> list[PyKCS11Command]:
    alphabet: list[PyKCS11Command] = []

    # wrap
    for command in config.wrap_sym_sym_commands:
        alphabet.append(PyKCS11WrapSymSym(command, scp))

    for command in config.wrap_sym_asym_commands:
        alphabet.append(PyKCS11WrapSymAsym(command, acp))

    for command in config.wrap_asym_sym_commands:
        alphabet.append(PyKCS11WrapAsymSym(command, scp))

    # unwrap
    for command in config.unwrap_sym_sym_commands:
        alphabet.append(PyKCS11UnwrapSymSym(command, scp))

    for command in config.unwrap_sym_asym_commands:
        alphabet.append(PyKCS11UnwrapSymAsym(command, acp))

    for command in config.unwrap_asym_sym_commands:
        alphabet.append(PyKCS11UnwrapAsymSym(command, scp))

    # encrypt
    for command in config.encrypt_sym_sym_commands:
        alphabet.append(PyKCS11EncryptSymSym(command, scp))

    for command in config.encrypt_sym_asym_commands:
        alphabet.append(PyKCS11EncryptSymAsym(command, acp))

    # decrypt
    for command in config.decrypt_sym_sym_commands:
        alphabet.append(PyKCS11DecryptSymSym(command, scp))

    for command in config.decrypt_sym_asym_commands:
        alphabet.append(PyKCS11DecryptSymAsym(command, acp))

    # deduce encrypt
    for command in config.deduce_encrypt_sym_sym_commands:
        alphabet.append(PyKCS11DeduceEncryptSymSym(command, scp))

    for command in config.deduce_encrypt_sym_asym_commands:
        alphabet.append(PyKCS11DeduceEncryptSymAsym(command, acp))

    # deduce decrypt
    for command in config.deduce_decrypt_sym_sym_commands:
        alphabet.append(PyKCS11DeduceDecryptSymSym(command, scp,
                                                   config.pointed_by[command.decrypted_key]))

    for command in config.deduce_decrypt_sym_asym_commands:
        alphabet.append(
            PyKCS11DeduceDecryptSymAsym(command, acp,
                                        config.pointed_by[command.decrypted_key]))

    for command in config.deduce_decrypt_asym_sym_commands:
        alphabet.append(PyKCS11DeduceDecryptAsymSym(command, scp,
                                                    config.pointed_by[command.decrypted_key]))

    #
    for command in config.setwrap_commands:
        alphabet.append(PyKCS11SetWrap(command))

    for command in config.setunwrap_commands:
        alphabet.append(PyKCS11SetUnwrap(command))

    for command in config.setencrypt_commands:
        alphabet.append(PyKCS11SetEncrypt(command))

    for command in config.setdecrypt_commands:
        alphabet.append(PyKCS11SetDecrypt(command))

    #

    for command in config.unsetwrap_commands:
        alphabet.append(PyKCS11UnsetWrap(command))

    for command in config.unsetunwrap_commands:
        alphabet.append(PyKCS11UnsetUnwrap(command))

    for command in config.unsetencrypt_commands:
        alphabet.append(PyKCS11UnsetEncrypt(command))

    for command in config.unsetdecrypt_commands:
        alphabet.append(PyKCS11UnsetDecrypt(command))

    return alphabet
