from configuration import Configuration

from python_pkcs11_commands import \
    PythonPKCS11Command, \
    PythonPKCS11WrapSymSym, \
    PythonPKCS11UnwrapSymSym, \
    PythonPKCS11EncryptSymSym, \
    PythonPKCS11DecryptSymSym, \
    PythonPKCS11DeduceDecryptSymSym, \
    PythonPKCS11SetWrap, \
    PythonPKCS11SetUnwrap, \
    PythonPKCS11SetEncrypt, \
    PythonPKCS11SetDecrypt, \
    PythonPKCS11UnsetWrap, \
    PythonPKCS11UnsetUnwrap, \
    PythonPKCS11UnsetEncrypt, \
    PythonPKCS11UnsetDecrypt


def convert_configuration_to_python_pkcs11_command_list(config: Configuration) -> list[PythonPKCS11Command]:
    alphabet: list[PythonPKCS11Command] = []

    for command in config.wrap_commands:
        alphabet.append(PythonPKCS11WrapSymSym(command))

    for command in config.unwrap_commands:
        alphabet.append(PythonPKCS11UnwrapSymSym(command))

    for command in config.encrypt_commands:
        alphabet.append(PythonPKCS11EncryptSymSym(command))

    for command in config.decrypt_commands:
        alphabet.append(PythonPKCS11DecryptSymSym(command))

    for command in config.deduce_decrypt_commands:
        alphabet.append(PythonPKCS11DeduceDecryptSymSym(command, config.pointed_by[command.decrypted_key]))

    #

    for command in config.setwrap_commands:
        alphabet.append(PythonPKCS11SetWrap(command))

    for command in config.setunwrap_commands:
        alphabet.append(PythonPKCS11SetUnwrap(command))

    for command in config.setencrypt_commands:
        alphabet.append(PythonPKCS11SetEncrypt(command))

    for command in config.setdecrypt_commands:
        alphabet.append(PythonPKCS11SetDecrypt(command))

    #

    for command in config.unsetwrap_commands:
        alphabet.append(PythonPKCS11UnsetWrap(command))

    for command in config.unsetunwrap_commands:
        alphabet.append(PythonPKCS11UnsetUnwrap(command))

    for command in config.unsetencrypt_commands:
        alphabet.append(PythonPKCS11UnsetEncrypt(command))

    for command in config.unsetdecrypt_commands:
        alphabet.append(PythonPKCS11UnsetDecrypt(command))

    return alphabet
