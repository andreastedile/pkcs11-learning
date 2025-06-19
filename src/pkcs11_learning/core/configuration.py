from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from tomllib import load

from .abstract_pkcs11_commands import *


class Configuration:
    def __init__(self):
        self.handle_of_secret_key_list: list[int] = []
        self.handle_of_public_key_list: list[int] = []
        self.handle_of_private_key_list: list[int] = []
        self.secret_key_list: list[int] = []
        self.public_key_list: list[int] = []
        self.private_key_list: list[int] = []
        self.aenc_list: list[int] = []
        self.senc_list: list[int] = []
        self.pointed_by: dict[int, list[int]] = defaultdict(list)
        # wrap
        self.wrap_sym_sym_commands: list[AbstractPKCS11WrapSymSym] = []
        self.wrap_sym_asym_commands: list[AbstractPKCS11WrapSymAsym] = []
        self.wrap_asym_sym_commands: list[AbstractPKCS11WrapAsymSym] = []
        # unwrap
        self.unwrap_sym_sym_commands: list[AbstractPKCS11UnwrapSymSym] = []
        self.unwrap_sym_asym_commands: list[AbstractPKCS11UnwrapSymAsym] = []
        self.unwrap_asym_sym_commands: list[AbstractPKCS11UnwrapAsymSym] = []
        # encrypt
        self.encrypt_sym_sym_commands: list[AbstractPKCS11EncryptSymSym] = []
        self.encrypt_sym_asym_commands: list[AbstractPKCS11EncryptSymAsym] = []
        # decrypt
        self.decrypt_sym_sym_commands: list[AbstractPKCS11DecryptSymSym] = []
        self.decrypt_sym_asym_commands: list[AbstractPKCS11DecryptSymAsym] = []
        # deduce encrypt
        self.deduce_encrypt_sym_sym_commands: list[AbstractDeduceEncryptSymSym] = []
        self.deduce_encrypt_sym_asym_commands: list[AbstractDeduceEncryptSymAsym] = []
        # deduce decrypt
        self.deduce_decrypt_sym_sym_commands: list[AbstractDeduceDecryptSymSym] = []
        self.deduce_decrypt_sym_asym_commands: list[AbstractDeduceDecryptSymAsym] = []
        self.deduce_decrypt_asym_sym_commands: list[AbstractDeduceDecryptAsymSym] = []
        # set attributes
        self.setwrap_commands: list[AbstractPKCS11SetWrap] = []
        self.setunwrap_commands: list[AbstractPKCS11SetUnwrap] = []
        self.setencrypt_commands: list[AbstractPKCS11SetEncrypt] = []
        self.setdecrypt_commands: list[AbstractPKCS11SetDecrypt] = []
        # unset attributes
        self.unsetwrap_commands: list[AbstractPKCS11UnsetWrap] = []
        self.unsetunwrap_commands: list[AbstractPKCS11UnsetUnwrap] = []
        self.unsetencrypt_commands: list[AbstractPKCS11UnsetEncrypt] = []
        self.unsetdecrypt_commands: list[AbstractPKCS11UnsetDecrypt] = []

    @staticmethod
    def load_from_file(file: Path) -> Configuration:
        """
        :param file: a .toml file, such as "wrap_and_decrypt.toml"
        """
        config = Configuration()

        with open(file, "rb") as f:
            data = load(f)

            nodes = data["nodes"]

            handle_of_secret_key = nodes.get("handle_of_secret_key")
            handle_of_public_key = nodes.get("handle_of_public_key")
            handle_of_private_key = nodes.get("handle_of_private_key")
            secret_key_list = nodes.get("secret_key")
            public_key_list = nodes.get("public_key")
            private_key_list = nodes.get("private_key")
            aenc_list = nodes.get("aenc")
            senc_list = nodes.get("senc")

            for node in handle_of_secret_key:
                index = node["index"]
                config.handle_of_secret_key_list.append(index)
            for node in handle_of_public_key:
                index = node["index"]
                config.handle_of_public_key_list.append(index)
            for node in handle_of_private_key:
                index = node["index"]
                config.handle_of_private_key_list.append(index)
            for node in secret_key_list:
                index = node["index"]
                config.secret_key_list.append(index)
                pointed_by = node["pointed_by"]
                for handle in pointed_by:
                    config.pointed_by[index].append(handle)
            for node in public_key_list:
                index = node["index"]
                pointed_by = node["pointed_by"]
                config.public_key_list.append(index)
                for handle in pointed_by:
                    config.pointed_by[index].append(handle)
            for node in private_key_list:
                index = node["index"]
                pointed_by = node["pointed_by"]
                config.private_key_list.append(index)
                for handle in pointed_by:
                    config.pointed_by[index].append(handle)
            for node in aenc_list:
                index = node["index"]
                config.aenc_list.append(index)
            for node in senc_list:
                index = node["index"]
                config.senc_list.append(index)

            commands = data["commands"]

            wrap_sym_sym_commands = commands.get('wrap_sym_sym', [])
            wrap_sym_asym_commands = commands.get('wrap_sym_asym', [])
            wrap_asym_sym_commands = commands.get('wrap_asym_sym', [])

            unwrap_sym_sym_commands = commands.get('unwrap_sym_sym', [])
            unwrap_sym_asym_commands = commands.get('unwrap_sym_asym', [])
            unwrap_asym_sym_commands = commands.get('unwrap_asym_sym', [])

            encrypt_sym_sym_commands = commands.get('encrypt_sym_sym', [])
            encrypt_sym_asym_commands = commands.get('encrypt_sym_asym', [])

            decrypt_sym_sym_commands = commands.get('decrypt_sym_sym', [])
            decrypt_sym_asym_commands = commands.get('decrypt_sym_asym', [])

            deduce_encrypt_sym_sym_commands = commands.get('deduce_encrypt_sym_sym', [])
            deduce_encrypt_sym_asym_commands = commands.get('deduce_encrypt_sym_asym', [])

            deduce_decrypt_sym_sym_commands = commands.get('deduce_decrypt_sym_sym', [])
            deduce_sym_asym_decrypt_commands = commands.get('deduce_decrypt_sym_asym', [])
            deduce_decrypt_asym_sym_commands = commands.get('deduce_decrypt_asym_sym', [])

            for command in wrap_sym_sym_commands:
                command = AbstractPKCS11WrapSymSym(command["handle_of_wrapping_key"],
                                                   command["handle_of_key_to_be_wrapped"],
                                                   command["wrapped_key"])
                config.wrap_sym_sym_commands.append(command)

            for command in wrap_sym_asym_commands:
                command = AbstractPKCS11WrapSymAsym(command["handle_of_wrapping_key"],
                                                    command["handle_of_key_to_be_wrapped"],
                                                    command["wrapped_key"])
                config.wrap_sym_asym_commands.append(command)

            for command in wrap_asym_sym_commands:
                command = AbstractPKCS11WrapAsymSym(command["handle_of_wrapping_key"],
                                                    command["handle_of_key_to_be_wrapped"],
                                                    command["wrapped_key"])
                config.wrap_asym_sym_commands.append(command)

            for command in unwrap_sym_sym_commands:
                command = AbstractPKCS11UnwrapSymSym(command["handle_of_unwrapping_key"],
                                                     command["key_to_be_unwrapped"],
                                                     command["handle_of_recovered_key"])
                config.unwrap_sym_sym_commands.append(command)

            for command in unwrap_sym_asym_commands:
                command = AbstractPKCS11UnwrapSymAsym(command["handle_of_unwrapping_key"],
                                                      command["key_to_be_unwrapped"],
                                                      command["handle_of_recovered_key"])
                config.unwrap_sym_asym_commands.append(command)

            for command in unwrap_asym_sym_commands:
                command = AbstractPKCS11UnwrapAsymSym(command["handle_of_unwrapping_key"],
                                                      command["key_to_be_unwrapped"],
                                                      command["handle_of_recovered_key"])
                config.unwrap_asym_sym_commands.append(command)

            for command in encrypt_sym_sym_commands:
                command = AbstractPKCS11EncryptSymSym(command["handle_of_encryption_key"],
                                                      command["key_to_be_encrypted"],
                                                      command["encrypted_key"])
                config.encrypt_sym_sym_commands.append(command)

            for command in encrypt_sym_asym_commands:
                command = AbstractPKCS11EncryptSymAsym(command["handle_of_encryption_key"],
                                                       command["key_to_be_encrypted"],
                                                       command["encrypted_key"])
                config.encrypt_sym_asym_commands.append(command)

            for command in decrypt_sym_sym_commands:
                command = AbstractPKCS11DecryptSymSym(command["handle_of_decryption_key"],
                                                      command["key_to_be_decrypted"],
                                                      command["decrypted_key"])
                config.decrypt_sym_sym_commands.append(command)

            for command in decrypt_sym_asym_commands:
                command = AbstractPKCS11DecryptSymAsym(command["handle_of_decryption_key"],
                                                       command["key_to_be_decrypted"],
                                                       command["decrypted_key"])
                config.decrypt_sym_asym_commands.append(command)

            for command in deduce_encrypt_sym_sym_commands:
                command = AbstractDeduceEncryptSymSym(command["encryption_key"],
                                                      command["key_to_be_encrypted"],
                                                      command["encrypted_key"])
                config.deduce_encrypt_sym_sym_commands.append(command)

            for command in deduce_encrypt_sym_asym_commands:
                command = AbstractDeduceEncryptSymAsym(command["encryption_key"],
                                                       command["key_to_be_encrypted"],
                                                       command["encrypted_key"])
                config.deduce_encrypt_sym_asym_commands.append(command)

            for command in deduce_decrypt_sym_sym_commands:
                command = AbstractDeduceDecryptSymSym(command["decryption_key"],
                                                      command["key_to_be_decrypted"],
                                                      command["decrypted_key"])
                config.deduce_decrypt_sym_sym_commands.append(command)

            for command in deduce_sym_asym_decrypt_commands:
                command = AbstractDeduceDecryptSymAsym(command["decryption_key"],
                                                       command["key_to_be_decrypted"],
                                                       command["decrypted_key"])
                config.deduce_decrypt_sym_asym_commands.append(command)

            for command in deduce_decrypt_asym_sym_commands:
                command = AbstractDeduceDecryptAsymSym(command["decryption_key"],
                                                       command["key_to_be_decrypted"],
                                                       command["decrypted_key"])
                config.deduce_decrypt_asym_sym_commands.append(command)

            setattribute = data["setattribute"]

            setattribute_wrap = setattribute.get("wrap", [])
            setattribute_unwrap = setattribute.get("unwrap", [])
            setattribute_encrypt = setattribute.get("encrypt", [])
            setattribute_decrypt = setattribute.get("decrypt", [])

            for command in setattribute_wrap:
                command = AbstractPKCS11SetWrap(command["handle"])
                config.setwrap_commands.append(command)

            for command in setattribute_unwrap:
                command = AbstractPKCS11SetUnwrap(command["handle"])
                config.setunwrap_commands.append(command)

            for command in setattribute_encrypt:
                command = AbstractPKCS11SetEncrypt(command["handle"])
                config.setencrypt_commands.append(command)

            for command in setattribute_decrypt:
                command = AbstractPKCS11SetDecrypt(command["handle"])
                config.setdecrypt_commands.append(command)

            unsetattribute = data["unsetattribute"]

            unsetattribute_wrap = unsetattribute.get("wrap", [])
            unsetattribute_unwrap = unsetattribute.get("unwrap", [])
            unsetattribute_encrypt = unsetattribute.get("encrypt", [])
            unsetattribute_decrypt = unsetattribute.get("decrypt", [])

            for command in unsetattribute_wrap:
                command = AbstractPKCS11UnsetWrap(command["handle"])
                config.unsetwrap_commands.append(command)

            for command in unsetattribute_unwrap:
                command = AbstractPKCS11UnsetUnwrap(command["handle"])
                config.unsetunwrap_commands.append(command)

            for command in unsetattribute_encrypt:
                command = AbstractPKCS11UnsetEncrypt(command["handle"])
                config.unsetencrypt_commands.append(command)

            for command in unsetattribute_decrypt:
                command = AbstractPKCS11UnsetDecrypt(command["handle"])
                config.unsetdecrypt_commands.append(command)

        return config
