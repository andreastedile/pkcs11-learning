from __future__ import annotations

import tomllib
from collections import defaultdict

from abstract_pkcs11_commands import \
    AbstractPKCS11Wrap, \
    AbstractPKCS11Unwrap, \
    AbstractPKCS11Encrypt, \
    AbstractPKCS11Decrypt, \
    AbstractDeduceEncrypt, \
    AbstractDeduceDecrypt, \
    AbstractPKCS11SetWrap, \
    AbstractPKCS11SetUnwrap, \
    AbstractPKCS11SetEncrypt, \
    AbstractPKCS11SetDecrypt, \
    AbstractPKCS11UnsetWrap, \
    AbstractPKCS11UnsetUnwrap, \
    AbstractPKCS11UnsetEncrypt, \
    AbstractPKCS11UnsetDecrypt


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
        #
        self.wrap_commands: list[AbstractPKCS11Wrap] = []
        self.unwrap_commands: list[AbstractPKCS11Unwrap] = []
        self.encrypt_commands: list[AbstractPKCS11Encrypt] = []
        self.decrypt_commands: list[AbstractPKCS11Decrypt] = []
        self.deduce_encrypt_commands: list[AbstractDeduceEncrypt] = []
        self.deduce_decrypt_commands: list[AbstractDeduceDecrypt] = []
        #
        self.setwrap_commands: list[AbstractPKCS11SetWrap] = []
        self.setunwrap_commands: list[AbstractPKCS11SetUnwrap] = []
        self.setencrypt_commands: list[AbstractPKCS11SetEncrypt] = []
        self.setdecrypt_commands: list[AbstractPKCS11SetDecrypt] = []
        #
        self.unsetwrap_commands: list[AbstractPKCS11UnsetWrap] = []
        self.unsetunwrap_commands: list[AbstractPKCS11UnsetUnwrap] = []
        self.unsetencrypt_commands: list[AbstractPKCS11UnsetEncrypt] = []
        self.unsetdecrypt_commands: list[AbstractPKCS11UnsetDecrypt] = []

    @staticmethod
    def load_from_file(file: str) -> Configuration:
        """
        :param file: a .toml file, such as "wrap_and_decrypt.toml" 
        """
        config = Configuration()

        with open(file, "rb") as f:
            data = tomllib.load(f)

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

            wrap_commands = commands.get('wrap', [])
            unwrap_commands = commands.get('unwrap', [])
            encrypt_commands = commands.get('encrypt', [])
            decrypt_commands = commands.get('decrypt', [])
            deduce_encrypt_commands = commands.get('deduce_encrypt', [])
            deduce_decrypt_commands = commands.get('deduce_decrypt', [])

            for command in wrap_commands:
                command = AbstractPKCS11Wrap(command["handle_of_wrapping_key"],
                                             command["handle_of_key_to_be_wrapped"],
                                             command["wrapped_key"])
                config.wrap_commands.append(command)

            for command in unwrap_commands:
                command = AbstractPKCS11Unwrap(command["handle_of_unwrapping_key"],
                                               command["key_to_be_unwrapped"],
                                               command["handle_of_recovered_key"])
                config.unwrap_commands.append(command)

            for command in encrypt_commands:
                command = AbstractPKCS11Encrypt(command["handle_of_encryption_key"],
                                                command["key_to_be_encrypted"],
                                                command["encrypted_key"])
                config.encrypt_commands.append(command)

            for command in decrypt_commands:
                command = AbstractPKCS11Decrypt(command["handle_of_decryption_key"],
                                                command["key_to_be_decrypted"],
                                                command["decrypted_key"])
                config.decrypt_commands.append(command)

            for command in deduce_encrypt_commands:
                command = AbstractDeduceEncrypt(command["encryption_key"],
                                                command["key_to_be_encrypted"],
                                                command["encrypted_key"])
                config.deduce_encrypt_commands.append(command)

            for command in deduce_decrypt_commands:
                command = AbstractDeduceDecrypt(command["decryption_key"],
                                                command["key_to_be_decrypted"],
                                                command["decrypted_key"])
                config.deduce_decrypt_commands.append(command)

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


if __name__ == "__main__":
    config = Configuration.load_from_file("wrap_and_decrypt.toml")
    pass
