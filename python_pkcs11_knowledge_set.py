from __future__ import annotations

from dataclasses import dataclass

from pkcs11 import SecretKey, PublicKey, PrivateKey

from configuration import Configuration


@dataclass
class PythonPKCS11KnowledgeSet:
    def __init__(self):
        self.handle_of_secret_key_dict: dict[int, SecretKey | None] = {}
        self.handle_of_public_key_dict: dict[int, PublicKey | None] = {}
        self.handle_of_private_key_dict: dict[int, PrivateKey | None] = {}
        self.secret_key_dict: dict[int, bytes | None] = {}
        self.public_key_dict: dict[int, bytes | None] = {}
        self.private_key_dict: dict[int, bytes | None] = {}
        self.aenc_dict: dict[int, bytes | None] = {}
        self.senc_dict: dict[int, bytes | None] = {}

    @staticmethod
    def from_configuration(config: Configuration) -> PythonPKCS11KnowledgeSet:
        knowledge_set = PythonPKCS11KnowledgeSet()

        for index in config.handle_of_secret_key_list:
            knowledge_set.handle_of_secret_key_dict[index] = None
        for index in config.handle_of_public_key_list:
            knowledge_set.handle_of_public_key_dict[index] = None
        for index in config.handle_of_private_key_list:
            knowledge_set.handle_of_private_key_dict[index] = None
        for index in config.secret_key_list:
            knowledge_set.secret_key_dict[index] = None
        for index in config.public_key_list:
            knowledge_set.public_key_dict[index] = None
        for index in config.private_key_list:
            knowledge_set.private_key_dict[index] = None
        for index in config.aenc_list:
            knowledge_set.aenc_dict[index] = None
        for index in config.senc_list:
            knowledge_set.senc_dict[index] = None

        return knowledge_set
