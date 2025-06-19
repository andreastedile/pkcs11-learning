from __future__ import annotations

from dataclasses import dataclass

from Crypto.PublicKey.RSA import RsaKey
from PyKCS11.LowLevel import CK_OBJECT_HANDLE


@dataclass
class PyKCS11KnowledgeSet:
    def __init__(self):
        self.handle_dict: dict[int, CK_OBJECT_HANDLE] = {}
        self.secret_key_dict: dict[int, bytes] = {}
        self.public_key_dict: dict[int, RsaKey] = {}
        self.private_key_dict: dict[int, RsaKey] = {}
        self.rsa_pkcs_aenc_dict: dict[int, bytes] = {}
        self.rsa_pkcs_oaep_aenc_dict: dict[int, bytes] = {}
        self.aes_gcm_senc_dict: dict[int, bytes] = {}
        self.aes_ecb_senc_dict: dict[int, bytes] = {}

    def clear(self):
        self.handle_dict.clear()
        self.secret_key_dict.clear()
        self.public_key_dict.clear()
        self.private_key_dict.clear()
        self.rsa_pkcs_aenc_dict.clear()
        self.rsa_pkcs_oaep_aenc_dict.clear()
        self.aes_gcm_senc_dict.clear()
        self.aes_ecb_senc_dict.clear()
