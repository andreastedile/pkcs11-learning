__all__ = ["PyKCS11EncryptSymSym", "PyKCS11EncryptSymAsym",
           "PyKCS11DeduceEncryptSymSym", "PyKCS11DeduceEncryptSymAsym"]

import sys
import typing

from Crypto.Cipher import AES, PKCS1_v1_5
from PyKCS11 import *
from PyKCS11.LowLevel import *

from pkcs11_learning.core.abstract_pkcs11_commands import *
from pkcs11_learning.core.cryptographic_parameters import *
from pkcs11_learning.pykcs11_adapt.pykcs11_command.command import PyKCS11Command
from pkcs11_learning.pykcs11_adapt.cryptographic_parameters_to_pykcs11 import RSAPKCSOAEPParams_to_pykcs11
from pkcs11_learning.pykcs11_adapt.pykcs11_knowledge_set import PyKCS11KnowledgeSet


class PyKCS11EncryptSymSym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11EncryptSymSym, params: SymmetricCryptographyParams):
        self.command = command
        self.params = params

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_encryption_key = ks.handle_dict.get(self.command.handle_of_encryption_key)
        if handle_of_encryption_key is None:
            return NOT_APPLICABLE

        key_to_be_encrypted = ks.secret_key_dict.get(self.command.key_to_be_encrypted)
        if key_to_be_encrypted is None:
            return NOT_APPLICABLE

        try:
            match self.params:
                case AESECBParams():
                    mechanism = Mechanism(CKM_AES_ECB)
                    encrypted_key = session.encrypt(handle_of_encryption_key, key_to_be_encrypted, mechanism)

                    existing_encrypted_key = ks.aes_ecb_senc_dict.get(self.command.encrypted_key)
                    if existing_encrypted_key is None:
                        ks.aes_ecb_senc_dict[self.command.encrypted_key] = bytes(encrypted_key)
                    else:
                        assert bytes(encrypted_key) == existing_encrypted_key
                case AESGCMParams():
                    mechanism = AES_GCM_Mechanism(self.params.iv, self.params.aad, self.params.tag_bit_length)
                    encrypted_key = session.encrypt(handle_of_encryption_key, key_to_be_encrypted, mechanism)

                    existing_encrypted_key = ks.aes_gcm_senc_dict.get(self.command.encrypted_key)
                    if existing_encrypted_key is None:
                        ks.aes_gcm_senc_dict[self.command.encrypted_key] = bytes(encrypted_key)
                    else:
                        assert bytes(encrypted_key) == existing_encrypted_key
                case other:
                    typing.assert_never(other)
            return OP_OK
        except PyKCS11Error as e:
            # diagnosis
            can_encrypt = session.getAttributeValue(handle_of_encryption_key, [CKA_ENCRYPT])[0]
            if can_encrypt:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL


class PyKCS11EncryptSymAsym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11EncryptSymAsym, params: AsymmetricCryptographyParams):
        self.command = command
        self.params = params

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_encryption_key = ks.handle_dict.get(self.command.handle_of_encryption_key)
        if handle_of_encryption_key is None:
            return NOT_APPLICABLE

        key_to_be_encrypted = ks.secret_key_dict.get(self.command.key_to_be_encrypted)
        if key_to_be_encrypted is None:
            return NOT_APPLICABLE

        try:
            match self.params:
                case RSAPKCSParams():
                    mechanism = MechanismRSAPKCS1
                    encrypted_key = session.encrypt(handle_of_encryption_key, key_to_be_encrypted, mechanism)

                    existing_encrypted_key = ks.rsa_pkcs_aenc_dict.get(self.command.encrypted_key)
                    if existing_encrypted_key is None:
                        ks.rsa_pkcs_aenc_dict[self.command.encrypted_key] = bytes(encrypted_key)
                    else:
                        # we cannot compare as this cryptographic mechanism introduces randomness.
                        pass
                case RSAPKCSOAEPParams():
                    mechanism = RSAPKCSOAEPParams_to_pykcs11(self.params)
                    encrypted_key = session.encrypt(handle_of_encryption_key, key_to_be_encrypted, mechanism)

                    existing_encrypted_key = ks.rsa_pkcs_oaep_aenc_dict.get(self.command.encrypted_key)
                    if existing_encrypted_key is None:
                        ks.rsa_pkcs_oaep_aenc_dict[self.command.encrypted_key] = bytes(encrypted_key)
                    else:
                        # we cannot compare as this cryptographic mechanism introduces randomness.
                        pass
                case other:
                    typing.assert_never(other)
            return OP_OK
        except PyKCS11Error as e:
            # diagnosis
            can_encrypt = session.getAttributeValue(handle_of_encryption_key, [CKA_ENCRYPT])[0]
            if can_encrypt:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL


class PyKCS11DeduceEncryptSymSym(PyKCS11Command):
    def __init__(self, command: AbstractDeduceEncryptSymSym, params: SymmetricCryptographyParams):
        self.command = command
        self.params = params

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        encryption_key = ks.secret_key_dict.get(self.command.encryption_key)
        if encryption_key is None:
            return NOT_APPLICABLE

        key_to_be_encrypted = ks.secret_key_dict.get(self.command.key_to_be_encrypted)
        if key_to_be_encrypted is None:
            return NOT_APPLICABLE

        match self.params:
            case AESECBParams():
                cipher = AES.new(encryption_key, AES.MODE_ECB)

                encrypted_key = cipher.encrypt(key_to_be_encrypted)

                existing_encrypted_key = ks.aes_ecb_senc_dict.get(self.command.encrypted_key)
                if existing_encrypted_key is None:
                    ks.aes_ecb_senc_dict[self.command.encrypted_key] = encrypted_key
                else:
                    assert encrypted_key == ks.aes_ecb_senc_dict[self.command.encrypted_key]
            case AESGCMParams():
                cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=self.params.iv,
                                 mac_len=self.params.tag_bit_length)
                cipher = cipher.update(self.params.aad)

                encrypted_key, digest = cipher.encrypt_and_digest(key_to_be_encrypted)

                existing_encrypted_key = ks.aes_gcm_senc_dict.get(self.command.encrypted_key)
                if existing_encrypted_key is None:
                    ks.aes_gcm_senc_dict[self.command.encrypted_key] = encrypted_key
                else:
                    assert encrypted_key == existing_encrypted_key
            case other:
                typing.assert_never(other)
        return OP_OK


class PyKCS11DeduceEncryptSymAsym(PyKCS11Command):
    def __init__(self, command: AbstractDeduceEncryptSymAsym, params: AsymmetricCryptographyParams):
        self.command = command
        self.params = params

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        encryption_key = ks.public_key_dict.get(self.command.encryption_key)
        if encryption_key is None:
            return NOT_APPLICABLE

        key_to_be_encrypted = ks.secret_key_dict.get(self.command.key_to_be_encrypted)
        if key_to_be_encrypted is None:
            return NOT_APPLICABLE

        match self.params:
            case RSAPKCSParams():
                cipher = PKCS1_v1_5.new(encryption_key)

                encrypted_key = cipher.encrypt(key_to_be_encrypted)

                existing_encrypted_key = ks.rsa_pkcs_aenc_dict.get(self.command.encrypted_key)
                if existing_encrypted_key is None:
                    ks.rsa_pkcs_aenc_dict[self.command.encrypted_key] = bytes(encrypted_key)
                else:
                    # we cannot compare as this cryptographic mechanism introduces randomness.
                    pass
            case RSAPKCSOAEPParams():
                cipher = RSAPKCSOAEPParams_to_pycryptodome_cipher(self.params, encryption_key)

                encrypted_key = cipher.encrypt(key_to_be_encrypted)

                existing_encrypted_key = ks.rsa_pkcs_oaep_aenc_dict.get(self.command.encrypted_key)
                if existing_encrypted_key is None:
                    ks.rsa_pkcs_oaep_aenc_dict[self.command.encrypted_key] = encrypted_key
                else:
                    # we cannot compare as this cryptographic mechanism introduces randomness.
                    pass
            case other:
                typing.assert_never(other)
        return OP_OK
