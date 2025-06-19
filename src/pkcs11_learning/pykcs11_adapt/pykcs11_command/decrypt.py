import sys
import typing

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from PyKCS11 import *
from PyKCS11.LowLevel import *

from pkcs11_learning.core.abstract_pkcs11_commands import *
from pkcs11_learning.core.cryptographic_parameters import *
from pkcs11_learning.pykcs11_adapt.pykcs11_command.command import PyKCS11Command
from pkcs11_learning.pykcs11_adapt.cryptographic_parameters_to_pykcs11 import RSAPKCSOAEPParams_to_pykcs11
from pkcs11_learning.pykcs11_adapt.pykcs11_knowledge_set import PyKCS11KnowledgeSet


class PyKCS11DecryptSymSym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11DecryptSymSym, params: SymmetricCryptographyParams):
        self.command = command
        self.params = params

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_decryption_key = ks.handle_dict.get(self.command.handle_of_decryption_key)
        if handle_of_decryption_key is None:
            return NOT_APPLICABLE

        try:
            match self.params:
                case AESECBParams():
                    key_to_be_decrypted = ks.aes_ecb_senc_dict.get(self.command.key_to_be_decrypted)
                    if key_to_be_decrypted is None:
                        return NOT_APPLICABLE

                    mechanism = Mechanism(CKM_AES_ECB)
                    decrypted_key = session.decrypt(handle_of_decryption_key, key_to_be_decrypted, mechanism)

                    existing_decrypted_key = ks.secret_key_dict.get(self.command.decrypted_key)
                    if existing_decrypted_key is None:
                        ks.secret_key_dict[self.command.decrypted_key] = bytes(decrypted_key)
                    else:
                        assert bytes(decrypted_key) == ks.secret_key_dict[self.command.decrypted_key]
                case AESGCMParams():
                    key_to_be_decrypted = ks.aes_gcm_senc_dict.get(self.command.key_to_be_decrypted)
                    if key_to_be_decrypted is None:
                        return NOT_APPLICABLE

                    mechanism = AES_GCM_Mechanism(self.params.iv, self.params.aad, self.params.tag_bit_length)
                    decrypted_key = session.decrypt(handle_of_decryption_key, key_to_be_decrypted, mechanism)

                    existing_decrypted_key = ks.secret_key_dict.get(self.command.decrypted_key)
                    if existing_decrypted_key is None:
                        ks.secret_key_dict[self.command.decrypted_key] = bytes(decrypted_key)
                    else:
                        assert bytes(decrypted_key) == ks.secret_key_dict[self.command.decrypted_key]
                case other:
                    typing.assert_never(other)
            return OP_OK
        except PyKCS11Error as e:
            # diagnosis
            can_decrypt = session.getAttributeValue(handle_of_decryption_key, [CKA_DECRYPT])[0]
            if can_decrypt:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL


class PyKCS11DecryptSymAsym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11DecryptSymAsym, params: AsymmetricCryptographyParams):
        self.command = command
        self.params = params

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_decryption_key = ks.handle_dict.get(self.command.handle_of_decryption_key)
        if handle_of_decryption_key is None:
            return NOT_APPLICABLE

        try:
            match self.params:
                case RSAPKCSParams():
                    key_to_be_decrypted = ks.rsa_pkcs_aenc_dict.get(self.command.key_to_be_decrypted)
                    if key_to_be_decrypted is None:
                        return NOT_APPLICABLE

                    mechanism = MechanismRSAPKCS1
                    decrypted_key = session.decrypt(handle_of_decryption_key, key_to_be_decrypted, mechanism)

                    existing_decrypted_key = ks.secret_key_dict.get(self.command.decrypted_key)
                    if existing_decrypted_key is None:
                        ks.secret_key_dict[self.command.decrypted_key] = bytes(decrypted_key)
                    else:
                        assert bytes(decrypted_key) == ks.secret_key_dict[self.command.decrypted_key]
                case RSAPKCSOAEPParams():
                    key_to_be_decrypted = ks.rsa_pkcs_oaep_aenc_dict.get(self.command.key_to_be_decrypted)
                    if key_to_be_decrypted is None:
                        return NOT_APPLICABLE

                    mechanism = RSAPKCSOAEPParams_to_pykcs11(self.params)
                    decrypted_key = session.decrypt(handle_of_decryption_key, key_to_be_decrypted, mechanism)

                    existing_decrypted_key = ks.secret_key_dict.get(self.command.decrypted_key)
                    if existing_decrypted_key is None:
                        ks.secret_key_dict[self.command.decrypted_key] = bytes(decrypted_key)
                    else:
                        assert bytes(decrypted_key) == ks.secret_key_dict[self.command.decrypted_key]
            return OP_OK
        except PyKCS11Error as e:
            # diagnosis
            can_decrypt = session.getAttributeValue(handle_of_decryption_key, [CKA_DECRYPT])[0]
            if can_decrypt:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL


class PyKCS11DeduceDecryptSymSym(PyKCS11Command):
    def __init__(self, command: AbstractDeduceDecryptSymSym, params: SymmetricCryptographyParams,
                 pointed_by: list[int]):
        self.command = command
        self.params = params
        self.pointed_by = pointed_by

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        decryption_key = ks.secret_key_dict.get(self.command.decryption_key)
        if decryption_key is None:  # we do not have the decryption key yet.
            return NOT_APPLICABLE

        match self.params:
            case AESECBParams():
                key_to_be_decrypted = ks.aes_ecb_senc_dict.get(self.command.key_to_be_decrypted)
                if key_to_be_decrypted is None:
                    return NOT_APPLICABLE

                decipher = AES.new(decryption_key, AES.MODE_ECB)

                decrypted_key = decipher.decrypt(key_to_be_decrypted)

                existing_decrypted_key = ks.secret_key_dict.get(self.command.decrypted_key)
                if existing_decrypted_key is None:
                    ks.secret_key_dict[self.command.decrypted_key] = decrypted_key
                else:
                    assert decrypted_key == ks.secret_key_dict[self.command.decrypted_key]
            case AESGCMParams():
                key_to_be_decrypted = ks.aes_gcm_senc_dict.get(self.command.key_to_be_decrypted)
                if key_to_be_decrypted is None:
                    return NOT_APPLICABLE

                mac_len = int(self.params.tag_bit_length / 8)
                decipher = AES.new(decryption_key, AES.MODE_GCM, nonce=self.params.iv, mac_len=mac_len)
                decipher = decipher.update(self.params.aad)

                decrypted_key = decipher.decrypt_and_verify(key_to_be_decrypted[:-mac_len],
                                                            key_to_be_decrypted[-mac_len:])

                existing_decrypted_key = ks.secret_key_dict.get(self.command.decrypted_key)
                if existing_decrypted_key is None:
                    ks.secret_key_dict[self.command.decrypted_key] = decrypted_key
                else:
                    assert decrypted_key == ks.secret_key_dict[self.command.decrypted_key]
            case other:
                typing.assert_never(other)
        return OP_OK


class PyKCS11DeduceDecryptSymAsym(PyKCS11Command):
    def __init__(self, command: AbstractDeduceDecryptSymAsym, params: AsymmetricCryptographyParams,
                 pointed_by: list[int]):
        self.command = command
        self.params = params
        self.pointed_by = pointed_by

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        decryption_key = ks.private_key_dict.get(self.command.decryption_key)
        if decryption_key is None:  # we do not have the decryption key yet.
            return NOT_APPLICABLE

        match self.params:
            case RSAPKCSParams():
                key_to_be_decrypted = ks.rsa_pkcs_aenc_dict.get(self.command.key_to_be_decrypted)
                if key_to_be_decrypted is None:
                    return NOT_APPLICABLE

                decipher = PKCS1_v1_5.new(decryption_key)

                decrypted_key = decipher.decrypt(key_to_be_decrypted, None)

                existing_decrypted_key = ks.secret_key_dict.get(self.command.decrypted_key)
                if existing_decrypted_key is None:
                    ks.secret_key_dict[self.command.decrypted_key] = decrypted_key
                else:
                    assert decrypted_key == ks.secret_key_dict[self.command.decrypted_key]
            case RSAPKCSOAEPParams():
                key_to_be_decrypted = ks.rsa_pkcs_oaep_aenc_dict.get(self.command.key_to_be_decrypted)
                if key_to_be_decrypted is None:
                    return NOT_APPLICABLE

                decipher = RSAPKCSOAEPParams_to_pycryptodome_cipher(self.params, decryption_key)

                decrypted_key = decipher.decrypt(key_to_be_decrypted)

                existing_decrypted_key = ks.secret_key_dict.get(self.command.decrypted_key)
                if existing_decrypted_key is None:
                    ks.secret_key_dict[self.command.decrypted_key] = decrypted_key
                else:
                    assert decrypted_key == ks.secret_key_dict[self.command.decrypted_key]
            case other:
                typing.assert_never(other)
        return OP_OK


class PyKCS11DeduceDecryptAsymSym(PyKCS11Command):
    CLEAR_TEXT = "hello, world!"

    def __init__(self, command: AbstractDeduceDecryptAsymSym, params: SymmetricCryptographyParams,
                 pointed_by: list[int]):
        self.command = command
        self.params = params
        self.pointed_by = pointed_by

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        decryption_key = ks.secret_key_dict.get(self.command.decryption_key)
        if decryption_key is None:  # we do not have the decryption key yet.
            return NOT_APPLICABLE

        match self.params:
            case AESECBParams():
                key_to_be_decrypted = ks.aes_ecb_senc_dict.get(self.command.key_to_be_decrypted)
                if key_to_be_decrypted is None:
                    return NOT_APPLICABLE

                decipher = AES.new(decryption_key, AES.MODE_ECB)

                decrypted_key = decipher.decrypt(key_to_be_decrypted)
                private_key = RSA.import_key(decrypted_key)

                if self.command.decrypted_key in ks.secret_key_dict:
                    # TODO: check private rsa key equality
                    pass
                else:
                    ks.private_key_dict[self.command.decrypted_key] = private_key
            case AESGCMParams():
                key_to_be_decrypted = ks.aes_gcm_senc_dict.get(self.command.key_to_be_decrypted)
                if key_to_be_decrypted is None:
                    return NOT_APPLICABLE

                mac_len = int(self.params.tag_bit_length / 8)
                decipher = AES.new(decryption_key, AES.MODE_GCM, nonce=self.params.iv, mac_len=mac_len)
                decipher = decipher.update(self.params.aad)

                decrypted_key = decipher.decrypt_and_verify(key_to_be_decrypted[:-mac_len],
                                                            key_to_be_decrypted[-mac_len:])
                private_key = RSA.import_key(decrypted_key)

                if self.command.decrypted_key in ks.secret_key_dict:
                    # TODO: check private rsa key equality
                    pass
                else:
                    ks.private_key_dict[self.command.decrypted_key] = private_key
            case other:
                typing.assert_never(other)
        return OP_OK
