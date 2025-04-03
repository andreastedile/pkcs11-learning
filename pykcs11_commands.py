__all__ = [
    "PyKCS11Command",
    "PyKCS11WrapSymSym", "PyKCS11WrapSymAsym", "PyKCS11WrapAsymSym",
    "PyKCS11UnwrapSymSym", "PyKCS11UnwrapAsymSym", "PyKCS11UnwrapSymAsym",
    "PyKCS11EncryptSymSym", "PyKCS11EncryptSymAsym",
    "PyKCS11DecryptSymSym", "PyKCS11DecryptSymAsym",
    "PyKCS11DeduceEncryptSymSym", "PyKCS11DeduceEncryptSymAsym",
    "PyKCS11DeduceDecryptSymSym", "PyKCS11DeduceDecryptAsymSym", "PyKCS11DeduceDecryptSymAsym",
    "PyKCS11SetWrap", "PyKCS11UnsetWrap",
    "PyKCS11SetUnwrap", "PyKCS11UnsetUnwrap",
    "PyKCS11SetEncrypt", "PyKCS11UnsetEncrypt",
    "PyKCS11SetDecrypt", "PyKCS11UnsetDecrypt"
]

import abc
import sys

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from PyKCS11 import Session, PyKCS11Error, CK_TRUE, CK_FALSE, MechanismRSAPKCS1
from PyKCS11.LowLevel import \
    CK_OBJECT_HANDLE, \
    CKA_CLASS, CKA_KEY_TYPE, CKA_WRAP, CKA_UNWRAP, CKA_ENCRYPT, CKA_DECRYPT, \
    CKO_PRIVATE_KEY, CKO_SECRET_KEY, \
    CKK_RSA, CKK_AES

from abstract_pkcs11_commands import *
from my_types import AESGCMEncryptionWithDigest, AES_GCM_MECHANISM, TAG_BYTES, AAD, IV
from pykcs11_knowledge_set import PyKCS11KnowledgeSet


class PyKCS11Command(abc.ABC):
    @abc.abstractmethod
    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        raise NotImplementedError

    def __repr__(self):
        return str(self)

    def __str__(self):
        raise NotImplementedError


class PyKCS11WrapSymSym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11WrapSymSym):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_wrapping_key = ks.handle_dict.get(self.command.handle_of_wrapping_key)
        if handle_of_wrapping_key is None:  # we do not have the handle of the wrapping key yet.
            return NOT_APPLICABLE
        assert isinstance(handle_of_wrapping_key, CK_OBJECT_HANDLE)

        handle_of_key_to_be_wrapped = ks.handle_dict.get(self.command.handle_of_key_to_be_wrapped)
        if handle_of_key_to_be_wrapped is None:  # we do not have the handle of the key to be wrapped yet.
            return NOT_APPLICABLE
        assert isinstance(handle_of_key_to_be_wrapped, CK_OBJECT_HANDLE)

        try:
            wrapped_key = session.wrapKey(handle_of_wrapping_key, handle_of_key_to_be_wrapped, AES_GCM_MECHANISM)

            ewd = AESGCMEncryptionWithDigest.from_pkcs11_aes_gcm(bytes(wrapped_key), TAG_BYTES)

            if self.command.wrapped_key in ks.senc_dict:  # terms can be derived in multiple ways
                assert ewd == ks.senc_dict[self.command.wrapped_key]
            else:
                ks.senc_dict[self.command.wrapped_key] = ewd
        except PyKCS11Error as e:
            # diagnosis
            can_wrap = session.getAttributeValue(handle_of_wrapping_key, [CKA_WRAP])[0]
            if can_wrap:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11WrapSymAsym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11WrapSymAsym):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_wrapping_key = ks.handle_dict.get(self.command.handle_of_wrapping_key)
        if handle_of_wrapping_key is None:  # we do not have the handle of the wrapping key yet.
            return NOT_APPLICABLE
        assert isinstance(handle_of_wrapping_key, CK_OBJECT_HANDLE)

        handle_of_key_to_be_wrapped = ks.handle_dict.get(self.command.handle_of_key_to_be_wrapped)
        if handle_of_key_to_be_wrapped is None:  # we do not have the handle of the key to be wrapped yet.
            return NOT_APPLICABLE
        assert isinstance(handle_of_key_to_be_wrapped, CK_OBJECT_HANDLE)

        try:
            wrapped_key = session.wrapKey(handle_of_wrapping_key, handle_of_key_to_be_wrapped, MechanismRSAPKCS1)

            if self.command.wrapped_key in ks.aenc_dict:  # terms can be derived in multiple ways
                assert bytes(wrapped_key) == ks.aenc_dict[self.command.wrapped_key]
            else:
                ks.aenc_dict[self.command.wrapped_key] = bytes(wrapped_key)
        except PyKCS11Error as e:
            # diagnosis
            can_wrap = session.getAttributeValue(handle_of_wrapping_key, [CKA_WRAP])[0]
            if can_wrap:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11WrapAsymSym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11WrapAsymSym):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_wrapping_key = ks.handle_dict.get(self.command.handle_of_wrapping_key)
        if handle_of_wrapping_key is None:  # we do not have the handle of the wrapping key yet.
            return NOT_APPLICABLE
        assert isinstance(handle_of_wrapping_key, CK_OBJECT_HANDLE)

        handle_of_key_to_be_wrapped = ks.handle_dict.get(self.command.handle_of_key_to_be_wrapped)
        if handle_of_key_to_be_wrapped is None:  # we do not have the handle of the key to be wrapped yet.
            return NOT_APPLICABLE
        assert isinstance(handle_of_key_to_be_wrapped, CK_OBJECT_HANDLE)

        try:
            wrapped_key = session.wrapKey(handle_of_wrapping_key, handle_of_key_to_be_wrapped, AES_GCM_MECHANISM)

            ewd = AESGCMEncryptionWithDigest.from_pkcs11_aes_gcm(bytes(wrapped_key), TAG_BYTES)

            if self.command.wrapped_key in ks.senc_dict:  # terms can be derived in multiple ways
                assert ewd == ks.senc_dict[self.command.wrapped_key]
            else:
                ks.senc_dict[self.command.wrapped_key] = ewd
        except PyKCS11Error as e:
            # diagnosis
            can_wrap = session.getAttributeValue(handle_of_wrapping_key, [CKA_WRAP])[0]
            if can_wrap:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11UnwrapSymSym(PyKCS11Command):
    UNWRAP_SYM_SYM_TEMPLATE = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_AES),
    ]

    def __init__(self, command: AbstractPKCS11UnwrapSymSym):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_unwrapping_key = ks.handle_dict.get(self.command.handle_of_unwrapping_key)
        if handle_of_unwrapping_key is None:  # we do not have the handle of the unwrapping key yet.
            return NOT_APPLICABLE
        assert isinstance(handle_of_unwrapping_key, CK_OBJECT_HANDLE)

        ewd = ks.senc_dict.get(self.command.key_to_be_unwrapped)
        if ewd is None:  # we do not have the key to be unwrapped yet.
            return NOT_APPLICABLE
        assert isinstance(ewd, AESGCMEncryptionWithDigest)

        key_to_be_unwrapped = bytes(ewd)
        try:
            handle_of_recovered_key = session.unwrapKey(handle_of_unwrapping_key,
                                                        key_to_be_unwrapped,
                                                        PyKCS11UnwrapSymSym.UNWRAP_SYM_SYM_TEMPLATE,
                                                        AES_GCM_MECHANISM)

            ks.handle_dict[self.command.handle_of_recovered_key] = handle_of_recovered_key
        except PyKCS11Error as e:
            # diagnosis
            can_unwrap = session.getAttributeValue(handle_of_unwrapping_key, [CKA_UNWRAP])[0]
            if can_unwrap:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11UnwrapSymAsym(PyKCS11Command):
    UNWRAP_SYM_ASYM_TEMPLATE = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_AES),
    ]

    def __init__(self, command: AbstractPKCS11UnwrapSymAsym):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_unwrapping_key = ks.handle_dict.get(self.command.handle_of_unwrapping_key)
        if handle_of_unwrapping_key is None:  # we do not have the handle of the unwrapping key yet.
            return NOT_APPLICABLE
        assert isinstance(handle_of_unwrapping_key, CK_OBJECT_HANDLE)

        key_to_be_unwrapped = ks.aenc_dict.get(self.command.key_to_be_unwrapped)
        if key_to_be_unwrapped is None:  # we do not have the key to be unwrapped yet.
            return NOT_APPLICABLE
        assert isinstance(key_to_be_unwrapped, bytes)

        try:
            handle_of_recovered_key = session.unwrapKey(handle_of_unwrapping_key,
                                                        key_to_be_unwrapped,
                                                        PyKCS11UnwrapSymAsym.UNWRAP_SYM_ASYM_TEMPLATE,
                                                        MechanismRSAPKCS1)

            ks.handle_dict[self.command.handle_of_recovered_key] = handle_of_recovered_key
        except PyKCS11Error as e:
            # diagnosis
            can_unwrap = session.getAttributeValue(handle_of_unwrapping_key, [CKA_UNWRAP])[0]
            if can_unwrap:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11UnwrapAsymSym(PyKCS11Command):
    UNWRAP_ASYM_SYM_TEMPLATE = [
        (CKA_CLASS, CKO_PRIVATE_KEY),
        (CKA_KEY_TYPE, CKK_RSA),
    ]

    def __init__(self, command: AbstractPKCS11UnwrapAsymSym):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_unwrapping_key = ks.handle_dict.get(self.command.handle_of_unwrapping_key)
        if handle_of_unwrapping_key is None:  # we do not have the handle of the unwrapping key yet.
            return NOT_APPLICABLE
        assert isinstance(handle_of_unwrapping_key, CK_OBJECT_HANDLE)

        ewd = ks.senc_dict.get(self.command.key_to_be_unwrapped)
        if ewd is None:  # we do not have the key to be unwrapped yet.
            return NOT_APPLICABLE
        assert isinstance(ewd, AESGCMEncryptionWithDigest)

        key_to_be_unwrapped = bytes(ewd)
        try:
            handle_of_recovered_key = session.unwrapKey(handle_of_unwrapping_key,
                                                        key_to_be_unwrapped,
                                                        PyKCS11UnwrapAsymSym.UNWRAP_ASYM_SYM_TEMPLATE,
                                                        AES_GCM_MECHANISM)

            ks.handle_dict[self.command.handle_of_recovered_key] = handle_of_recovered_key
        except PyKCS11Error as e:
            # diagnosis
            can_unwrap = session.getAttributeValue(handle_of_unwrapping_key, [CKA_UNWRAP])[0]
            if can_unwrap:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11EncryptSymSym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11EncryptSymSym):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_encryption_key = ks.handle_dict.get(self.command.handle_of_encryption_key)
        if handle_of_encryption_key is None:  # we do not have the handle of the encryption key yet.
            return NOT_APPLICABLE
        assert isinstance(handle_of_encryption_key, CK_OBJECT_HANDLE)

        key_to_be_encrypted = ks.secret_key_dict.get(self.command.key_to_be_encrypted)
        if key_to_be_encrypted is None:  # we do not have the key to be encrypted yet.
            return NOT_APPLICABLE
        assert isinstance(key_to_be_encrypted, bytes)

        try:
            encrypted_key = session.encrypt(handle_of_encryption_key, key_to_be_encrypted, AES_GCM_MECHANISM)

            ewd = AESGCMEncryptionWithDigest.from_pkcs11_aes_gcm(bytes(encrypted_key), TAG_BYTES)

            if self.command.encrypted_key in ks.senc_dict:  # terms can be derived in multiple ways
                assert ewd == ks.senc_dict[self.command.encrypted_key]
            else:
                ks.senc_dict[self.command.encrypted_key] = ewd
        except PyKCS11Error as e:
            # diagnosis
            can_encrypt = session.getAttributeValue(handle_of_encryption_key, [CKA_ENCRYPT])[0]
            if can_encrypt:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11EncryptSymAsym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11EncryptSymAsym):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_encryption_key = ks.handle_dict.get(self.command.handle_of_encryption_key)
        if handle_of_encryption_key is None:  # we do not have the handle of the encryption key yet.
            return NOT_APPLICABLE
        assert isinstance(handle_of_encryption_key, CK_OBJECT_HANDLE)

        key_to_be_encrypted = ks.secret_key_dict.get(self.command.key_to_be_encrypted)
        if key_to_be_encrypted is None:  # we do not have the key to be encrypted yet.
            return NOT_APPLICABLE
        assert isinstance(key_to_be_encrypted, bytes)

        try:
            encrypted_key = session.encrypt(handle_of_encryption_key, key_to_be_encrypted, MechanismRSAPKCS1)

            if self.command.encrypted_key in ks.senc_dict:  # terms can be derived in multiple ways
                # no, PKCS#1 v1.5 padding introduces randomness!
                # assert encrypted_key == ks.aenc_dict[self.command.encrypted_key]
                pass
            else:
                ks.aenc_dict[self.command.encrypted_key] = bytes(encrypted_key)
        except PyKCS11Error as e:
            # diagnosis
            can_encrypt = session.getAttributeValue(handle_of_encryption_key, [CKA_ENCRYPT])[0]
            if can_encrypt:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11DecryptSymSym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11DecryptSymSym):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_decryption_key = ks.handle_dict.get(self.command.handle_of_decryption_key)
        if handle_of_decryption_key is None:  # we do not have the handle of the decryption key yet.
            return NOT_APPLICABLE
        assert isinstance(handle_of_decryption_key, CK_OBJECT_HANDLE)

        ewd = ks.senc_dict.get(self.command.key_to_be_decrypted)
        if ewd is None:  # we do not have the key to be decrypted yet.
            return NOT_APPLICABLE
        assert isinstance(ewd, AESGCMEncryptionWithDigest)

        key_to_be_decrypted = bytes(ewd)
        try:
            decrypted_key = session.decrypt(handle_of_decryption_key, key_to_be_decrypted, AES_GCM_MECHANISM)

            if self.command.decrypted_key in ks.secret_key_dict:  # terms can be derived in multiple ways
                assert bytes(decrypted_key) == ks.secret_key_dict[self.command.decrypted_key]
            else:
                ks.secret_key_dict[self.command.decrypted_key] = bytes(decrypted_key)
        except PyKCS11Error as e:
            # diagnosis
            can_decrypt = session.getAttributeValue(handle_of_decryption_key, [CKA_DECRYPT])[0]
            if can_decrypt:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11DecryptSymAsym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11DecryptSymAsym):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_decryption_key = ks.handle_dict.get(self.command.handle_of_decryption_key)
        if handle_of_decryption_key is None:  # we do not have the handle of the decryption key yet.
            return NOT_APPLICABLE
        assert isinstance(handle_of_decryption_key, CK_OBJECT_HANDLE)

        key_to_be_decrypted = ks.aenc_dict.get(self.command.key_to_be_decrypted)
        if key_to_be_decrypted is None:  # we do not have the key to be decrypted yet.
            return NOT_APPLICABLE
        assert isinstance(key_to_be_decrypted, bytes)

        try:
            decrypted_key = session.decrypt(handle_of_decryption_key, key_to_be_decrypted, MechanismRSAPKCS1)

            if self.command.decrypted_key in ks.secret_key_dict:  # terms can be derived in multiple ways
                assert bytes(decrypted_key) == ks.secret_key_dict[self.command.decrypted_key]
            else:
                ks.secret_key_dict[self.command.decrypted_key] = bytes(decrypted_key)
        except PyKCS11Error as e:
            # diagnosis
            can_decrypt = session.getAttributeValue(handle_of_decryption_key, [CKA_DECRYPT])[0]
            if can_decrypt:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11DeduceEncryptSymSym(PyKCS11Command):
    def __init__(self, command: AbstractDeduceEncryptSymSym):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        encryption_key = ks.secret_key_dict.get(self.command.encryption_key)
        if encryption_key is None:  # we do not have the encryption key yet.
            return NOT_APPLICABLE
        assert isinstance(encryption_key, bytes)

        key_to_be_encrypted = ks.secret_key_dict.get(self.command.key_to_be_encrypted)
        if key_to_be_encrypted is None:  # we do not have the key to be encrypted yet.
            return NOT_APPLICABLE
        assert isinstance(key_to_be_encrypted, bytes)

        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=IV, mac_len=TAG_BYTES)
        cipher = cipher.update(AAD)

        encrypted_key, digest = cipher.encrypt_and_digest(key_to_be_encrypted)

        ewd = AESGCMEncryptionWithDigest(encrypted_key, digest)

        if self.command.encrypted_key in ks.senc_dict:  # terms can be derived in multiple ways
            assert ewd == ks.senc_dict[self.command.encrypted_key]
        else:
            ks.senc_dict[self.command.encrypted_key] = ewd

        return OP_OK


class PyKCS11DeduceEncryptSymAsym(PyKCS11Command):
    def __init__(self, command: AbstractDeduceEncryptSymAsym):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        encryption_key = ks.public_key_dict.get(self.command.encryption_key)
        if encryption_key is None:  # we do not have the encryption key yet.
            return NOT_APPLICABLE
        assert isinstance(encryption_key, RsaKey)

        key_to_be_encrypted = ks.secret_key_dict.get(self.command.key_to_be_encrypted)
        if key_to_be_encrypted is None:  # we do not have the key to be encrypted yet.
            return NOT_APPLICABLE
        assert isinstance(key_to_be_encrypted, bytes)

        cipher = PKCS1_v1_5.new(encryption_key)

        encrypted_key = cipher.encrypt(key_to_be_encrypted)

        if self.command.encrypted_key in ks.aenc_dict:  # terms can be derived in multiple ways
            # no, PKCS#1 v1.5 padding introduces randomness!
            # assert encrypted_key == ks.aenc_dict[self.command.encrypted_key]
            pass
        else:
            ks.aenc_dict[self.command.encrypted_key] = encrypted_key

        return OP_OK


class PyKCS11DeduceDecryptSymSym(PyKCS11Command):
    def __init__(self, command: AbstractDeduceDecryptSymSym, pointed_by: list[int]):
        self.command = command
        self.pointed_by = pointed_by

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        decryption_key = ks.secret_key_dict.get(self.command.decryption_key)
        if decryption_key is None:  # we do not have the decryption key yet.
            return NOT_APPLICABLE
        assert isinstance(decryption_key, bytes)

        ewd = ks.senc_dict.get(self.command.key_to_be_decrypted)
        if ewd is None:  # we do not have the key to be decrypted yet.
            return NOT_APPLICABLE
        assert isinstance(ewd, AESGCMEncryptionWithDigest)

        decipher = AES.new(decryption_key, AES.MODE_GCM, nonce=IV, mac_len=TAG_BYTES)
        decipher = decipher.update(AAD)

        decrypted_key = decipher.decrypt_and_verify(ewd.encryption, ewd.digest)

        if self.command.decrypted_key in ks.secret_key_dict:  # terms can be derived in multiple ways
            assert decrypted_key == ks.secret_key_dict[self.command.decrypted_key]
        else:
            ks.secret_key_dict[self.command.decrypted_key] = decrypted_key

        for handle_of_encryption_key in self.pointed_by:
            try:
                encryption_key = ks.handle_dict.get(handle_of_encryption_key)
                if encryption_key is None:
                    continue
                # the encryption key we are going to use can or cannot have CKA_ENCRYPT set at this point.
                # if CKA_ENCRYPT is not set, then we set it temporarily, so that we can use the encryption key for encrypting.
                can_encrypt = session.getAttributeValue(encryption_key, [CKA_ENCRYPT])[0]
                session.setAttributeValue(encryption_key, [(CKA_ENCRYPT, CK_TRUE)])
                encrypted_by_pkcs11 = session.encrypt(encryption_key, b"hello, world", AES_GCM_MECHANISM)
                if not can_encrypt:
                    # if CKA_ENCRYPT was not set, then we unset it.
                    session.setAttributeValue(encryption_key, [(CKA_ENCRYPT, CK_FALSE)])

                cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce=IV, mac_len=TAG_BYTES)
                cipher = cipher.update(AAD)
                encrypted_by_cipher, digest = cipher.encrypt_and_digest(b"hello, world")

                # the two ciphertexts should be the same.
                assert bytes(encrypted_by_pkcs11) == encrypted_by_cipher + digest
            except PyKCS11Error as e:
                print(self.command, e, file=sys.stderr)
                # return OP_FAIL

        return OP_OK


class PyKCS11DeduceDecryptSymAsym(PyKCS11Command):
    def __init__(self, command: AbstractDeduceDecryptSymAsym, pointed_by: list[int]):
        self.command = command
        self.pointed_by = pointed_by

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        decryption_key = ks.private_key_dict.get(self.command.decryption_key)
        if decryption_key is None:  # we do not have the decryption key yet.
            return NOT_APPLICABLE
        assert isinstance(decryption_key, RsaKey)

        key_to_be_decrypted = ks.aenc_dict.get(self.command.key_to_be_decrypted)
        if key_to_be_decrypted is None:
            return NOT_APPLICABLE
        assert isinstance(key_to_be_decrypted, bytes)

        decipher = PKCS1_v1_5.new(decryption_key)

        decrypted_key = decipher.decrypt(key_to_be_decrypted, None, 0)
        assert decrypted_key is not None

        if self.command.decrypted_key in ks.secret_key_dict:  # terms can be derived in multiple ways
            assert decrypted_key == ks.secret_key_dict[self.command.decrypted_key]
        else:
            ks.secret_key_dict[self.command.decrypted_key] = decrypted_key

        for handle_of_encryption_key in self.pointed_by:
            try:
                encryption_key = ks.handle_dict.get(handle_of_encryption_key)
                if encryption_key is None:
                    continue
                # the encryption key we are going to use can or cannot have CKA_ENCRYPT set at this point.
                # if CKA_ENCRYPT is not set, then we set it temporarily, so that we can use the encryption key for encrypting.
                can_encrypt = session.getAttributeValue(encryption_key, [CKA_ENCRYPT])[0]
                session.setAttributeValue(encryption_key, [(CKA_ENCRYPT, CK_TRUE)])
                encrypted_by_pkcs11 = session.encrypt(encryption_key, b"hello, world", AES_GCM_MECHANISM)
                if not can_encrypt:
                    # if CKA_ENCRYPT was not set, then we unset it.
                    session.setAttributeValue(encryption_key, [(CKA_ENCRYPT, CK_FALSE)])

                cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce=IV, mac_len=TAG_BYTES)
                cipher = cipher.update(AAD)
                encrypted_by_cipher, digest = cipher.encrypt_and_digest(b"hello, world")

                # the two ciphertexts should be the same.
                assert bytes(encrypted_by_pkcs11) == encrypted_by_cipher + digest
                print(self.command, "pointed by:", handle_of_encryption_key, "check passed")
            except PyKCS11Error as e:
                print(self.command, e, file=sys.stderr)
                # return OP_FAIL

        return OP_OK


class PyKCS11DeduceDecryptAsymSym(PyKCS11Command):
    CLEAR_TEXT = "hello, world!"

    def __init__(self, command: AbstractDeduceDecryptAsymSym, pointed_by: list[int]):
        self.command = command
        self.pointed_by = pointed_by

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        decryption_key = ks.secret_key_dict.get(self.command.decryption_key)
        if decryption_key is None:  # we do not have the decryption key yet.
            return NOT_APPLICABLE
        assert isinstance(decryption_key, bytes)

        ewd = ks.aenc_dict.get(self.command.key_to_be_decrypted)
        if ewd is None:  # we do not have the key to be decrypted yet.
            return NOT_APPLICABLE
        assert isinstance(ewd, AESGCMEncryptionWithDigest)

        decipher = AES.new(decryption_key, AES.MODE_GCM, nonce=IV, mac_len=TAG_BYTES)
        decipher = decipher.update(AAD)

        decrypted_key = decipher.decrypt_and_verify(ewd.encryption, ewd.digest)
        private_key = RSA.import_key(decrypted_key)

        if self.command.decrypted_key in ks.secret_key_dict:  # terms can be derived in multiple ways
            # TODO: check private rsa key equality
            pass
        else:
            ks.private_key_dict[self.command.decrypted_key] = private_key

        for handle_of_encryption_key in self.pointed_by:
            try:
                encryption_key = ks.handle_dict.get(handle_of_encryption_key)
                if encryption_key is None:
                    continue
                # the encryption key we are going to use can or cannot have CKA_ENCRYPT set at this point.
                # if CKA_ENCRYPT is not set, then we set it temporarily, so that we can use the encryption key for encrypting.
                can_encrypt = session.getAttributeValue(encryption_key, [CKA_ENCRYPT])[0]
                session.setAttributeValue(encryption_key, [(CKA_ENCRYPT, CK_TRUE)])
                encrypted_by_pkcs11 = session.encrypt(encryption_key, PyKCS11DeduceDecryptAsymSym.CLEAR_TEXT.encode(),
                                                      AES_GCM_MECHANISM)
                if not can_encrypt:
                    # if CKA_ENCRYPT was not set, then we unset it.
                    session.setAttributeValue(encryption_key, [(CKA_ENCRYPT, CK_FALSE)])

                decipher = PKCS1_v1_5.new(private_key)
                encrypted_by_pkcs11_then_decrypted_by_cipher = decipher.decrypt(bytes(encrypted_by_pkcs11), None,
                                                                                len(PyKCS11DeduceDecryptAsymSym.CLEAR_TEXT))
                assert encrypted_by_pkcs11_then_decrypted_by_cipher is not None

                assert PyKCS11DeduceDecryptAsymSym.CLEAR_TEXT == encrypted_by_pkcs11_then_decrypted_by_cipher.decode()
            except PyKCS11Error as e:
                print(self.command, e, file=sys.stderr)
                # return OP_FAIL

        return OP_OK


class PyKCS11SetWrap(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11SetWrap):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_WRAP, CK_TRUE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11UnsetWrap(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11UnsetWrap):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_WRAP, CK_FALSE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11SetUnwrap(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11SetUnwrap):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_UNWRAP, CK_TRUE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11UnsetUnwrap(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11UnsetUnwrap):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_UNWRAP, CK_FALSE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11SetEncrypt(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11SetEncrypt):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_ENCRYPT, CK_TRUE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11UnsetEncrypt(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11UnsetEncrypt):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_ENCRYPT, CK_FALSE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11SetDecrypt(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11SetDecrypt):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_DECRYPT, CK_TRUE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11UnsetDecrypt(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11UnsetDecrypt):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_DECRYPT, CK_FALSE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK
