import abc

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad
from pkcs11 import SecretKey, Mechanism, Attribute, ObjectClass, KeyType, \
    WrapMixin, UnwrapMixin, EncryptMixin, DecryptMixin, \
    PKCS11Error

from abstract_pkcs11_commands import \
    AbstractPKCS11Wrap, \
    AbstractPKCS11Unwrap, \
    AbstractPKCS11Encrypt, \
    AbstractPKCS11Decrypt, \
    AbstractDeduceDecrypt, \
    AbstractPKCS11SetWrap, \
    AbstractPKCS11SetUnwrap, \
    AbstractPKCS11SetEncrypt, \
    AbstractPKCS11SetDecrypt, \
    AbstractPKCS11UnsetWrap, \
    AbstractPKCS11UnsetUnwrap, \
    AbstractPKCS11UnsetEncrypt, \
    AbstractPKCS11UnsetDecrypt, \
    OP_OK, OP_FAIL, NOT_APPLICABLE
from python_pkcs11_knowledge_set import PythonPKCS11KnowledgeSet


class PythonPKCS11Command(abc.ABC):
    @abc.abstractmethod
    def execute(self, ks: PythonPKCS11KnowledgeSet) -> str:
        raise NotImplementedError

    def __repr__(self):
        return str(self)

    def __str__(self):
        raise NotImplementedError


class PythonPKCS11WrapSymSym(PythonPKCS11Command):

    def __init__(self, command: AbstractPKCS11Wrap):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PythonPKCS11KnowledgeSet) -> str:
        handle_of_wrapping_key = ks.handle_of_secret_key_dict.get(self.command.handle_of_wrapping_key)
        if handle_of_wrapping_key is None:  # we do not have the handle of the wrapping key yet.
            return NOT_APPLICABLE

        handle_of_key_to_be_wrapped = ks.handle_of_secret_key_dict.get(self.command.handle_of_key_to_be_wrapped)
        if handle_of_key_to_be_wrapped is None:  # we do not have the handle of the key to be wrapped yet.
            return NOT_APPLICABLE

        try:
            handle_of_wrapping_key: WrapMixin
            wrapped_key = handle_of_wrapping_key.wrap_key(handle_of_key_to_be_wrapped, mechanism=Mechanism.DES3_ECB)
            if self.command.wrapped_key in ks.senc_dict:  # terms can be derived in multiple ways
                assert ks.senc_dict[self.command.wrapped_key] == wrapped_key
            else:
                ks.senc_dict[self.command.wrapped_key] = wrapped_key
            return OP_OK
        except PKCS11Error as _e:
            # from pkcs11 import KeyUnextractable
            # from pkcs11 import KeyNotWrappable
            # if isinstance(e, KeyUnextractable):
            #     pass
            # elif isinstance(e, KeyNotWrappable):
            #     pass
            # else:
            # #     print(self, e)
            #     pass
            return OP_FAIL


class PythonPKCS11UnwrapSymSym(PythonPKCS11Command):
    def __init__(self, command: AbstractPKCS11Unwrap):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PythonPKCS11KnowledgeSet) -> str:
        handle_of_unwrapping_key = ks.handle_of_secret_key_dict.get(self.command.handle_of_unwrapping_key)
        if handle_of_unwrapping_key is None:  # we do not have the handle of the unwrapping key yet.
            return NOT_APPLICABLE

        key_to_be_unwrapped = ks.senc_dict.get(self.command.key_to_be_unwrapped)
        if key_to_be_unwrapped is None:  # we do not have the key to be unwrapped yet.
            return NOT_APPLICABLE

        try:
            handle_of_unwrapping_key: UnwrapMixin
            handle_of_recovered_key = handle_of_unwrapping_key.unwrap_key(ObjectClass.SECRET_KEY,
                                                                          KeyType.DES3,
                                                                          key_to_be_unwrapped)
            if self.command.handle_of_recovered_key in ks.handle_of_secret_key_dict:  # terms can be derived in multiple ways
                # cannot assert knowledge_set[self.result_id] == result, as this would compare two memory addresses
                pass
            else:
                ks.handle_of_secret_key_dict[self.command.handle_of_recovered_key] = handle_of_recovered_key
            return OP_OK
        except PKCS11Error as _e:
            # print(self, e)
            return OP_FAIL


class PythonPKCS11EncryptSymSym(PythonPKCS11Command):
    def __init__(self, command: AbstractPKCS11Encrypt):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PythonPKCS11KnowledgeSet) -> str:
        handle_of_encryption_key = ks.handle_of_secret_key_dict.get(self.command.handle_of_encryption_key)
        if handle_of_encryption_key is None:  # we do not have the handle of the encryption key yet.
            return NOT_APPLICABLE

        key_to_be_encrypted = ks.secret_key_dict.get(self.command.key_to_be_encrypted)
        if key_to_be_encrypted is None:  # we do not have the key to be encrypted yet.
            return NOT_APPLICABLE

        try:
            handle_of_encryption_key: EncryptMixin
            encrypted_key = handle_of_encryption_key.encrypt(key_to_be_encrypted, mechanism=Mechanism.DES3_ECB)
            if self.command.encrypted_key in ks.senc_dict:  # terms can be derived in multiple ways
                assert ks.senc_dict[self.command.encrypted_key] == encrypted_key
            else:
                ks.senc_dict[self.command.encrypted_key] = encrypted_key
            return OP_OK
        except PKCS11Error as _e:
            # print(self, e)
            return OP_FAIL


class PythonPKCS11DecryptSymSym(PythonPKCS11Command):
    def __init__(self, command: AbstractPKCS11Decrypt):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PythonPKCS11KnowledgeSet) -> str:
        handle_of_decryption_key = ks.handle_of_secret_key_dict.get(self.command.handle_of_decryption_key)
        if handle_of_decryption_key is None:  # we do not have the handle of the decryption key yet.
            return NOT_APPLICABLE

        key_to_be_decrypted = ks.senc_dict.get(self.command.key_to_be_decrypted)
        if key_to_be_decrypted is None:  # we do not have the key to be decrypted yet.
            return NOT_APPLICABLE

        try:
            handle_of_decryption_key: DecryptMixin
            decrypted_key = handle_of_decryption_key.decrypt(key_to_be_decrypted, mechanism=Mechanism.DES3_ECB)
            if self.command.decrypted_key in ks.secret_key_dict:  # terms can be derived in multiple ways
                assert ks.secret_key_dict[self.command.decrypted_key] == decrypted_key
            else:
                ks.secret_key_dict[self.command.decrypted_key] = decrypted_key
            return OP_OK
        except PKCS11Error as _e:
            # print(self, e)
            return OP_FAIL


class PythonPKCS11DeduceDecryptSymSym(PythonPKCS11Command):
    def __init__(self, command: AbstractDeduceDecrypt, pointed_by: list[int]):
        self.command = command
        self.pointed_by = pointed_by

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PythonPKCS11KnowledgeSet) -> str:
        decryption_key = ks.secret_key_dict.get(self.command.decryption_key)
        if decryption_key is None:  # we do not have the decryption key yet.
            return NOT_APPLICABLE

        key_to_be_decrypted = ks.senc_dict.get(self.command.key_to_be_decrypted)
        if key_to_be_decrypted is None:  # we do not have the key to be decrypted yet.
            return NOT_APPLICABLE

        cipher = DES3.new(decryption_key, DES3.MODE_ECB)
        decrypted_key = cipher.decrypt(key_to_be_decrypted)
        if self.command.decrypted_key in ks.secret_key_dict:  # terms can be derived in multiple ways
            assert ks.secret_key_dict[self.command.decrypted_key] == decrypted_key

            padded = pad(b"hello, world!", 32)
            # we create a cipher with key we just decrypted and encrypt a text with it.
            cipher1 = DES3.new(decrypted_key, DES3.MODE_ECB)
            ciphertext1 = cipher1.encrypt(padded)
            for handle_of_encryption_key in self.pointed_by:
                try:
                    # we use the existing handles to that key to encrypt the same text.
                    encryption_key: EncryptMixin = ks.handle_of_secret_key_dict.get(handle_of_encryption_key)
                    ciphertext2: bytes = encryption_key.encrypt(padded, mechanism=Mechanism.DES3_ECB)
                    # the two ciphertexts should be the same.
                    assert ciphertext1 == ciphertext2
                except PKCS11Error:
                    pass
            if self.command.decrypted_key in ks.secret_key_dict:  # terms can be derived in multiple ways
                assert ks.secret_key_dict[self.command.decrypted_key] == decrypted_key
            else:
                ks.secret_key_dict[self.command.decrypted_key] = decrypted_key
        else:
            ks.secret_key_dict[self.command.decrypted_key] = decrypted_key
        return OP_OK


class PythonPKCS11SetWrap(PythonPKCS11Command):
    def __init__(self, command: AbstractPKCS11SetWrap):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PythonPKCS11KnowledgeSet) -> str:
        handle = ks.handle_of_secret_key_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        handle[Attribute.WRAP] = True
        return OP_OK


class PythonPKCS11UnsetWrap(PythonPKCS11Command):
    def __init__(self, command: AbstractPKCS11UnsetWrap):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PythonPKCS11KnowledgeSet) -> str:
        handle = ks.handle_of_secret_key_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        handle[Attribute.WRAP] = False
        return OP_OK


class PythonPKCS11SetUnwrap(PythonPKCS11Command):
    def __init__(self, command: AbstractPKCS11SetUnwrap):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PythonPKCS11KnowledgeSet) -> str:
        handle = ks.handle_of_secret_key_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        handle[Attribute.UNWRAP] = True
        return OP_OK


class PythonPKCS11UnsetUnwrap(PythonPKCS11Command):
    def __init__(self, command: AbstractPKCS11UnsetUnwrap):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PythonPKCS11KnowledgeSet) -> str:
        handle = ks.handle_of_secret_key_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        handle[Attribute.UNWRAP] = False
        return OP_OK


class PythonPKCS11SetEncrypt(PythonPKCS11Command):
    def __init__(self, command: AbstractPKCS11SetEncrypt):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PythonPKCS11KnowledgeSet) -> str:
        handle = ks.handle_of_secret_key_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        handle[Attribute.ENCRYPT] = True
        return OP_OK


class PythonPKCS11UnsetEncrypt(PythonPKCS11Command):
    def __init__(self, command: AbstractPKCS11UnsetEncrypt):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PythonPKCS11KnowledgeSet) -> str:
        handle = ks.handle_of_secret_key_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        handle[Attribute.ENCRYPT] = False
        return OP_OK


class PythonPKCS11SetDecrypt(PythonPKCS11Command):
    def __init__(self, command: AbstractPKCS11SetDecrypt):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PythonPKCS11KnowledgeSet) -> str:
        handle = ks.handle_of_secret_key_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        handle[Attribute.DECRYPT] = True
        return OP_OK


class PythonPKCS11UnsetDecrypt(PythonPKCS11Command):
    def __init__(self, command: AbstractPKCS11UnsetDecrypt):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PythonPKCS11KnowledgeSet) -> str:
        handle = ks.handle_of_secret_key_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        handle[Attribute.DECRYPT] = False
        return OP_OK
