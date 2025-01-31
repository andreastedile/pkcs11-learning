import abc

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad
from pkcs11 import SecretKey, Mechanism, Attribute, ObjectClass, KeyType, \
    WrapMixin, UnwrapMixin, EncryptMixin, DecryptMixin, \
    PKCS11Error

from my_types import PKCS11_Wrap, PKCS11_Unwrap, PKCS11_Encrypt, PKCS11_Decrypt, IntruderDecrypt

NOT_APPLICABLE = "not-applicable"
OP_FAIL = "op-fail"
OP_OK = "op-ok"


# noinspection PyPep8Naming
class PKCS11_SUL_Input(abc.ABC):
    @abc.abstractmethod
    def execute(self, handles_knowledge_set: dict[int, SecretKey], key_knowledge_set: dict[int, bytes]) -> str:
        raise NotImplementedError

    def __repr__(self):
        return str(self)


# noinspection PyPep8Naming
class PKCS11_SUL_Wrap(PKCS11_SUL_Input):

    def __init__(self, implication: PKCS11_Wrap):
        self.implication = implication

    def __str__(self):
        return str(self.implication)

    def execute(self, handles_knowledge_set: dict[int, SecretKey], key_knowledge_set: dict[int, bytes]) -> str:
        # noinspection PyTypeChecker
        handle_of_wrapping_key = handles_knowledge_set.get(self.implication.arguments.handle_of_wrapping_key)
        if handle_of_wrapping_key is None:  # we do not have the handle of the wrapping_key yet.
            return NOT_APPLICABLE

        handle_of_key_to_be_wrapped = handles_knowledge_set.get(self.implication.arguments.handle_of_key_to_be_wrapped)
        if handle_of_key_to_be_wrapped is None:  # we do not have the handle of the key to be wrapped yet.
            return NOT_APPLICABLE

        try:
            handle_of_wrapping_key: WrapMixin
            wrapped_key = handle_of_wrapping_key.wrap_key(handle_of_key_to_be_wrapped, mechanism=Mechanism.DES3_ECB)
            if self.implication.wrapped_key in key_knowledge_set:  # terms can be derived in multiple ways
                assert key_knowledge_set[self.implication.wrapped_key] == wrapped_key
            else:
                key_knowledge_set[self.implication.wrapped_key] = wrapped_key
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


# noinspection PyPep8Naming
class PKCS11_SUL_Unwrap(PKCS11_SUL_Input):
    def __init__(self, implication: PKCS11_Unwrap):
        self.implication = implication

    def __str__(self):
        return str(self.implication)

    def execute(self, handles_knowledge_set: dict[int, SecretKey], key_knowledge_set: dict[int, bytes]) -> str:
        # noinspection PyTypeChecker
        handle_of_unwrapping_key = handles_knowledge_set.get(self.implication.arguments.handle_of_unwrapping_key)
        if handle_of_unwrapping_key is None:  # we do not have the handle of the unwrapping key yet.
            return NOT_APPLICABLE

        key_to_be_unwrapped = key_knowledge_set.get(self.implication.arguments.key_to_be_unwrapped)
        if key_to_be_unwrapped is None:  # we do not have the key to be unwrapped yet.
            return NOT_APPLICABLE

        try:
            handle_of_unwrapping_key: UnwrapMixin
            handle_of_recovered_key = handle_of_unwrapping_key.unwrap_key(ObjectClass.SECRET_KEY,
                                                                          KeyType.DES3,
                                                                          key_to_be_unwrapped)
            if self.implication.handle_of_recovered_key in handles_knowledge_set:  # terms can be derived in multiple ways
                # cannot assert knowledge_set[self.result_id] == result, as this would compare two memory addresses
                pass
            else:
                # noinspection PyTypeChecker
                handles_knowledge_set[self.implication.handle_of_recovered_key] = handle_of_recovered_key
            return OP_OK
        except PKCS11Error as _e:
            # print(self, e)
            return OP_FAIL


# noinspection PyPep8Naming
class PKCS11_SUL_Encrypt(PKCS11_SUL_Input):
    def __init__(self, implication: PKCS11_Encrypt):
        self.implication = implication

    def __str__(self):
        return str(self.implication)

    def execute(self, handles_knowledge_set: dict[int, SecretKey], key_knowledge_set: dict[int, bytes]) -> str:
        # noinspection PyTypeChecker
        handle_of_encryption_key = handles_knowledge_set.get(self.implication.arguments.handle_of_encryption_key)
        if handle_of_encryption_key is None:  # we do not have the handle of the encryption key yet.
            return NOT_APPLICABLE

        key_to_be_encrypted = key_knowledge_set.get(self.implication.arguments.key_to_be_encrypted)
        if key_to_be_encrypted is None:  # we do not have the key to be encrypted yet.
            return NOT_APPLICABLE

        try:
            handle_of_encryption_key: EncryptMixin
            encrypted_key = handle_of_encryption_key.encrypt(key_to_be_encrypted, mechanism=Mechanism.DES3_ECB)
            if self.implication.encrypted_key in key_knowledge_set:  # terms can be derived in multiple ways
                assert key_knowledge_set[self.implication.encrypted_key] == encrypted_key
            else:
                key_knowledge_set[self.implication.encrypted_key] = encrypted_key
            return OP_OK
        except PKCS11Error as _e:
            # print(self, e)
            return OP_FAIL


# noinspection PyPep8Naming
class PKCS11_SUL_Decrypt(PKCS11_SUL_Input):
    def __init__(self, implication: PKCS11_Decrypt):
        self.implication = implication

    def __str__(self):
        return str(self.implication)

    def execute(self, handles_knowledge_set: dict[int, SecretKey], key_knowledge_set: dict[int, bytes]) -> str:
        # noinspection PyTypeChecker
        handle_of_decryption_key = handles_knowledge_set.get(self.implication.arguments.handle_of_decryption_key)
        if handle_of_decryption_key is None:  # we do not have the handle of the decryption key yet.
            return NOT_APPLICABLE

        key_to_be_decrypted = key_knowledge_set.get(self.implication.arguments.key_to_be_decrypted)
        if key_to_be_decrypted is None:  # we do not have the key to be decrypted yet.
            return NOT_APPLICABLE

        try:
            handle_of_decryption_key: DecryptMixin
            decrypted_key = handle_of_decryption_key.decrypt(key_to_be_decrypted, mechanism=Mechanism.DES3_ECB)
            if self.implication.decrypted_key in key_knowledge_set:  # terms can be derived in multiple ways
                assert key_knowledge_set[self.implication.decrypted_key] == decrypted_key
            else:
                key_knowledge_set[self.implication.decrypted_key] = decrypted_key
            return OP_OK
        except PKCS11Error as _e:
            # print(self, e)
            return OP_FAIL


# noinspection PyPep8Naming
class PKCS11_SUL_IntruderDecrypt(PKCS11_SUL_Input):
    def __init__(self, implication: IntruderDecrypt, pointed_by: list[int]):
        self.implication = implication
        self.pointed_by = pointed_by

    def __str__(self):
        return str(self.implication)

    def execute(self, handles_knowledge_set: dict[int, SecretKey], key_knowledge_set: dict[int, bytes]) -> str:
        decryption_key = key_knowledge_set.get(self.implication.arguments.decryption_key)
        if decryption_key is None:  # we do not have the decryption key yet.
            return NOT_APPLICABLE

        key_to_be_decrypted = key_knowledge_set.get(self.implication.arguments.key_to_be_decrypted)
        if key_to_be_decrypted is None:  # we do not have the key to be decrypted yet.
            return NOT_APPLICABLE

        cipher = DES3.new(decryption_key, DES3.MODE_ECB)
        decrypted_key = cipher.decrypt(key_to_be_decrypted)
        if self.implication.decrypted_key in key_knowledge_set:  # terms can be derived in multiple ways
            assert key_knowledge_set[self.implication.decrypted_key] == decrypted_key

            padded = pad(b"hello, world!", 32)
            # we create a cipher with key we just decrypted and encrypt a text with it.
            cipher1 = DES3.new(decrypted_key, DES3.MODE_ECB)
            ciphertext1 = cipher1.encrypt(padded)
            for handle_of_encryption_key in self.pointed_by:
                try:
                    # we use the existing handles to that key to encrypt the same text.
                    # noinspection PyTypeChecker
                    encryption_key: EncryptMixin = handles_knowledge_set.get(handle_of_encryption_key)
                    ciphertext2: bytes = encryption_key.encrypt(padded, mechanism=Mechanism.DES3_ECB)
                    # the two ciphertexts should be the same.
                    assert ciphertext1 == ciphertext2
                except PKCS11Error:
                    pass
            if self.implication.decrypted_key in key_knowledge_set:  # terms can be derived in multiple ways
                assert key_knowledge_set[self.implication.decrypted_key] == decrypted_key
            else:
                key_knowledge_set[self.implication.decrypted_key] = decrypted_key
        else:
            key_knowledge_set[self.implication.decrypted_key] = decrypted_key
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_SetWrap(PKCS11_SUL_Input):
    def __init__(self, handle: int):
        self.handle = handle

    def __str__(self):
        return f"SetWrap({self.handle})"

    def execute(self, handles_knowledge_set: dict[int, SecretKey], key_knowledge_set: dict[int, bytes]) -> str:
        handle = handles_knowledge_set.get(self.handle)
        if handle is None:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        handle[Attribute.WRAP] = True
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_UnsetWrap(PKCS11_SUL_Input):
    def __init__(self, handle: int):
        self.handle = handle

    def __str__(self):
        return f"UnsetWrap({self.handle})"

    def execute(self, handles_knowledge_set: dict[int, SecretKey], key_knowledge_set: dict[int, bytes]) -> str:
        handle = handles_knowledge_set.get(self.handle)
        if handle is None:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        handle[Attribute.WRAP] = False
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_SetUnwrap(PKCS11_SUL_Input):
    def __init__(self, handle: int):
        self.handle = handle

    def __str__(self):
        return f"SetUnwrap({self.handle})"

    def execute(self, handles_knowledge_set: dict[int, SecretKey], key_knowledge_set: dict[int, bytes]) -> str:
        handle = handles_knowledge_set.get(self.handle)
        if handle is None:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        handle[Attribute.UNWRAP] = True
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_UnsetUnwrap(PKCS11_SUL_Input):
    def __init__(self, handle: int):
        self.handle = handle

    def __str__(self):
        return f"UnsetUnwrap({self.handle})"

    def execute(self, handles_knowledge_set: dict[int, SecretKey], key_knowledge_set: dict[int, bytes]) -> str:
        handle = handles_knowledge_set.get(self.handle)
        if handle is None:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        handle[Attribute.UNWRAP] = False
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_SetEncrypt(PKCS11_SUL_Input):
    def __init__(self, handle: int):
        self.handle = handle

    def __str__(self):
        return f"SetEncrypt({self.handle})"

    def execute(self, handles_knowledge_set: dict[int, SecretKey], key_knowledge_set: dict[int, bytes]) -> str:
        handle = handles_knowledge_set.get(self.handle)
        if handle is None:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        handle[Attribute.ENCRYPT] = True
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_UnsetEncrypt(PKCS11_SUL_Input):
    def __init__(self, handle: int):
        self.handle = handle

    def __str__(self):
        return f"UnsetEncrypt({self.handle})"

    def execute(self, handles_knowledge_set: dict[int, SecretKey], key_knowledge_set: dict[int, bytes]) -> str:
        handle = handles_knowledge_set.get(self.handle)
        if handle is None:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        handle[Attribute.ENCRYPT] = False
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_SetDecrypt(PKCS11_SUL_Input):
    def __init__(self, handle: int):
        self.handle = handle

    def __str__(self):
        return f"SetDecrypt({self.handle})"

    def execute(self, handles_knowledge_set: dict[int, SecretKey], key_knowledge_set: dict[int, bytes]) -> str:
        handle = handles_knowledge_set.get(self.handle)
        if handle is None:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        handle[Attribute.DECRYPT] = True
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_UnsetDecrypt(PKCS11_SUL_Input):
    def __init__(self, handle: int):
        self.handle = handle

    def __str__(self):
        return f"UnsetDecrypt({self.handle})"

    def execute(self, handles_knowledge_set: dict[int, SecretKey], key_knowledge_set: dict[int, bytes]) -> str:
        handle = handles_knowledge_set.get(self.handle)
        if handle is None:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        handle[Attribute.DECRYPT] = False
        return OP_OK
