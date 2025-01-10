import abc
import re

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad
from pkcs11 import SecretKey, Mechanism, Attribute, ObjectClass, KeyType, \
    WrapMixin, UnwrapMixin, EncryptMixin, DecryptMixin, \
    PKCS11Error
from pysmt.fnode import FNode
from pysmt.shortcuts import Symbol

from grammar.my_types import HandleNode, KeyNode

NOT_APPLICABLE = "not-applicable"
OP_FAIL = "op-fail"
OP_OK = "op-ok"

regex = re.compile(r"^(?:\d+|(wrap|unwrap|encrypt|decrypt|intruder_decrypt)\((\d+),(\d+)\)=(\d+))$")


# noinspection PyPep8Naming
class PKCS11_SUL_Input(abc.ABC):
    """
    see:
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203351

    """

    @abc.abstractmethod
    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        raise NotImplementedError

    def __repr__(self):
        return str(self)


# noinspection PyPep8Naming
class PKCS11_SUL_Wrap(PKCS11_SUL_Input):
    """
    see:
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203354
    """

    def __init__(self, wrapping_key_id: int, key_to_be_wrapped_id: int, result_id: int):
        self.wrapping_key_id = wrapping_key_id
        self.key_to_be_wrapped_id = key_to_be_wrapped_id
        self.result_id = result_id

    def __str__(self):
        return f"wrap-{self.wrapping_key_id}-{self.key_to_be_wrapped_id}-{self.result_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        wrapping_key = knowledge_set.get(self.wrapping_key_id)
        key_to_be_wrapped = knowledge_set.get(self.key_to_be_wrapped_id)
        if not wrapping_key:  # we do not have the wrapping key yet
            return NOT_APPLICABLE
        if not key_to_be_wrapped:  # we do not have the key to wrap.dot yet
            return NOT_APPLICABLE

        # noinspection PyUnusedLocal
        try:
            wrapping_key: WrapMixin
            result = wrapping_key.wrap_key(key_to_be_wrapped, mechanism=Mechanism.DES3_ECB)
            if self.result_id in knowledge_set:  # terms can be derived in multiple ways
                assert knowledge_set[self.result_id] == result
            else:
                knowledge_set[self.result_id] = result
            return OP_OK
        except PKCS11Error as e:
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
    """
    see:
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203355
    """

    def __init__(self, unwrapping_key_id: int, wrapped_key_id: int, result_id: int):
        self.unwrapping_key_id = unwrapping_key_id
        self.wrapped_key_id = wrapped_key_id
        self.result_id = result_id

    def __str__(self):
        return f"unwrap-{self.unwrapping_key_id}-{self.wrapped_key_id}-{self.result_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        unwrapping_key = knowledge_set.get(self.unwrapping_key_id)
        wrapped_key = knowledge_set.get(self.wrapped_key_id)
        if not unwrapping_key:  # we do not have the unwrapping key yet
            return NOT_APPLICABLE
        if not wrapped_key:  # we do not have the key to unwrap yet
            return NOT_APPLICABLE

        # noinspection PyUnusedLocal
        try:
            unwrapping_key: UnwrapMixin
            result = unwrapping_key.unwrap_key(ObjectClass.SECRET_KEY, KeyType.DES3, wrapped_key,
                                               label=str(self.result_id))
            if self.result_id in knowledge_set:  # terms can be derived in multiple ways
                # cannot assert knowledge_set[self.result_id] == result, as this would compare two memory addresses
                pass
            else:
                knowledge_set[self.result_id] = result
            return OP_OK
        except PKCS11Error as e:
            # print(self, e)
            return OP_FAIL


# noinspection PyPep8Naming
class PKCS11_SUL_Encrypt(PKCS11_SUL_Input):
    """
    see:
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203293
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203294
    """

    def __init__(self, encryption_key_id: int, key_to_be_encrypted_id: int, result_id: int):
        self.encryption_key_id = encryption_key_id
        self.key_to_be_encrypted = key_to_be_encrypted_id
        self.result_id = result_id

    def __str__(self):
        return f"encrypt-{self.encryption_key_id}-{self.key_to_be_encrypted}-{self.result_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        encryption_key = knowledge_set.get(self.encryption_key_id)
        key_to_be_encrypted = knowledge_set.get(self.key_to_be_encrypted)
        if not encryption_key:  # we do not have the encrypting key yet
            return NOT_APPLICABLE
        if not key_to_be_encrypted:  # we do not have the key to encrypt yet
            return NOT_APPLICABLE

        # noinspection PyUnusedLocal
        try:
            encryption_key: EncryptMixin
            result = encryption_key.encrypt(key_to_be_encrypted, mechanism=Mechanism.DES3_ECB)
            if self.result_id in knowledge_set:  # terms can be derived in multiple ways
                assert knowledge_set[self.result_id] == result
            else:
                knowledge_set[self.result_id] = result
            return OP_OK
        except PKCS11Error as e:
            # print(self, e)
            return OP_FAIL


# noinspection PyPep8Naming
class PKCS11_SUL_Decrypt(PKCS11_SUL_Input):
    """
    see:
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203304
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203305
    """

    def __init__(self, decryption_key_id: int, key_to_be_decrypted_id: int, result_id: int):
        self.decryption_key_id = decryption_key_id
        self.key_to_be_decrypted_id = key_to_be_decrypted_id
        self.result_id = result_id

    def __str__(self):
        return f"decrypt-{self.decryption_key_id}-{self.key_to_be_decrypted_id}-{self.result_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        decrypting_key = knowledge_set.get(self.decryption_key_id)
        key_to_decrypt = knowledge_set.get(self.key_to_be_decrypted_id)
        if not decrypting_key:  # we do not have the decrypting key yet
            return NOT_APPLICABLE
        if not key_to_decrypt:  # we do not have the key to decrypt yet
            return NOT_APPLICABLE

        # noinspection PyUnusedLocal
        try:
            decrypting_key: DecryptMixin
            result = decrypting_key.decrypt(key_to_decrypt, mechanism=Mechanism.DES3_ECB)
            if self.result_id in knowledge_set:  # terms can be derived in multiple ways
                assert knowledge_set[self.result_id] == result
            else:
                knowledge_set[self.result_id] = result
            return OP_OK
        except PKCS11Error as e:
            # print(self, e)
            return OP_FAIL


# noinspection PyPep8Naming
class PKCS11_SUL_IntruderDecrypt(PKCS11_SUL_Input):
    def __init__(self, decryption_key_id: int, key_to_be_decrypted_id: int, result_id: int, pointed_by: list[int]):
        self.decryption_key_id = decryption_key_id
        self.key_to_be_decrypted_id = key_to_be_decrypted_id
        self.result_id = result_id
        self.pointed_by = pointed_by

    def __str__(self):
        return f"intruderdecrypt-{self.decryption_key_id}-{self.key_to_be_decrypted_id}-{self.result_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        decrypting_key = knowledge_set.get(self.decryption_key_id)
        key_to_decrypt = knowledge_set.get(self.key_to_be_decrypted_id)
        if not decrypting_key:  # we do not have the decrypting key yet
            return NOT_APPLICABLE
        if not key_to_decrypt:  # we do not have the key to decrypt yet
            return NOT_APPLICABLE

        cipher = DES3.new(decrypting_key, DES3.MODE_ECB)
        result = cipher.decrypt(key_to_decrypt)
        if self.result_id in knowledge_set:  # terms can be derived in multiple ways
            assert knowledge_set[self.result_id] == result

            padded = pad(b"testing...", 32)
            # we create a cipher with key we just decrypted and encrypt a text with it.
            cipher1 = DES3.new(result, DES3.MODE_ECB)
            ciphertext1 = cipher1.encrypt(padded)
            for encryption_key_id in self.pointed_by:
                try:
                    # we use the existing handles to that key to encrypt the same text.
                    encryption_key: EncryptMixin = knowledge_set.get(encryption_key_id)
                    ciphertext2: bytes = encryption_key.encrypt(padded, mechanism=Mechanism.DES3_ECB)
                    # the two ciphertexts should be the same.
                    assert ciphertext1 == ciphertext2
                except PKCS11Error:
                    pass
            if self.result_id in knowledge_set:  # terms can be derived in multiple ways
                assert knowledge_set[self.result_id] == result
            else:
                knowledge_set[self.result_id] = result
        else:
            knowledge_set[self.result_id] = result
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_SetWrap(PKCS11_SUL_Input):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"set-wrap-{self.key_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key = knowledge_set.get(self.key_id)
        if not key:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        key[Attribute.WRAP] = True
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_UnsetWrap(PKCS11_SUL_Input):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"unset-wrap-{self.key_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key = knowledge_set.get(self.key_id)
        if not key:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        key[Attribute.WRAP] = False
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_SetUnwrap(PKCS11_SUL_Input):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"set-unwrap-{self.key_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key = knowledge_set.get(self.key_id)
        if not key:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        key[Attribute.UNWRAP] = True
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_UnsetUnwrap(PKCS11_SUL_Input):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"unset-unwrap-{self.key_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key = knowledge_set.get(self.key_id)
        if not key:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        key[Attribute.UNWRAP] = False
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_SetEncrypt(PKCS11_SUL_Input):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"set-encrypt-{self.key_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key = knowledge_set.get(self.key_id)
        if not key:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        key[Attribute.ENCRYPT] = True
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_UnsetEncrypt(PKCS11_SUL_Input):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"unset-encrypt-{self.key_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key = knowledge_set.get(self.key_id)
        if not key:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        key[Attribute.ENCRYPT] = False
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_SetDecrypt(PKCS11_SUL_Input):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"set-decrypt-{self.key_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key = knowledge_set.get(self.key_id)
        if not key:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        key[Attribute.DECRYPT] = True
        return OP_OK


# noinspection PyPep8Naming
class PKCS11_SUL_UnsetDecrypt(PKCS11_SUL_Input):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"unset-decrypt-{self.key_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key = knowledge_set.get(self.key_id)
        if not key:
            return NOT_APPLICABLE

        # noinspection PyUnresolvedReferences
        key[Attribute.DECRYPT] = False
        return OP_OK


def convert_str_input_to_pkcs11_sul_input(graph: dict[int, HandleNode | KeyNode], model: list[FNode],
                                          str_input: str) -> PKCS11_SUL_Input:
    match = re.match(regex, str_input)
    if match:
        if match.group(1) is None:
            # n = int(str_input)
            pass
        else:
            command, param1, param2, result = match.groups()
            command: str
            param1: str
            param2: str
            result: str
            match command:
                case "wrap":
                    return PKCS11_SUL_Wrap(int(param1), int(param2), int(result))
                case "unwrap":
                    return PKCS11_SUL_Unwrap(int(param1), int(param2), int(result))
                case "encrypt":
                    return PKCS11_SUL_Encrypt(int(param1), int(param2), int(result))
                case "decrypt":
                    return PKCS11_SUL_Decrypt(int(param1), int(param2), int(result))
                case "intruder_decrypt":
                    attr: KeyNode = graph[int(result)]
                    handle_in = [n for n in attr.handle_in if Symbol(str(n)) in model]
                    return PKCS11_SUL_IntruderDecrypt(int(param1), int(param2), int(result), handle_in)
                case other:
                    raise ValueError(other)
    else:
        raise ValueError("Input does not match the pattern:", str_input)
