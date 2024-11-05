import abc
import logging

from Crypto.Cipher import DES3
from pkcs11 import WrapMixin, SecretKey, Mechanism, Attribute, UnwrapMixin, EncryptMixin, DecryptMixin, ObjectClass, \
    KeyType

NOT_APPLICABLE = "not-applicable"
OP_FAIL = "op-fail"
OP_OK = "op-ok"
KEY_FOUND = "key-found"
KEY_NOT_FOUND = "key-not-found"

logger = logging.getLogger(__name__)


class AttackerCommand(abc.ABC):

    @abc.abstractmethod
    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        raise NotImplementedError

    def __repr__(self):
        return str(self)


class WrapCommand(AttackerCommand):
    def __init__(self, wrapping_key_id: int, key_to_wrap_id: int, result_id: int):
        self.wrapping_key_id = wrapping_key_id
        self.key_to_wrap_id = key_to_wrap_id
        self.result_id = result_id

    def __str__(self):
        return f"wrap({self.wrapping_key_id},{self.key_to_wrap_id})={self.result_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        if self.result_id in knowledge_set:  # we already have the result
            return NOT_APPLICABLE
        wrapping_key: SecretKey = knowledge_set.get(self.wrapping_key_id)
        key_to_wrap: SecretKey = knowledge_set.get(self.key_to_wrap_id)
        if not wrapping_key:  # we do not have the wrapping key yet
            return NOT_APPLICABLE
        if not key_to_wrap:  # we do not have the key to wrap.dot yet
            return NOT_APPLICABLE
        assert isinstance(wrapping_key, WrapMixin)
        assert isinstance(key_to_wrap, SecretKey)
        try:
            result = wrapping_key.wrap_key(key_to_wrap, mechanism=Mechanism.DES3_ECB)
            knowledge_set[self.result_id] = result
        except Exception:
            cond1 = not wrapping_key[Attribute.WRAP]
            cond2 = not key_to_wrap[Attribute.EXTRACTABLE]
            assert cond1 or cond2
            return OP_FAIL
        return OP_OK


class UnwrapCommand(AttackerCommand):
    def __init__(self, unwrapping_key_id: int, key_to_unwrap_id: int, result_id: int):
        self.unwrapping_key_id = unwrapping_key_id
        self.key_to_unwrap_id = key_to_unwrap_id
        self.result_id = result_id

    def __str__(self):
        return f"unwrap({self.unwrapping_key_id},{self.key_to_unwrap_id})={self.result_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        if self.result_id in knowledge_set:  # we already have the result
            return NOT_APPLICABLE
        unwrapping_key: SecretKey = knowledge_set.get(self.unwrapping_key_id)
        key_to_unwrap: bytes = knowledge_set.get(self.key_to_unwrap_id)
        if not unwrapping_key:  # we do not have the unwrapping key yet
            return NOT_APPLICABLE
        if not key_to_unwrap:  # we do not have the key to unwrap yet
            return NOT_APPLICABLE
        assert isinstance(unwrapping_key, UnwrapMixin)
        assert isinstance(key_to_unwrap, bytes)
        try:
            result = unwrapping_key.unwrap_key(ObjectClass.SECRET_KEY, KeyType.DES3, key_to_unwrap)
            knowledge_set[self.result_id] = result
        except Exception:
            cond1 = not unwrapping_key[Attribute.UNWRAP]
            assert cond1
            return OP_FAIL
        return OP_OK


class EncryptCommand(AttackerCommand):
    def __init__(self, encrypting_key_id: int, term_to_encrypt_id: int, result_id: int):
        self.encrypting_key_id = encrypting_key_id
        self.term_to_encrypt_id = term_to_encrypt_id
        self.result_id = result_id

    def __str__(self):
        return f"encrypt({self.encrypting_key_id},{self.term_to_encrypt_id})={self.result_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        if self.result_id in knowledge_set:  # we already have the result
            return NOT_APPLICABLE
        encrypting_key: SecretKey = knowledge_set.get(self.encrypting_key_id)
        term_to_encrypt: bytes = knowledge_set.get(self.term_to_encrypt_id)
        if not encrypting_key:  # we do not have the encrypting key yet
            return NOT_APPLICABLE
        if not term_to_encrypt:  # we do not have the term to encrypt yet
            return NOT_APPLICABLE
        assert isinstance(encrypting_key, EncryptMixin)
        assert isinstance(term_to_encrypt, bytes)
        try:
            result = encrypting_key.encrypt(term_to_encrypt, mechanism=Mechanism.DES3_ECB)
            knowledge_set[self.result_id] = result
        except Exception:
            cond1 = not encrypting_key[Attribute.ENCRYPT]
            assert cond1
            return OP_FAIL
        return OP_OK


class DecryptCommand(AttackerCommand):
    def __init__(self, decrypting_key_id: int, term_to_decrypt_id: int, result_id: int):
        self.decrypting_key_id = decrypting_key_id
        self.term_to_decrypt_id = term_to_decrypt_id
        self.result_id = result_id

    def __str__(self):
        return f"decrypt({self.decrypting_key_id},{self.term_to_decrypt_id})={self.result_id}"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        if self.result_id in knowledge_set:  # we already have the result
            return NOT_APPLICABLE
        decrypting_key: SecretKey = knowledge_set.get(self.decrypting_key_id)
        term_to_decrypt: bytes = knowledge_set.get(self.term_to_decrypt_id)
        if not decrypting_key:  # we do not have the decrypting key yet
            return NOT_APPLICABLE
        if not term_to_decrypt:  # we do not have the term to decrypt yet
            return NOT_APPLICABLE
        assert isinstance(decrypting_key, DecryptMixin)
        assert isinstance(term_to_decrypt, bytes)
        try:
            result = decrypting_key.decrypt(term_to_decrypt, mechanism=Mechanism.DES3_ECB)
            knowledge_set[self.result_id] = result
        except Exception:
            cond1 = not decrypting_key[Attribute.DECRYPT]
            assert cond1
            return OP_FAIL
        return OP_OK


def test_key_equivalence(key_handle: SecretKey, key_to_test: bytes) -> bool | str:
    logger.debug("test key equivalence")

    from Crypto.Util.Padding import pad
    SECRET = pad(b"hello there", 32)

    cipher = DES3.new(key_to_test, DES3.MODE_ECB)
    ciphertext_1 = cipher.encrypt(SECRET)

    key_handle: EncryptMixin
    try:
        ciphertext_2 = key_handle.encrypt(SECRET, mechanism=Mechanism.DES3_ECB)
    except Exception:
        assert not key_handle[Attribute.ENCRYPT]
        return OP_FAIL

    logger.debug("ciphertext 1: %s", "".join(f"{byte:02X}" for byte in ciphertext_1))
    logger.debug("ciphertext 2: %s", "".join(f"{byte:02X}" for byte in ciphertext_2))

    return ciphertext_1 == ciphertext_2


class SetWrap(AttackerCommand):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"set-wrap({self.key_id})"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key: SecretKey = knowledge_set.get(self.key_id)
        if not key:
            return OP_FAIL
        assert isinstance(key, SecretKey)
        key[Attribute.WRAP] = True
        return OP_OK


class UnsetWrap(AttackerCommand):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"unset-wrap({self.key_id})"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key: SecretKey = knowledge_set.get(self.key_id)
        if not key:
            return OP_FAIL
        assert isinstance(key, SecretKey)
        key[Attribute.WRAP] = False
        return OP_OK


class SetUnwrap(AttackerCommand):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"set-unwrap({self.key_id})"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key: SecretKey = knowledge_set.get(self.key_id)
        if not key:
            return OP_FAIL
        assert isinstance(key, SecretKey)
        key[Attribute.UNWRAP] = True
        return OP_OK


class UnsetUnwrap(AttackerCommand):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"unset-unwrap({self.key_id})"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key: SecretKey = knowledge_set.get(self.key_id)
        if not key:
            return OP_FAIL
        assert isinstance(key, SecretKey)
        key[Attribute.UNWRAP] = False
        return OP_OK


class SetEncrypt(AttackerCommand):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"set-encrypt({self.key_id})"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key: SecretKey = knowledge_set.get(self.key_id)
        if not key:
            return OP_FAIL
        assert isinstance(key, SecretKey)
        key[Attribute.ENCRYPT] = True
        return OP_OK


class UnsetEncrypt(AttackerCommand):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"unset-encrypt({self.key_id})"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key: SecretKey = knowledge_set.get(self.key_id)
        if not key:
            return OP_FAIL
        assert isinstance(key, SecretKey)
        key[Attribute.ENCRYPT] = False
        return OP_OK


class SetDecrypt(AttackerCommand):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"set-decrypt({self.key_id})"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key: SecretKey = knowledge_set.get(self.key_id)
        if not key:
            return OP_FAIL
        assert isinstance(key, SecretKey)
        key[Attribute.DECRYPT] = True
        return OP_OK


class UnsetDecrypt(AttackerCommand):
    def __init__(self, key_id: int):
        self.key_id = key_id

    def __str__(self):
        return f"unset-decrypt({self.key_id})"

    def execute(self, knowledge_set: dict[int, SecretKey | bytes]) -> str:
        key: SecretKey = knowledge_set.get(self.key_id)
        if not key:
            return OP_FAIL
        assert isinstance(key, SecretKey)
        key[Attribute.DECRYPT] = False
        return OP_OK
