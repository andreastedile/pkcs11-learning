from copy import deepcopy
from enum import Enum

type KeyType = int | tuple[KeyType, KeyType]


class Security(Enum):
    LOW = 0,
    HIGH = 1,

    def __str__(self) -> str:
        if self == Security.LOW:
            return "LOW"
        else:
            return "HIGH"


class WrapImplication:
    __match_args__ = ("handle_of_wrapping_key", "handle_of_key_to_be_wrapped", "wrapped_key",)

    def __init__(self, handle_of_wrapping_key: int, handle_of_key_to_be_wrapped: int, wrapped_key: int):
        self.handle_of_wrapping_key = handle_of_wrapping_key
        self.handle_of_key_to_be_wrapped = handle_of_key_to_be_wrapped
        self.wrapped_key = wrapped_key

    def __repr__(self) -> str:
        return f"wrap({self.handle_of_wrapping_key},{self.handle_of_key_to_be_wrapped})={self.wrapped_key}"

    def __eq__(self, other) -> bool:
        if not isinstance(other, WrapImplication):
            raise NotImplementedError
        return (self.handle_of_wrapping_key == other.handle_of_wrapping_key and
                self.handle_of_key_to_be_wrapped == other.handle_of_key_to_be_wrapped and
                self.wrapped_key == other.wrapped_key)


class UnwrapImplication:
    __match_args__ = ("handle_of_unwrapping_key", "key_to_be_unwrapped", "handle_of_recovered_key",)

    def __init__(self, handle_of_unwrapping_key: int, key_to_be_unwrapped: int, unwrapped_key: int):
        self.handle_of_unwrapping_key = handle_of_unwrapping_key
        self.key_to_be_unwrapped = key_to_be_unwrapped
        self.handle_of_recovered_key = unwrapped_key

    def __repr__(self) -> str:
        return f"unwrap({self.handle_of_unwrapping_key},{self.key_to_be_unwrapped})={self.handle_of_recovered_key}"

    def __eq__(self, other) -> bool:
        if not isinstance(other, UnwrapImplication):
            raise NotImplementedError
        return (self.handle_of_unwrapping_key == other.handle_of_unwrapping_key and
                self.key_to_be_unwrapped == other.key_to_be_unwrapped and
                self.handle_of_recovered_key == other.handle_of_recovered_key)


class EncryptImplication:
    __match_args__ = ("handle_of_encryption_key", "key_to_be_encrypted", "encrypted_key",)

    def __init__(self, handle_of_encryption_key: int, key_to_be_encrypted: int, encrypted_key: int):
        self.handle_of_encryption_key = handle_of_encryption_key
        self.key_to_be_encrypted = key_to_be_encrypted
        self.encrypted_key = encrypted_key

    def __repr__(self) -> str:
        return f"encrypt({self.handle_of_encryption_key},{self.key_to_be_encrypted})={self.encrypted_key}"

    def __eq__(self, other) -> bool:
        if not isinstance(other, EncryptImplication):
            raise NotImplementedError
        return (self.handle_of_encryption_key == other.handle_of_encryption_key and
                self.key_to_be_encrypted == other.key_to_be_encrypted and
                self.encrypted_key == other.encrypted_key)


class DecryptImplication:
    __match_args__ = ("handle_of_decryption_key", "key_to_be_decrypted", "decrypted_key",)

    def __init__(self, handle_of_decryption_key: int, key_to_be_decrypted: int, decrypted_key: int):
        self.handle_of_decryption_key = handle_of_decryption_key
        self.key_to_be_decrypted = key_to_be_decrypted
        self.decrypted_key = decrypted_key

    def __repr__(self) -> str:
        return f"decrypt({self.handle_of_decryption_key},{self.key_to_be_decrypted})={self.decrypted_key}"

    def __eq__(self, other) -> bool:
        if not isinstance(other, DecryptImplication):
            raise NotImplementedError
        return (self.handle_of_decryption_key == other.handle_of_decryption_key and
                self.key_to_be_decrypted == other.key_to_be_decrypted and
                self.decrypted_key == other.decrypted_key)


class IntruderDecryptImplication:
    __match_args__ = ("decryption_key", "key_to_be_decrypted", "decrypted_key",)

    def __init__(self, decryption_key: int, key_to_be_decrypted: int, decrypted_key: int):
        self.decryption_key = decryption_key
        self.key_to_be_decrypted = key_to_be_decrypted
        self.decrypted_key = decrypted_key

    def __repr__(self) -> str:
        return f"intruder_decrypt({self.decryption_key},{self.key_to_be_decrypted})={self.decrypted_key}"

    def __eq__(self, other) -> bool:
        if not isinstance(other, IntruderDecryptImplication):
            raise NotImplementedError
        return (self.decryption_key == other.decryption_key and
                self.key_to_be_decrypted == other.key_to_be_decrypted and
                self.decrypted_key == other.decrypted_key)


class HandleNode:
    def __init__(self,
                 initial: bool,
                 points_to: int,
                 use: bool,
                 unwrap_in: UnwrapImplication | None,
                 wrap_out: list[WrapImplication],
                 unwrap_out: list[UnwrapImplication],
                 encrypt_out: list[EncryptImplication],
                 decrypt_out: list[DecryptImplication]):
        """
        :param initial: Whether the handle node is part of the initial knowledge. If true, the node cannot be pruned.
        :param points_to: Key node pointed by the handle node.
        :param use: Whether the handle node can be used as wrapping key, unwrapping key, encryption key, decryption key.
        :param unwrap_in: Pair of handle node and key node, the first being the (handle to the) unwrapping key, the
         second being the wrapped key.
        """
        self.initial = initial
        self.points_to = points_to
        self.use = use
        self.unwrap_in = unwrap_in
        self.wrap_out = wrap_out
        self.unwrap_out = unwrap_out
        self.encrypt_out = encrypt_out
        self.decrypt_out = decrypt_out
        self.copy = deepcopy(self) if initial else None

    def __eq__(self, other):
        if not isinstance(other, HandleNode):
            return False
        return (self.initial == other.initial and
                self.points_to == other.points_to and
                self.use == other.use and
                self.unwrap_in == other.unwrap_in and
                self.wrap_out == other.wrap_out and
                self.unwrap_out == other.unwrap_out and
                self.encrypt_out == other.encrypt_out and
                self.decrypt_out == other.decrypt_out)

    def __repr__(self):
        return (("HandleNode("
                 "initial={},"
                 "points_to={},"
                 "use={},"
                 "unwrap_in={},"
                 "wrap_out={},"
                 "unwrap_out={},"
                 "encrypt_out={},"
                 "decrypt_out={})")
                .format(self.initial,
                        self.points_to,
                        self.use,
                        self.unwrap_in,
                        self.wrap_out,
                        self.unwrap_out,
                        self.encrypt_out,
                        self.decrypt_out))

    def implies_other_nodes(self):
        return (len(self.wrap_out) > 0 or
                len(self.unwrap_out) > 0 or
                len(self.encrypt_out) > 0 or
                len(self.decrypt_out) > 0)

    def is_implied_by_other_nodes(self):
        return self.unwrap_in is not None


class KeyNode:
    def __init__(self,
                 initial: bool,
                 value: KeyType,
                 known: bool,
                 security,
                 handle_in: list[int],
                 wrap_in: list[WrapImplication],
                 encrypt_in: list[EncryptImplication],
                 decrypt_in: list[DecryptImplication],
                 intruder_decrypt_in: list[IntruderDecryptImplication],
                 unwrap_out: list[UnwrapImplication],
                 encrypt_out: list[EncryptImplication],
                 decrypt_out: list[DecryptImplication],
                 intruder_decrypt_out: list[IntruderDecryptImplication]):
        """
        :param security:
        :param initial: Whether the key node is part of the initial knowledge. If true, the node cannot be pruned.
        :param value: Value of the key node.
        :param known: Whether the key node is known and can be used as key to be wrapped, wrapped key, key to be
        encrypted, key to be decrypted.
        :param security: Whether the key node has low or high security.
        :param handle_in: Handle nodes pointing to the key node.
        :param wrap_in: Pairs of handle node and key node, the first being the (handle to the) wrapping key, the second
         being the key to be wrapped.
        :param encrypt_in: Pairs of handle node and key node, the first being the (handle to the) encryption key, the
         second being the key to be encrypted.
        :param decrypt_in: Pairs of handle node and key node, the first being the (handle to the) decryption key, the
         second being the key to be decrypted.
        :param intruder_decrypt_in: Pairs of key node and key node, the first being the decryption key, the second being
         the key to be decrypted.
        """
        self.initial = initial
        self.value = value
        self.known = known
        self.security = security
        self.handle_in = handle_in
        self.wrap_in = wrap_in
        self.encrypt_in = encrypt_in
        self.decrypt_in = decrypt_in
        self.intruder_decrypt_in = intruder_decrypt_in
        self.unwrap_out = unwrap_out
        self.encrypt_out = encrypt_out
        self.decrypt_out = decrypt_out
        self.intruder_decrypt_out = intruder_decrypt_out
        self.copy = deepcopy(self) if initial else None

    def __eq__(self, other):
        if not isinstance(other, KeyNode):
            return False
        return (self.initial == other.initial and
                self.value == other.value and
                self.known == other.known and
                self.security == other.security and
                self.handle_in == other.handle_in and
                self.wrap_in == other.wrap_in and
                self.encrypt_in == other.encrypt_in and
                self.decrypt_in == other.decrypt_in and
                self.intruder_decrypt_in == other.intruder_decrypt_in and
                self.unwrap_out == other.unwrap_out and
                self.encrypt_out == other.encrypt_out and
                self.decrypt_out == other.decrypt_out and
                self.intruder_decrypt_out == other.intruder_decrypt_out)

    def __repr__(self):
        return (("KeyNode("
                 "initial={},"
                 "value={},"
                 "known={},"
                 "security={},"
                 "handle_in={},"
                 "wrap_in={},"
                 "encrypt_in={},"
                 "decrypt_in={},"
                 "intruder_decrypt_in={},"
                 "unwrap_out={},"
                 "encrypt_out={},"
                 "decrypt_out={},"
                 "intruder_decrypt_out={}")
                .format(self.initial,
                        self.value,
                        self.known,
                        self.security,
                        self.handle_in,
                        self.wrap_in,
                        self.encrypt_in,
                        self.decrypt_in,
                        self.intruder_decrypt_in,
                        self.unwrap_out,
                        self.encrypt_out,
                        self.decrypt_out,
                        self.intruder_decrypt_out))

    def implies_other_nodes(self):
        return (len(self.unwrap_out) > 0 or
                len(self.encrypt_out) > 0 or
                len(self.decrypt_out) > 0 or
                len(self.intruder_decrypt_out) > 0)

    def is_implied_by_other_nodes(self):
        return (len(self.wrap_in) > 0 or
                len(self.encrypt_in) > 0 or
                len(self.decrypt_in) > 0 or
                len(self.intruder_decrypt_in) > 0)
