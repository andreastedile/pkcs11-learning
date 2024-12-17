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


class HandleNode:
    def __init__(self,
                 initial: bool,
                 points_to: int,
                 use: bool,
                 unwrap_in: tuple[int, int] | None,
                 wrap_out: list[tuple[int, None, int] | tuple[None, int, int]],
                 unwrap_out: list[tuple[int, int]],
                 encrypt_out: list[tuple[int, int]],
                 decrypt_out: list[tuple[int, int]]):
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
        return len(self.unwrap_in) > 0


class KeyNode:
    def __init__(self,
                 initial: bool,
                 value: KeyType,
                 known: bool,
                 security,
                 handle_in: list[int],
                 wrap_in: list[tuple[int, int]],
                 encrypt_in: list[tuple[int, int]],
                 decrypt_in: list[tuple[int, int]],
                 intruder_decrypt_in: list[tuple[int, int]],
                 unwrap_out: list[tuple[int, int]],
                 encrypt_out: list[tuple[int, int]],
                 decrypt_out: list[tuple[int, int]],
                 intruder_decrypt_out: list[tuple[int, int]]):
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
