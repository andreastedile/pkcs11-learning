from copy import deepcopy
from enum import Enum

type KeyType = int | tuple[KeyType, KeyType]


class Security(Enum):
    LOW = 0,
    HIGH = 1,


class HandleNode:
    def __init__(self, initial: bool, points_to: int, use: bool, unwrap_in: tuple[int, int] | None):
        """
        :param initial: Whether the handle node is part of the initial knowledge. If true, the node cannot be pruned.
        :param points_to: Key node pointed by the handle node.
        :param use: Whether the handle node can be used as wrapping key, unwrapping key, encryption key, decryption key.
        :param unwrap_in: Pair of handle node and key node, the first being the (handle to the) unwrapping key, the
         second being the wrapped key.
        """
        self.points_to = points_to
        self.unwrap_in = unwrap_in
        self.use = use
        self.initial = initial
        self.copy = deepcopy(self) if initial else None

    def __eq__(self, other):
        if not isinstance(other, HandleNode):
            return False
        return (self.points_to == other.points_to and
                self.unwrap_in == other.unwrap_in)

    def __repr__(self):
        return ("HandleNode(points_to={}, unwrap_in={})"
                .format(self.points_to, self.unwrap_in))


class KeyNode:
    def __init__(self, initial: bool, value: KeyType, known: bool, security, handle_in: list[int],
                 wrap_in: list[tuple[int, int]], encrypt_in: list[tuple[int, int]], decrypt_in: list[tuple[int, int]],
                 intruder_decrypt_in: list[tuple[int, int]]):
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
        self.value = value
        self.known = known
        self.security = security
        self.handle_in = handle_in
        self.wrap_in = wrap_in
        self.encrypt_in = encrypt_in
        self.decrypt_in = decrypt_in
        self.intruder_decrypt_in = intruder_decrypt_in
        self.initial = initial
        self.copy = deepcopy(self) if initial else None

    def __eq__(self, other):
        if not isinstance(other, KeyNode):
            return False
        return (self.value == other.value and
                self.known == other.known and
                self.handle_in == other.handle_in and
                self.wrap_in == other.wrap_in and
                self.encrypt_in == other.encrypt_in and
                self.decrypt_in == other.decrypt_in and
                self.intruder_decrypt_in == other.intruder_decrypt_in)

    def __repr__(self):
        return ("KeyNode(value={}, handle_in={}, wrap_in={}, encrypt_in={}, decrypt_in={}, known={})"
                .format(self.value, self.known, self.handle_in, self.wrap_in, self.encrypt_in, self.decrypt_in,
                        self.intruder_decrypt_in))
