from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple

type KeyType = int | tuple[KeyType, KeyType]


class Security(Enum):
    LOW = 0,
    HIGH = 1,

    def __str__(self) -> str:
        if self == Security.LOW:
            return "LOW"
        else:
            return "HIGH"


@dataclass
class HandleNode:
    value: KeyType
    """Value of the key node."""
    usable: bool
    """Whether the handle node can be used as wrapping key, unwrapping key, encryption key, decryption key."""


@dataclass
class KeyNode:
    value: KeyType
    """Value of the key node."""
    security: Security
    """Whether the key node has low or high security."""


class KnowledgeBase:
    def __init__(self):
        self.handles: dict[int, HandleNode] = {}
        self.keys: dict[int, KeyNode] = {}
        self.wrap_arguments_list: dict[int, list[PKCS11_WrapArguments]] = defaultdict(list)
        self.unwrap_arguments: dict[int, PKCS11_UnwrapArguments] = {}
        self.encrypt_arguments_list: dict[int, list[PKCS11_EncryptArguments]] = defaultdict(list)
        self.decrypt_arguments_list: dict[int, list[PKCS11_DecryptArguments]] = defaultdict(list)
        self.intruder_decrypt_arguments: dict[int, IntruderDecryptArguments] = {}

    def __eq__(self, other):
        if not isinstance(other, KnowledgeBase):
            raise NotImplementedError
        return (self.handles == other.handles and
                self.keys == other.keys and
                self.wrap_arguments_list == other.wrap_arguments_list and
                self.unwrap_arguments == other.unwrap_arguments and
                self.encrypt_arguments_list == other.encrypt_arguments_list and
                self.decrypt_arguments_list == other.decrypt_arguments_list and
                self.intruder_decrypt_arguments == other.intruder_decrypt_arguments)

    def __len__(self):
        return len(self.handles) + len(self.keys)

    def __copy__(self):
        copy = KnowledgeBase()
        copy.handles = deepcopy(self.handles)
        copy.keys = deepcopy(self.keys)
        copy.wrap_arguments_list = deepcopy(self.wrap_arguments_list)
        copy.unwrap_arguments = deepcopy(self.unwrap_arguments)
        copy.encrypt_arguments_list = deepcopy(self.encrypt_arguments_list)
        copy.decrypt_arguments_list = deepcopy(self.decrypt_arguments_list)
        copy.intruder_decrypt_arguments = deepcopy(self.intruder_decrypt_arguments)
        return copy

    def copy(self):
        return self.__copy__()

    def next_available_id(self):
        if len(self.handles) == 0 and len(self.keys) == 0:
            return 0
        elif len(self.handles) == 0 and len(self.keys) > 0:
            return max(self.keys) + 1
        elif len(self.handles) > 0 and len(self.keys) == 0:
            return max(self.handles) + 1
        else:
            return max(max(self.handles), max(self.keys)) + 1


# noinspection PyPep8Naming
class PKCS11_WrapArguments(NamedTuple):
    handle_of_wrapping_key: int
    handle_of_key_to_be_wrapped: int


# noinspection PyPep8Naming
class PKCS11_UnwrapArguments(NamedTuple):
    handle_of_unwrapping_key: int
    key_to_be_unwrapped: int


# noinspection PyPep8Naming
class PKCS11_EncryptArguments(NamedTuple):
    handle_of_encryption_key: int
    key_to_be_encrypted: int


# noinspection PyPep8Naming
class PKCS11_DecryptArguments(NamedTuple):
    handle_of_decryption_key: int
    key_to_be_decrypted: int


class IntruderDecryptArguments(NamedTuple):
    decryption_key: int
    key_to_be_decrypted: int


# https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203351

# noinspection PyPep8Naming
@dataclass
class PKCS11_Wrap:
    """
    see:
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203354
    """
    arguments: PKCS11_WrapArguments
    wrapped_key: int

    def __str__(self) -> str:
        return f"Wrap({self.arguments.handle_of_wrapping_key},{self.arguments.handle_of_key_to_be_wrapped})={self.wrapped_key}"


# noinspection PyPep8Naming
@dataclass
class PKCS11_Unwrap:
    """
    see:
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203355
    """
    arguments: PKCS11_UnwrapArguments
    handle_of_recovered_key: int

    def __str__(self) -> str:
        return f"Unwrap({self.arguments.handle_of_unwrapping_key},{self.arguments.key_to_be_unwrapped})={self.handle_of_recovered_key}"


# noinspection PyPep8Naming
@dataclass
class PKCS11_Encrypt:
    """
    see:
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203293
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203294
    """
    arguments: PKCS11_EncryptArguments
    encrypted_key: int

    def __str__(self) -> str:
        return f"Encrypt({self.arguments.handle_of_encryption_key},{self.arguments.key_to_be_encrypted})={self.encrypted_key}"


# noinspection PyPep8Naming
@dataclass
class PKCS11_Decrypt:
    """
    see:
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203304
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203305
    """
    arguments: PKCS11_DecryptArguments
    decrypted_key: int

    def __str__(self) -> str:
        return f"Decrypt({self.arguments.handle_of_decryption_key},{self.arguments.key_to_be_decrypted})={self.decrypted_key}"


@dataclass
class IntruderDecrypt:
    arguments: IntruderDecryptArguments
    decrypted_key: int

    def __str__(self) -> str:
        return f"IntruderDecrypt({self.arguments.decryption_key},{self.arguments.key_to_be_decrypted})={self.decrypted_key}"


PKCS11_FunctionArguments = PKCS11_WrapArguments | PKCS11_UnwrapArguments | PKCS11_EncryptArguments | PKCS11_DecryptArguments | IntruderDecryptArguments

PKCS11_Functions = PKCS11_Wrap | PKCS11_Unwrap | PKCS11_Encrypt | PKCS11_Decrypt | IntruderDecrypt
