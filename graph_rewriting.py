from collections.abc import Iterator
from copy import deepcopy
from itertools import count

from my_types import KnowledgeBase, KeyNode, Security, HandleNode, \
    PKCS11_WrapArguments, \
    PKCS11_UnwrapArguments, \
    PKCS11_EncryptArguments, \
    PKCS11_DecryptArguments, \
    IntruderDecryptArguments

MAX_HANDLES_OF_RECOVERED_KEY_WITH_SAME_ARGUMENTS = 2


def wrap(input_kb: KnowledgeBase, output_kb: KnowledgeBase, id_generator: Iterator[int]):
    for n1, attr1 in input_kb.handles.items():
        if not attr1.usable:
            continue

        for n2, attr2 in input_kb.handles.items():
            match [n for n, attr in output_kb.keys.items() if attr.value == (attr2.value, attr1.value)]:
                case []:
                    n3 = next(id_generator)
                    attr3 = KeyNode((deepcopy(attr2.value), deepcopy(attr1.value)),
                                    Security.LOW)
                    output_kb.keys[n3] = attr3
                    output_kb.wrap_arguments_list[n3].append(PKCS11_WrapArguments(n1, n2))
                case [n3]:
                    arguments = PKCS11_WrapArguments(n1, n2)
                    if arguments not in output_kb.wrap_arguments_list[n3]:
                        output_kb.wrap_arguments_list[n3].append(arguments)
                case other:
                    # At most one key node for value can exist.
                    raise ValueError(other)


def encrypt(input_kb: KnowledgeBase, output_kb: KnowledgeBase, id_generator: Iterator[int]):
    for n1, attr1 in input_kb.handles.items():
        if not attr1.usable:
            continue

        for n2, attr2 in input_kb.keys.items():
            match [n for n, attr in output_kb.keys.items() if attr.value == (attr2.value, attr1.value)]:
                case []:
                    n3 = next(id_generator)
                    attr3 = KeyNode((deepcopy(attr2.value), deepcopy(attr1.value)),
                                    Security.LOW)
                    output_kb.keys[n3] = attr3
                    output_kb.encrypt_arguments_list[n3].append(PKCS11_EncryptArguments(n1, n2))
                case [n3]:
                    arguments = PKCS11_EncryptArguments(n1, n2)
                    if arguments not in output_kb.encrypt_arguments_list[n3]:
                        output_kb.encrypt_arguments_list[n3].append(arguments)
                case other:
                    # At most one key node for value can exist.   
                    raise ValueError(other)


def decrypt(input_kb: KnowledgeBase, output_kb: KnowledgeBase, id_generator: Iterator[int]):
    for n1, attr1 in input_kb.handles.items():
        if not attr1.usable:
            continue

        for n2, attr2 in input_kb.keys.items():
            match attr2.value:
                case (inner, outer) if outer == attr1.value:
                    match [n for n, attr in output_kb.keys.items() if attr.value == inner]:
                        case []:
                            n3 = next(id_generator)
                            attr3 = KeyNode(deepcopy(inner),
                                            Security.LOW)
                            output_kb.keys[n3] = attr3
                            output_kb.decrypt_arguments_list[n3].append(PKCS11_DecryptArguments(n1, n2))
                        case [n3]:
                            arguments = PKCS11_DecryptArguments(n1, n2)
                            if arguments not in output_kb.decrypt_arguments_list[n3]:
                                output_kb.decrypt_arguments_list[n3].append(arguments)
                        case other:
                            # At most one key node for value can exist.
                            raise ValueError(other)


def unwrap(input_kb: KnowledgeBase, output_kb: KnowledgeBase, id_generator: Iterator[int]):
    for n1, attr1 in input_kb.handles.items():
        if not attr1.usable:
            continue

        for n2, attr2 in input_kb.keys.items():
            match attr2.value:
                case (inner, outer) if outer == attr1.value:
                    handles_with_same_arguments = [n for n, arguments in input_kb.unwrap_arguments.items() if
                                                   arguments == PKCS11_UnwrapArguments(n1, n2)]

                    for _ in range(MAX_HANDLES_OF_RECOVERED_KEY_WITH_SAME_ARGUMENTS - len(handles_with_same_arguments)):
                        n3 = next(id_generator)
                        attr3 = HandleNode(deepcopy(inner),
                                           True)
                        output_kb.handles[n3] = attr3
                        output_kb.unwrap_arguments[n3] = PKCS11_UnwrapArguments(n1, n2)


def intruder_decrypt(input_kb: KnowledgeBase, output_kb: KnowledgeBase, id_generator: Iterator[int]):
    for n1, attr1 in input_kb.keys.items():
        for n2, attr2 in input_kb.keys.items():
            match attr2.value:
                case (inner, outer) if outer == attr1.value:
                    match [n for n, attr in output_kb.keys.items() if attr.value == inner]:
                        case []:
                            n3 = next(id_generator)
                            attr3 = KeyNode(deepcopy(inner),
                                            Security.LOW)
                            output_kb.keys[n3] = attr3
                            output_kb.intruder_decrypt_arguments[n3] = IntruderDecryptArguments(n1, n2)
                        case [_]:
                            pass
                        case other:
                            # At most one key node for value can exist.
                            raise ValueError(other)


def expand_knowledge_base(kb: KnowledgeBase, n_iter: int) -> KnowledgeBase:
    # id generator for the new nodes and keys in the knowledge base
    id_generator = count(kb.next_available_id())

    output_kb = kb.copy()

    for i in range(n_iter):
        print("expand; iter", i)

        temp_kb = output_kb.copy()

        decrypt(temp_kb, output_kb, id_generator)

        intruder_decrypt(temp_kb, output_kb, id_generator)

        unwrap(temp_kb, output_kb, id_generator)

        encrypt(temp_kb, output_kb, id_generator)

        wrap(temp_kb, output_kb, id_generator)

    return output_kb
