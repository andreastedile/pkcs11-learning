from pysmt.fnode import FNode

from pkcs11_sul_inputs import PKCS11_SUL_Input, \
    PKCS11_SUL_Wrap, PKCS11_SUL_Unwrap, PKCS11_SUL_Encrypt, PKCS11_SUL_Decrypt, PKCS11_SUL_IntruderDecrypt, \
    PKCS11_SUL_SetWrap, PKCS11_SUL_SetUnwrap, PKCS11_SUL_SetEncrypt, PKCS11_SUL_SetDecrypt, \
    PKCS11_SUL_UnsetWrap, PKCS11_SUL_UnsetUnwrap, PKCS11_SUL_UnsetEncrypt, PKCS11_SUL_UnsetDecrypt, \
    convert_str_input_to_pkcs11_sul_input
from grammar.my_types import HandleNode, KeyNode


def print_alphabet(alphabet: list[PKCS11_SUL_Input]):
    print(f"alphabet has {len(alphabet)} inputs")
    print("number of wrap inputs:   ", len([input for input in alphabet if isinstance(input, PKCS11_SUL_Wrap)]))
    print("number of unwrap inputs: ", len([input for input in alphabet if isinstance(input, PKCS11_SUL_Unwrap)]))
    print("number of encrypt inputs:", len([input for input in alphabet if isinstance(input, PKCS11_SUL_Encrypt)]))
    print("number of decrypt inputs:", len([input for input in alphabet if isinstance(input, PKCS11_SUL_Decrypt)]))


def extract_alphabet(graph: dict[int, HandleNode | KeyNode]) -> list[PKCS11_SUL_Input]:
    alphabet = []

    for n, attr in graph.items():
        if isinstance(attr, KeyNode):
            for implication in attr.wrap_in:
                alphabet.append(PKCS11_SUL_Wrap(implication.handle_of_wrapping_key,
                                                implication.handle_of_key_to_be_wrapped,
                                                implication.wrapped_key))
            for implication in attr.encrypt_in:
                alphabet.append(PKCS11_SUL_Encrypt(implication.handle_of_encryption_key,
                                                   implication.key_to_be_encrypted,
                                                   implication.encrypted_key))
            for implication in attr.decrypt_in:
                alphabet.append(PKCS11_SUL_Decrypt(implication.handle_of_decryption_key,
                                                   implication.key_to_be_decrypted,
                                                   implication.decrypted_key))
            for implication in attr.intruder_decrypt_in:
                alphabet.append(PKCS11_SUL_IntruderDecrypt(implication.decryption_key,
                                                           implication.key_to_be_decrypted,
                                                           implication.decrypted_key, attr.handle_in.copy()))
        elif isinstance(attr, HandleNode):
            if attr.unwrap_in is not None:
                alphabet.append(PKCS11_SUL_Unwrap(attr.unwrap_in.handle_of_unwrapping_key,
                                                  attr.unwrap_in.key_to_be_unwrapped,
                                                  attr.unwrap_in.handle_of_recovered_key))

    for n, attr in graph.items():
        if isinstance(attr, HandleNode):
            alphabet.append(PKCS11_SUL_SetWrap(n))
            alphabet.append(PKCS11_SUL_UnsetWrap(n))
            alphabet.append(PKCS11_SUL_SetUnwrap(n))
            alphabet.append(PKCS11_SUL_UnsetUnwrap(n))
            alphabet.append(PKCS11_SUL_SetEncrypt(n))
            alphabet.append(PKCS11_SUL_UnsetEncrypt(n))
            alphabet.append(PKCS11_SUL_SetDecrypt(n))
            alphabet.append(PKCS11_SUL_UnsetDecrypt(n))

    print_alphabet(alphabet)

    return alphabet


def convert_model_to_alphabet(graph: dict[int, HandleNode | KeyNode], model: list[FNode]) -> list[PKCS11_SUL_Input]:
    alphabet: list[PKCS11_SUL_Input] = []

    for atom in model:
        if atom.is_symbol():
            name: str = atom.symbol_name()
            if name.isdigit():
                n = int(name)
                attr = graph[n]
                if isinstance(attr, HandleNode):
                    alphabet.append(PKCS11_SUL_SetWrap(n))
                    alphabet.append(PKCS11_SUL_UnsetWrap(n))
                    alphabet.append(PKCS11_SUL_SetUnwrap(n))
                    alphabet.append(PKCS11_SUL_UnsetUnwrap(n))
                    alphabet.append(PKCS11_SUL_SetEncrypt(n))
                    alphabet.append(PKCS11_SUL_UnsetEncrypt(n))
                    alphabet.append(PKCS11_SUL_SetDecrypt(n))
                    alphabet.append(PKCS11_SUL_UnsetDecrypt(n))
            else:
                converted = convert_str_input_to_pkcs11_sul_input(graph, model, name)
                alphabet.append(converted)
        else:
            assert atom.is_not()

    print_alphabet(alphabet)

    return alphabet
