import re

from pysmt.fnode import FNode

from pkcs11_sul_inputs import PKCS11_SUL_Input, \
    PKCS11_SUL_Wrap, PKCS11_SUL_Unwrap, PKCS11_SUL_Encrypt, PKCS11_SUL_Decrypt, PKCS11_SUL_IntruderDecrypt, \
    PKCS11_SUL_SetWrap, PKCS11_SUL_SetUnwrap, PKCS11_SUL_SetEncrypt, PKCS11_SUL_SetDecrypt, \
    PKCS11_SUL_UnsetWrap, PKCS11_SUL_UnsetUnwrap, PKCS11_SUL_UnsetEncrypt, PKCS11_SUL_UnsetDecrypt
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
            for (n1, n2) in attr.wrap_in:
                alphabet.append(PKCS11_SUL_Wrap(n1, n2, n))
            for (n1, n2) in attr.encrypt_in:
                alphabet.append(PKCS11_SUL_Encrypt(n1, n2, n))
            for (n1, n2) in attr.decrypt_in:
                alphabet.append(PKCS11_SUL_Decrypt(n1, n2, n))
            for (n1, n2) in attr.intruder_decrypt_in:
                alphabet.append(PKCS11_SUL_IntruderDecrypt(n1, n2, n))
        elif isinstance(attr, HandleNode):
            match attr.unwrap_in:
                case (n1, n2):
                    alphabet.append(PKCS11_SUL_Unwrap(n1, n2, n))

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
    prog = re.compile(r"^(?:\d+|(wrap|unwrap|encrypt|decrypt|intruder_decrypt)\((\d+),(\d+)\)=(\d+))$")

    alphabet = []

    for atom in model:
        if atom.is_symbol():
            name: str = atom.symbol_name()
            match = re.match(prog, name)
            if match:
                if match.group(1) is None:
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
                    command, param1, param2, result = match.groups()
                    command: str
                    param1: str
                    param2: str
                    result: str
                    match command:
                        case "wrap":
                            alphabet.append(PKCS11_SUL_Wrap(int(param1), int(param2), int(result)))
                        case "unwrap":
                            alphabet.append(PKCS11_SUL_Unwrap(int(param1), int(param2), int(result)))
                        case "encrypt":
                            alphabet.append(PKCS11_SUL_Encrypt(int(param1), int(param2), int(result)))
                        case "decrypt":
                            alphabet.append(PKCS11_SUL_Decrypt(int(param1), int(param2), int(result)))
                        case "intruder_decrypt":
                            alphabet.append(PKCS11_SUL_IntruderDecrypt(int(param1), int(param2), int(result)))
                        case other:
                            raise ValueError(other)
            else:
                print("Input does not match the pattern:", atom.symbol_name())
        else:
            assert atom.is_not()

    print_alphabet(alphabet)

    return alphabet
