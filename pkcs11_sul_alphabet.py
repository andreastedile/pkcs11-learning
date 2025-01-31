import typing

from networkx.classes import MultiDiGraph

from my_types import PKCS11_FunctionArguments, \
    PKCS11_WrapArguments, PKCS11_Wrap, \
    PKCS11_UnwrapArguments, PKCS11_Unwrap, \
    PKCS11_EncryptArguments, PKCS11_Encrypt, \
    PKCS11_DecryptArguments, PKCS11_Decrypt, \
    IntruderDecrypt, IntruderDecryptArguments
from pkcs11_sul_inputs import PKCS11_SUL_Input, \
    PKCS11_SUL_Wrap, \
    PKCS11_SUL_Unwrap, \
    PKCS11_SUL_Encrypt, \
    PKCS11_SUL_Decrypt, \
    PKCS11_SUL_IntruderDecrypt, \
    PKCS11_SUL_SetWrap, PKCS11_SUL_UnsetWrap, \
    PKCS11_SUL_SetUnwrap, PKCS11_SUL_UnsetUnwrap, \
    PKCS11_SUL_SetEncrypt, PKCS11_SUL_UnsetEncrypt, \
    PKCS11_SUL_SetDecrypt, PKCS11_SUL_UnsetDecrypt


def print_alphabet(alphabet: list[PKCS11_SUL_Input]):
    print(f"alphabet has {len(alphabet)} inputs")
    print("number of wrap inputs:   ", len([input for input in alphabet if isinstance(input, PKCS11_SUL_Wrap)]))
    print("number of unwrap inputs: ", len([input for input in alphabet if isinstance(input, PKCS11_SUL_Unwrap)]))
    print("number of encrypt inputs:", len([input for input in alphabet if isinstance(input, PKCS11_SUL_Encrypt)]))
    print("number of decrypt inputs:", len([input for input in alphabet if isinstance(input, PKCS11_SUL_Decrypt)]))


def extract_alphabet_from_model(model: MultiDiGraph) -> list[PKCS11_SUL_Input]:
    alphabet = []

    for n1, attr1 in model.nodes(data=True):
        if model.in_degree(n1) == 2:  # -> not an initial node
            # Note that, by construction, a non-initial node has the attribute "arguments";
            # thus we could equivalently check that node.get("arguments") is not None.
            arguments: PKCS11_FunctionArguments = attr1["arguments"]

            if isinstance(arguments, PKCS11_WrapArguments):
                pkcs11_input = PKCS11_Wrap(arguments, n1)
                pkcs11_sul_input = PKCS11_SUL_Wrap(pkcs11_input)
                alphabet.append(pkcs11_sul_input)
            elif isinstance(arguments, PKCS11_UnwrapArguments):
                pkcs11_input = PKCS11_Unwrap(arguments, n1)
                pkcs11_sul_input = PKCS11_SUL_Unwrap(pkcs11_input)
                alphabet.append(pkcs11_sul_input)
            elif isinstance(arguments, PKCS11_EncryptArguments):
                pkcs11_input = PKCS11_Encrypt(arguments, n1)
                pkcs11_sul_input = PKCS11_SUL_Encrypt(pkcs11_input)
                alphabet.append(pkcs11_sul_input)
            elif isinstance(arguments, PKCS11_DecryptArguments):
                pkcs11_input = PKCS11_Decrypt(arguments, n1)
                pkcs11_sul_input = PKCS11_SUL_Decrypt(pkcs11_input)
                alphabet.append(pkcs11_sul_input)
            elif isinstance(arguments, IntruderDecryptArguments):
                pointed_by = [n2 for n2, attr2 in model.nodes(data=True) if
                              attr2["nodetype"] == "handle" and attr1["value"] == attr2["value"]]
                pkcs11_input = IntruderDecrypt(arguments, n1)
                pkcs11_sul_input = PKCS11_SUL_IntruderDecrypt(pkcs11_input, pointed_by)
                alphabet.append(pkcs11_sul_input)
            else:
                typing.assert_never(arguments)
        else:
            # sanity check
            assert model.in_degree(n1) == 0  # -> an initial node

    for n1, attr1 in model.nodes(data=True):
        node_type = attr1["nodetype"]
        if node_type == "handle":
            alphabet.append(PKCS11_SUL_SetWrap(n1))
            alphabet.append(PKCS11_SUL_UnsetWrap(n1))
            alphabet.append(PKCS11_SUL_SetUnwrap(n1))
            alphabet.append(PKCS11_SUL_UnsetUnwrap(n1))
            alphabet.append(PKCS11_SUL_SetEncrypt(n1))
            alphabet.append(PKCS11_SUL_UnsetEncrypt(n1))
            alphabet.append(PKCS11_SUL_SetDecrypt(n1))
            alphabet.append(PKCS11_SUL_UnsetDecrypt(n1))
        else:
            # sanity check
            assert node_type == "key"

    return alphabet
