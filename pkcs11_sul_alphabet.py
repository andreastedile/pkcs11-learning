from pkcs11_sul_inputs import PKCS11_SUL_Input, \
    PKCS11_SUL_Wrap, PKCS11_SUL_Unwrap, PKCS11_SUL_Encrypt, PKCS11_SUL_Decrypt, \
    PKCS11_SUL_SetWrap, PKCS11_SUL_SetUnwrap, PKCS11_SUL_SetEncrypt, PKCS11_SUL_SetDecrypt, \
    PKCS11_SUL_UnsetWrap, PKCS11_SUL_UnsetUnwrap, PKCS11_SUL_UnsetEncrypt, PKCS11_SUL_UnsetDecrypt
from grammar.my_types import HandleNode, KeyNode


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

    print(f"alphabet has {len(alphabet)} inputs")
    print("number of wrap inputs:   ", len([input for input in alphabet if isinstance(input, PKCS11_SUL_Wrap)]))
    print("number of unwrap inputs: ", len([input for input in alphabet if isinstance(input, PKCS11_SUL_Unwrap)]))
    print("number of encrypt inputs:", len([input for input in alphabet if isinstance(input, PKCS11_SUL_Encrypt)]))
    print("number of decrypt inputs:", len([input for input in alphabet if isinstance(input, PKCS11_SUL_Decrypt)]))

    return alphabet
