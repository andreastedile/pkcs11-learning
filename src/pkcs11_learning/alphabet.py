from pkcs11_learning.commands import AttackerCommand, \
    SetWrap, UnsetWrap, \
    SetUnwrap, UnsetUnwrap, \
    SetEncrypt, UnsetEncrypt, \
    SetDecrypt, UnsetDecrypt, \
    WrapCommand, UnwrapCommand, \
    EncryptCommand, DecryptCommand
from pkcs11_learning.graph import HandleNode, KeyNode, \
    alphabet_unwrap, alphabet_decrypt, alphabet_wrap, alphabet_encrypt


def validate_initial_state(nodes: dict[int, HandleNode | KeyNode]):
    raise NotImplementedError


def generate_attribute_changing_commands(nodes: dict[int, HandleNode | KeyNode]) -> list[AttackerCommand]:
    attribute_changing_commands = []

    for n, attr in nodes.items():
        if isinstance(attr, HandleNode):
            attribute_changing_commands.append(SetWrap(n))
            attribute_changing_commands.append(UnsetWrap(n))
            attribute_changing_commands.append(SetUnwrap(n))
            attribute_changing_commands.append(UnsetUnwrap(n))
            attribute_changing_commands.append(SetEncrypt(n))
            attribute_changing_commands.append(UnsetEncrypt(n))
            attribute_changing_commands.append(SetDecrypt(n))
            attribute_changing_commands.append(UnsetDecrypt(n))

    return attribute_changing_commands


def generate_alphabet(nodes0: dict[int, HandleNode | KeyNode], n_iter: int) -> list[AttackerCommand]:
    for _ in range(n_iter):
        unwrap_commands = alphabet_unwrap(nodes0)
        decrypt_commands = alphabet_decrypt(nodes0)
        wrap_commands = alphabet_wrap(nodes0)
        encrypt_commands = alphabet_encrypt(nodes0)
        # TODO: merge the differences into node0

    all_commands = []
    for n, attr in nodes0.items():
        if isinstance(attr, KeyNode):
            for (n1, n2) in attr.wrap_in:
                all_commands.append(WrapCommand(n1, n2, n))
            for (n1, n2) in attr.decrypt_in:
                all_commands.append(DecryptCommand(n1, n2, n))
            for (n1, n2) in attr.encrypt_in:
                all_commands.append(EncryptCommand(n1, n2, n))
        elif isinstance(attr, HandleNode):
            for (n1, n2) in attr.unwrap_in:
                all_commands.append(UnwrapCommand(n1, n2, n))

    attribute_changing_commands = generate_attribute_changing_commands(nodes0)
    all_commands.extend(attribute_changing_commands)

    return all_commands
