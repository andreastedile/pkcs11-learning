import re

from pysmt.fnode import FNode

from grammar.my_types import HandleNode, KeyNode, \
    IntruderDecryptImplication, DecryptImplication, EncryptImplication, UnwrapImplication, WrapImplication
from grammar.visualization import convert_graph_to_dot
from pkcs11_sul_inputs import regex


def visualize_model(graph: dict[int, HandleNode | KeyNode], model: list[FNode], file: str):
    visible_nodes = []
    visible_wrap_implications = []
    visible_unwrap_implications = []
    visible_encrypt_implications = []
    visible_decrypt_implications = []
    visible_intruder_decrypt_implications = []

    for atom in model:
        if atom.is_symbol():
            name: str = atom.symbol_name()
            match = re.match(regex, name)
            if match:
                if match.group(1) is None:
                    visible_nodes.append(int(name))
                else:
                    command, param1, param2, result = match.groups()
                    match command:
                        case "wrap":
                            implication = WrapImplication(int(param1), int(param2), int(result))
                            visible_wrap_implications.append(implication)
                        case "unwrap":
                            implication = UnwrapImplication(int(param1), int(param2), int(result))
                            visible_unwrap_implications.append(implication)
                        case "encrypt":
                            implication = EncryptImplication(int(param1), int(param2), int(result))
                            visible_encrypt_implications.append(implication)
                        case "decrypt":
                            implication = DecryptImplication(int(param1), int(param2), int(result))
                            visible_decrypt_implications.append(implication)
                        case "intruder_decrypt":
                            implication = IntruderDecryptImplication(int(param1), int(param2), int(result))
                            visible_intruder_decrypt_implications.append(implication)
                        case other:
                            raise ValueError(other)
            else:
                print("Input does not match the pattern:", name)
        else:
            assert atom.is_not()

    dot = convert_graph_to_dot(graph,
                               visible_nodes,
                               visible_wrap_implications,
                               visible_unwrap_implications,
                               visible_encrypt_implications,
                               visible_decrypt_implications,
                               visible_intruder_decrypt_implications)
    dot.write(f"{file}.svg", format="svg")
