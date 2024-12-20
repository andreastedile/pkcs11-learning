import re

from pysmt.fnode import FNode

from grammar.my_types import HandleNode, KeyNode
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
                            visible_wrap_implications.append((int(param1), int(param2), int(result)))
                        case "unwrap":
                            visible_unwrap_implications.append((int(param1), int(param2), int(result)))
                        case "encrypt":
                            visible_encrypt_implications.append((int(param1), int(param2), int(result)))
                        case "decrypt":
                            visible_decrypt_implications.append((int(param1), int(param2), int(result)))
                        case "intruder_decrypt":
                            visible_intruder_decrypt_implications.append(
                                (int(param1), int(param2), int(result)))
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
