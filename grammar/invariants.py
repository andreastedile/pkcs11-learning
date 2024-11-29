from grammar.my_types import HandleNode, KeyNode


def check_all_key_nodes_have_different_values(nodes: dict[int, HandleNode | KeyNode]):
    for n1, attr1 in nodes.items():
        for n2, attr2 in nodes.items():
            if n1 != n2 and isinstance(attr1, KeyNode) and isinstance(attr2, KeyNode):
                if attr1.value == attr2.value:
                    raise ValueError(n1, n2, attr1.value)
