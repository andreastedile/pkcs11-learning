from grammar.my_types import HandleNode, KeyNode


def check_all_key_nodes_have_different_values(nodes: dict[int, HandleNode | KeyNode]):
    for n1, attr1 in nodes.items():
        for n2, attr2 in nodes.items():
            if n1 != n2 and isinstance(attr1, KeyNode) and isinstance(attr2, KeyNode):
                if attr1.value == attr2.value:
                    raise ValueError(n1, n2, attr1.value)


def check_all_implicant_nodes_are_present(graph: dict[int, HandleNode | KeyNode]):
    for n1, attr1 in graph.items():
        if isinstance(attr1, KeyNode):
            for n2 in attr1.handle_in:
                assert n2 in graph
            for (e1, e2) in attr1.wrap_in:
                assert e1 in graph
                assert e2 in graph
            for (e1, e2) in attr1.encrypt_in:
                assert e1 in graph
                assert e2 in graph
            for (e1, e2) in attr1.decrypt_in:
                assert e1 in graph
                assert e2 in graph
            for (e1, e2) in attr1.intruder_decrypt_in:
                assert e1 in graph
                assert e2 in graph
        elif isinstance(attr1, HandleNode):
            match attr1.unwrap_in:
                case (e1, e2):
                    assert e1 in graph
                    assert e2 in graph


def check_all_implied_nodes_are_present(graph: dict[int, HandleNode | KeyNode]):
    for n1, attr1 in graph.items():
        if isinstance(attr1, KeyNode):
            for (n2, n3) in attr1.unwrap_out:
                assert n2 in graph
                assert n3 in graph
            for (n2, n3) in attr1.encrypt_out:
                assert n2 in graph
                assert n3 in graph
            for (n2, n3) in attr1.decrypt_out:
                assert n2 in graph
                assert n3 in graph
            for (n2, n3) in attr1.intruder_decrypt_out:
                assert n2 in graph
                assert n3 in graph
        elif isinstance(attr1, HandleNode):
            for (n2, n3) in attr1.wrap_out:
                assert n1 in graph
                assert n3 in graph
            for (n2, n3) in attr1.unwrap_out:
                assert n1 in graph
                assert n3 in graph
            for (n2, n3) in attr1.encrypt_out:
                assert n1 in graph
                assert n3 in graph
            for (n2, n3) in attr1.decrypt_out:
                assert n1 in graph
                assert n3 in graph
