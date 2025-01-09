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
            for implication in attr1.wrap_in:
                assert implication.handle_of_wrapping_key in graph
                assert implication.handle_of_key_to_be_wrapped in graph
            for implication in attr1.encrypt_in:
                assert implication.handle_of_encryption_key in graph
                assert implication.key_to_be_encrypted in graph
            for implication in attr1.decrypt_in:
                assert implication.handle_of_decryption_key in graph
                assert implication.key_to_be_decrypted in graph
            for implication in attr1.intruder_decrypt_in:
                assert implication.decryption_key in graph
                assert implication.key_to_be_decrypted in graph
        elif isinstance(attr1, HandleNode):
            if attr1.unwrap_in is not None:
                assert attr1.unwrap_in.handle_of_unwrapping_key in graph
                assert attr1.unwrap_in.key_to_be_unwrapped in graph


def check_all_implied_nodes_are_present(graph: dict[int, HandleNode | KeyNode]):
    for n1, attr1 in graph.items():
        if isinstance(attr1, KeyNode):
            for implication in attr1.unwrap_out:
                assert implication.handle_of_unwrapping_key in graph
                assert implication.handle_of_recovered_key in graph
            for implication in attr1.encrypt_out:
                assert implication.handle_of_encryption_key in graph
                assert implication.encrypted_key in graph
            for implication in attr1.decrypt_out:
                assert implication.handle_of_decryption_key in graph
                assert implication.decrypted_key in graph
            for implication in attr1.intruder_decrypt_out:
                assert implication.decryption_key in graph
                assert implication.key_to_be_decrypted in graph
                assert implication.decrypted_key in graph
        elif isinstance(attr1, HandleNode):
            for implication in attr1.wrap_out:
                assert implication.handle_of_key_to_be_wrapped in graph
                assert implication.wrapped_key in graph
            for implication in attr1.unwrap_out:
                assert implication.key_to_be_unwrapped in graph
                assert implication.handle_of_recovered_key in graph
            for implication in attr1.encrypt_out:
                assert implication.key_to_be_encrypted in graph
                assert implication.encrypted_key in graph
            for implication in attr1.decrypt_out:
                assert implication.handle_of_decryption_key in graph
                assert implication.decrypted_key in graph
