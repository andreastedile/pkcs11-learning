from __future__ import annotations

type KeyType = int | tuple[KeyType, KeyType]

MAX_N_HANDLES_TO_KEY = 2


class HandleNode:
    # noinspection PyDefaultArgument
    def __init__(self, value: int, unwrap_in: list[tuple[int, int]] = []):
        self.value = value
        self.unwrap_in = unwrap_in

    def __repr__(self):
        return ("HandleNode(value={}, unwrap_in={})"
                .format(self.value, self.unwrap_in))


class KeyNode:
    # noinspection PyDefaultArgument
    def __init__(self, value: KeyType,
                 known=False,
                 handle_in: list[int] = [],
                 wrap_in: list[tuple[int, int]] = [],
                 encrypt_in: list[tuple[int, int]] = [],
                 decrypt_in: list[tuple[int, int]] = []):
        self.value = value
        self.known = known
        self.handle_in = handle_in
        self.wrap_in = wrap_in
        self.encrypt_in = encrypt_in
        self.decrypt_in = decrypt_in

    def __repr__(self):
        return ("KeyNode(value={}, handle_in={}, wrap_in={}, encrypt_in={}, decrypt_in={}, known={})"
                .format(self.value, self.handle_in, self.wrap_in, self.encrypt_in, self.decrypt_in, self.known))


def alphabet_wrap(nodes: dict[int, HandleNode | KeyNode]) -> dict[int, HandleNode | KeyNode]:
    nodes_copy = nodes.copy()

    for n1, attr1 in [(n, attr) for n, attr in nodes.items() if isinstance(attr, HandleNode)]:
        attr2: KeyNode
        n2, attr2 = attr1.value, nodes[attr1.value]

        for n3, attr3 in [(n, attr) for n, attr in nodes.items() if isinstance(attr, HandleNode)]:
            attr4: KeyNode
            n4, attr4 = attr3.value, nodes[attr3.value]

            result = (attr4.value, attr2.value)

            n5_list = [n for n, attr in nodes_copy.items() if isinstance(attr, KeyNode) and attr.value == result]
            if len(n5_list) == 0:
                n5 = len(nodes_copy)
                attr5 = KeyNode(result)
                attr5.wrap_in.append((n1, n3))
                attr5.known = True
                nodes_copy[n5] = attr5
            else:
                assert len(n5_list) == 1
                n5 = n5_list[0]
                attr5: KeyNode = nodes_copy[n5]

                if (n1, n3) not in attr5.wrap_in:
                    attr5.wrap_in.append((n1, n3))
                if not attr5.known:
                    attr5.known = True

    return nodes_copy


def alphabet_encrypt(nodes: dict[int, HandleNode | KeyNode]) -> dict[int, HandleNode | KeyNode]:
    nodes_copy = nodes.copy()

    for n1, attr1 in [(n, attr) for n, attr in nodes.items() if isinstance(attr, HandleNode)]:
        attr2: KeyNode
        n2, attr2 = attr1.value, nodes[attr1.value]

        for n3, attr3 in [(n, attr) for n, attr in nodes.items() if isinstance(attr, KeyNode) and attr.known]:
            result = (attr3.value, attr2.value)

            n4_list = [n for n, attr in nodes_copy.items() if isinstance(attr, KeyNode) and attr.value == result]
            if len(n4_list) == 0:
                n4 = len(nodes_copy)
                attr4 = KeyNode(result)
                attr4.encrypt_in.append((n1, n3))
                attr4.known = True
                nodes_copy[n4] = attr4
            else:
                assert len(n4_list) == 1
                n4 = n4_list[0]
                attr4: KeyNode = nodes_copy[n4]

                if (n1, n3) not in attr4.encrypt_in:
                    attr4.encrypt_in.append((n1, n3))
                if not attr4.known:
                    attr4.known = True

    return nodes_copy


def alphabet_unwrap(nodes: dict[int, HandleNode | KeyNode]) -> dict[int, HandleNode | KeyNode]:
    nodes_copy = nodes.copy()

    for n1, attr1 in [(n, attr) for n, attr in nodes.items() if isinstance(attr, HandleNode)]:
        attr2: KeyNode
        n2, attr2 = attr1.value, nodes[attr1.value]

        for n3, attr3 in [(n, attr) for n, attr in nodes.items() if isinstance(attr, KeyNode) and attr.known]:

            result = try_decrypt(attr2.value, attr3.value)
            if result is None:
                continue

            n4_list = [n for n, attr in nodes_copy if isinstance(attr, KeyNode) and attr.value == result]
            if len(n4_list) == 0:
                n5 = len(nodes_copy)
                n4 = len(nodes_copy) + 1
                attr5 = HandleNode(n4)
                attr5.unwrap_in.append((n1, n3))
                attr4 = KeyNode(result)
                attr4.handle_in.append(n5)
                nodes_copy[n5] = attr5
                nodes_copy[n4] = attr4
            else:
                assert len(n4_list) == 1
                n4 = n4_list[0]
                attr4: KeyNode = nodes_copy[n4]

                if len(attr4.handle_in) < MAX_N_HANDLES_TO_KEY:
                    n5 = len(nodes_copy)
                    attr5 = HandleNode(n4)
                    attr5.unwrap_in.append((n1, n3))
                    nodes_copy[n5] = attr5

    return nodes_copy


def alphabet_decrypt(nodes: dict[int, HandleNode | KeyNode]) -> dict[int, HandleNode | KeyNode]:
    nodes_copy = nodes.copy()

    for n1, attr1 in [(n, attr) for n, attr in nodes.items() if isinstance(attr, HandleNode)]:
        attr2: KeyNode
        n2, attr2 = attr1.value, nodes[attr1.value]

        for n3, attr3 in [(n, attr) for n, attr in nodes.items() if isinstance(attr, KeyNode) and attr.known]:

            result = try_decrypt(attr2.value, attr3.value)
            if result is None:
                continue

            n4_list = [n for n, attr in nodes_copy.items() if isinstance(attr, KeyNode) and attr.value == result]
            if len(n4_list) == 0:
                n4 = len(nodes_copy)
                attr4 = KeyNode(result)
                attr4.decrypt_in.append((n1, n3))
                attr4.known = True
                nodes_copy[n4] = attr4
            else:
                assert len(n4_list) == 1
                n4 = n4_list[0]
                attr4: KeyNode = nodes_copy[n4]

                if (n1, n3) not in attr4.decrypt_in:
                    attr4.decrypt_in.append((n1, n3))
                if not attr4.known:
                    attr4.known = True

    return nodes_copy


def try_decrypt(decrypting_key: KeyType, key_to_decrypt: KeyType) -> KeyType | None:
    match key_to_decrypt, decrypting_key:
        case (inner_key, encrypting_key), decrypting_key if encrypting_key == decrypting_key:
            return inner_key
        case _:
            return None
