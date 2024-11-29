type KeyType = int | tuple[KeyType, KeyType]


class HandleNode:
    def __init__(self, points_to: int, unwrap_in: tuple[int, int] | None, use: bool):
        self.points_to = points_to
        self.unwrap_in = unwrap_in
        self.use = use

    def __eq__(self, other):
        if not isinstance(other, HandleNode):
            return False
        return (self.points_to == other.points_to and
                self.unwrap_in == other.unwrap_in)

    def __repr__(self):
        return ("HandleNode(points_to={}, unwrap_in={})"
                .format(self.points_to, self.unwrap_in))


class KeyNode:
    def __init__(self, value: KeyType,
                 known: bool,
                 handle_in: list[int],
                 wrap_in: list[tuple[int, int]],
                 encrypt_in: list[tuple[int, int]],
                 decrypt_in: list[tuple[int, int]]):
        self.value = value
        self.known = known
        self.handle_in = handle_in
        self.wrap_in = wrap_in
        self.encrypt_in = encrypt_in
        self.decrypt_in = decrypt_in

    def __eq__(self, other):
        if not isinstance(other, KeyNode):
            return False
        return (self.value == other.value and
                self.known == other.known and
                self.handle_in == other.handle_in and
                self.wrap_in == other.wrap_in and
                self.encrypt_in == other.encrypt_in and
                self.decrypt_in == other.decrypt_in)

    def __repr__(self):
        return ("KeyNode(value={}, handle_in={}, wrap_in={}, encrypt_in={}, decrypt_in={}, known={})"
                .format(self.value, self.handle_in, self.wrap_in, self.encrypt_in, self.decrypt_in, self.known))
