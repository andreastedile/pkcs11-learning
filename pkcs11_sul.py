import typing

from aalpy import SUL
from pkcs11 import Session, SecretKey, Object

from inputs import PKCS11_SUL_Input


# noinspection PyPep8Naming
class PKCS11_SUL(SUL):
    __slots__ = ["session", "initial_knowledge_factory", "knowledge_set"]

    def __init__(self, session: Session,
                 initial_knowledge_factory: typing.Callable[[Session], dict[int, SecretKey | bytes]]):
        super().__init__()

        self.session = session
        for obj in session.get_objects():
            obj: Object
            obj.destroy()

        self.initial_knowledge_factory = initial_knowledge_factory
        self.knowledge_set: dict[int, SecretKey | bytes] = {}

    def pre(self):
        self.knowledge_set = self.initial_knowledge_factory(self.session)

    def post(self):
        objects = self.session.get_objects()
        for obj in objects:
            obj: Object
            obj.destroy()

    def step(self, input: PKCS11_SUL_Input):
        return input.execute(self.knowledge_set)
