import typing

from aalpy import SUL
from pkcs11 import Session, SecretKey, Object

from pkcs11_sul_inputs import PKCS11_SUL_Input


# noinspection PyPep8Naming
class PKCS11_SUL(SUL):
    __slots__ = ["session", "initial_knowledge_factory", "handles_knowledge_set", "key_knowledge_set"]

    def __init__(self, session: Session,
                 initial_knowledge_factory: typing.Callable[[Session], tuple[dict[int, SecretKey], dict[int, bytes]]]):
        """
        :param session: 
        :param initial_knowledge_factory: Factory for the attacker's initial knowledge of handles.
        """
        super().__init__()

        self.session = session
        for obj in session.get_objects():
            obj: Object
            obj.destroy()

        self.initial_knowledge_factory = initial_knowledge_factory

        self.handles_knowledge_set: dict[int, SecretKey] = {}
        self.key_knowledge_set: dict[int, bytes] = {}

    def pre(self):
        self.handles_knowledge_set, self.key_knowledge_set = self.initial_knowledge_factory(self.session)

    def post(self):
        objects = self.session.get_objects()
        for obj in objects:
            obj: Object
            obj.destroy()

    def step(self, pkcs11_input: PKCS11_SUL_Input):
        return pkcs11_input.execute(self.handles_knowledge_set, self.key_knowledge_set)
