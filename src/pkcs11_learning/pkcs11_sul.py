import logging

from aalpy import SUL
from pkcs11 import Session, SecretKey, Object

from pkcs11_learning.commands import AttackerCommand
from pkcs11_learning.graph import HandleNode, KeyNode

logger = logging.getLogger(__name__)


# noinspection PyPep8Naming
class PKCS11_SUL(SUL):
    __slots__ = ["session", "initial_knowledge", "knowledge_set"]

    def __init__(self, session: Session, initial_knowledge: dict[int, HandleNode | KeyNode]):
        super().__init__()

        self.session = session
        for obj in session.get_objects():
            obj: Object
            obj.destroy()

        self.initial_knowledge = initial_knowledge.copy()
        self.knowledge_set: dict[int, SecretKey | bytes] = {}

    def pre(self):
        raise NotImplementedError

    def post(self):
        objects = self.session.get_objects()
        for obj in objects:
            obj: Object
            obj.destroy()

        self.knowledge_set.clear()

    def step(self, command: AttackerCommand):
        logger.debug(command)
        result = command.execute(self.knowledge_set)
        logger.debug(result)

        return result
