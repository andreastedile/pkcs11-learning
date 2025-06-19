import typing

from aalpy import SUL
from PyKCS11 import Session

from .pykcs11_knowledge_set import PyKCS11KnowledgeSet
from .pykcs11_command.command import PyKCS11Command


class PyKCS11SUL(SUL):
    __slots__ = ["session", "knowledge_set", "reset_knowledge_set"]

    def __init__(self,
                 session: Session,
                 knowledge_set: PyKCS11KnowledgeSet,
                 reset_knowledge_set: typing.Callable[[Session, PyKCS11KnowledgeSet], None]):
        super().__init__()

        self.session = session
        self.knowledge_set = knowledge_set
        self.reset_knowledge_set = reset_knowledge_set

    def pre(self):
        pass

    def post(self):
        self.reset_knowledge_set(self.session, self.knowledge_set)

    def step(self, command: PyKCS11Command):
        ret = command.execute(self.knowledge_set, self.session)
        return ret
