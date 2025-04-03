import typing

from aalpy import SUL
from PyKCS11 import Session

from pykcs11_commands import PyKCS11Command
from pykcs11_knowledge_set import PyKCS11KnowledgeSet


class PyKCS11SUL(SUL):
    __slots__ = ["session", "initial_knowledge_factory", "knowledge_set"]

    def __init__(self,
                 session: Session,
                 initial_knowledge_factory: typing.Callable[[Session, PyKCS11KnowledgeSet], None]):
        """
        :param session: 
        :param initial_knowledge_factory: Factory for the attacker's initial knowledge of handles.
        """
        super().__init__()

        self.session = session
        
        objects = session.findObjects()
        for obj in objects:
            session.destroyObject(obj)

        self.initial_knowledge_factory = initial_knowledge_factory

        self.knowledge_set = PyKCS11KnowledgeSet()

    def pre(self):
        self.initial_knowledge_factory(self.session, self.knowledge_set)

    def post(self):
        objects = self.session.findObjects()
        for obj in objects:
            self.session.destroyObject(obj)

    def step(self, command: PyKCS11Command):
        ret = command.execute(self.knowledge_set, self.session)
        return ret
