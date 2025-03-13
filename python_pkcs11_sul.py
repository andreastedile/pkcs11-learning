import typing

from aalpy import SUL
from pkcs11 import Session, Object

from python_pkcs11_commands import PythonPKCS11Command, PythonPKCS11DeduceDecryptSymSym
from python_pkcs11_knowledge_set import PythonPKCS11KnowledgeSet


class PythonPKCS11SUL(SUL):
    __slots__ = ["session", "initial_knowledge_factory", "knowledge_set"]

    def __init__(self,
                 session: Session,
                 initial_knowledge_factory: typing.Callable[[Session], PythonPKCS11KnowledgeSet]):
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

        self.knowledge_set = initial_knowledge_factory(self.session)

    def pre(self):
        self.knowledge_set = self.initial_knowledge_factory(self.session)

    def post(self):
        objects = self.session.get_objects()
        for obj in objects:
            obj: Object
            obj.destroy()

    def step(self, command: PythonPKCS11Command):
        return command.execute(self.knowledge_set)
