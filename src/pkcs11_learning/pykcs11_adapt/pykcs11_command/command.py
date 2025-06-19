import abc

from PyKCS11 import Session

from pkcs11_learning.pykcs11_adapt.pykcs11_knowledge_set import PyKCS11KnowledgeSet


class PyKCS11Command(abc.ABC):
    """
    Interface for executing a pykcs11_command with PyKCS11.
    """

    @abc.abstractmethod
    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        raise NotImplementedError

    def __repr__(self):
        return str(self)

    def __str__(self):
        raise NotImplementedError
