import sys

from PyKCS11 import Session, PyKCS11Error, CK_TRUE, CK_FALSE
from PyKCS11.LowLevel import CKA_WRAP, CKA_UNWRAP, CKA_ENCRYPT, CKA_DECRYPT

from pkcs11_learning.core.abstract_pkcs11_commands import *
from pkcs11_learning.pykcs11_adapt.pykcs11_command.command import PyKCS11Command
from pkcs11_learning.pykcs11_adapt.pykcs11_knowledge_set import PyKCS11KnowledgeSet


class PyKCS11SetWrap(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11SetWrap):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_WRAP, CK_TRUE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11UnsetWrap(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11UnsetWrap):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_WRAP, CK_FALSE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11SetUnwrap(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11SetUnwrap):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_UNWRAP, CK_TRUE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11UnsetUnwrap(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11UnsetUnwrap):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_UNWRAP, CK_FALSE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11SetEncrypt(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11SetEncrypt):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_ENCRYPT, CK_TRUE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11UnsetEncrypt(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11UnsetEncrypt):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_ENCRYPT, CK_FALSE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11SetDecrypt(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11SetDecrypt):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_DECRYPT, CK_TRUE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK


class PyKCS11UnsetDecrypt(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11UnsetDecrypt):
        self.command = command

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle = ks.handle_dict.get(self.command.handle)
        if handle is None:
            return NOT_APPLICABLE

        try:
            session.setAttributeValue(handle, [(CKA_DECRYPT, CK_FALSE)])
        except PyKCS11Error as e:
            print(self.command, e, file=sys.stderr)
            return OP_FAIL

        return OP_OK
