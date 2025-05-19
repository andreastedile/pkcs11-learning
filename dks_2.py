from PyKCS11 import Session, MechanismAESGENERATEKEY
from PyKCS11.LowLevel import \
    CKA_VALUE_LEN, CKA_LABEL, CKA_SENSITIVE, CKA_EXTRACTABLE, \
    CK_TRUE, CK_OBJECT_HANDLE

from my_types import DEFAULT_HANDLE_TEMPLATE
from pykcs11_knowledge_set import PyKCS11KnowledgeSet


def create_knowledge_set(session: Session) -> PyKCS11KnowledgeSet:
    knowledge_set = PyKCS11KnowledgeSet()

    n0_template = [
        (CKA_VALUE_LEN, 16),
        (CKA_LABEL, "0"),
        (CKA_SENSITIVE, CK_TRUE),
        (CKA_EXTRACTABLE, CK_TRUE)
    ]
    n0 = session.generateKey(n0_template, MechanismAESGENERATEKEY)

    n1_template = [
        (CKA_VALUE_LEN, 16),
        (CKA_LABEL, "1"),
        (CKA_EXTRACTABLE, CK_TRUE),
    ]
    n1 = session.generateKey(n1_template, MechanismAESGENERATEKEY)

    n2 = b'\x94\xf7\x1b\xa3.\xa0;g\x14\xa7\x1d\xdfL\xf9\x05Q'

    knowledge_set.handle_dict[0] = n0
    knowledge_set.handle_dict[1] = n1
    knowledge_set.secret_key_dict[2] = n2

    return knowledge_set


def reset_knowledge_set(session: Session, knowledge_set: PyKCS11KnowledgeSet):
    n0 = knowledge_set.handle_dict[0]
    n1 = knowledge_set.handle_dict[1]

    for obj in session.findObjects():
        assert isinstance(obj, CK_OBJECT_HANDLE)

        if obj.value() == n0.value():
            continue
        elif obj.value() == n1.value():
            continue
        else:
            session.destroyObject(obj)

    session.setAttributeValue(n0, DEFAULT_HANDLE_TEMPLATE)
    session.setAttributeValue(n1, DEFAULT_HANDLE_TEMPLATE)

    knowledge_set.clear()
    knowledge_set.handle_dict[0] = n0
    knowledge_set.handle_dict[1] = n1
