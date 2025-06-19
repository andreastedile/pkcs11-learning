from PyKCS11 import Session, MechanismAESGENERATEKEY
from PyKCS11.LowLevel import *

from pkcs11_learning.pykcs11_adapt.pykcs11_knowledge_set import PyKCS11KnowledgeSet


def create_initial_knowledge_set(session: Session) -> PyKCS11KnowledgeSet:
    """
    The intruder knows the handles h(n1, k1), h(n2, k2);
    n1 has the attributes sensitive, extract and whereas n2 has the attribute extract set.
    """
    n1_template = [
        (CKA_VALUE_LEN, 16),
        (CKA_SENSITIVE, CK_TRUE),
        (CKA_EXTRACTABLE, CK_TRUE),
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    n1 = session.generateKey(n1_template, MechanismAESGENERATEKEY)

    n2_template = [
        (CKA_VALUE_LEN, 16),
        (CKA_EXTRACTABLE, CK_TRUE),
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    n2 = session.generateKey(n2_template, MechanismAESGENERATEKEY)

    knowledge_set = PyKCS11KnowledgeSet()
    knowledge_set.handle_dict[0] = n1
    knowledge_set.handle_dict[1] = n2

    return knowledge_set


def reset_knowledge_set(session: Session, knowledge_set: PyKCS11KnowledgeSet):
    n1 = knowledge_set.handle_dict[0]
    n2 = knowledge_set.handle_dict[1]

    for handle in knowledge_set.handle_dict.values():
        if handle == n1:
            continue
        if handle == n2:
            continue
        session.destroyObject(handle)

    n0_template = [
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    session.setAttributeValue(n1, n0_template)

    n1_template = [
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    session.setAttributeValue(n2, n1_template)

    knowledge_set.clear()
    knowledge_set.handle_dict[0] = n1
    knowledge_set.handle_dict[1] = n2
