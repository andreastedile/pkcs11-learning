from PyKCS11 import Session, MechanismAESGENERATEKEY
from PyKCS11.LowLevel import \
    CKA_VALUE_LEN, CKA_LABEL, CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_WRAP, CKA_DECRYPT, \
    CK_TRUE
from pykcs11_knowledge_set import PyKCS11KnowledgeSet


def wrap_and_decrypt_initial_knowledge_factory(session: Session, ks: PyKCS11KnowledgeSet):
    ks.clear()

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
        (CKA_WRAP, CK_TRUE),
        (CKA_DECRYPT, CK_TRUE)
    ]
    n1 = session.generateKey(n1_template, MechanismAESGENERATEKEY)

    ks.handle_dict[0] = n0
    ks.handle_dict[1] = n1
