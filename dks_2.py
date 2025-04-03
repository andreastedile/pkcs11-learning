from PyKCS11 import Session, MechanismAESGENERATEKEY
from PyKCS11.LowLevel import \
    CKA_VALUE_LEN, CKA_LABEL, CKA_SENSITIVE, CKA_EXTRACTABLE, \
    CK_TRUE

from pykcs11_knowledge_set import PyKCS11KnowledgeSet

N0_TEMPLATE = [
    (CKA_VALUE_LEN, 16),
    (CKA_LABEL, "0"),
    (CKA_SENSITIVE, CK_TRUE),
    (CKA_EXTRACTABLE, CK_TRUE)
]

N1_TEMPLATE = [
    (CKA_VALUE_LEN, 16),
    (CKA_LABEL, "1"),
    (CKA_EXTRACTABLE, CK_TRUE),
]


def dks_experiment_2_initial_knowledge_factory(session: Session, ks: PyKCS11KnowledgeSet):
    ks.clear()

    n0 = session.generateKey(N0_TEMPLATE, MechanismAESGENERATEKEY)
    n1 = session.generateKey(N1_TEMPLATE, MechanismAESGENERATEKEY)
    n2 = b'\x94\xf7\x1b\xa3.\xa0;g\x14\xa7\x1d\xdfL\xf9\x05Q'

    ks.handle_dict[0] = n0
    ks.handle_dict[1] = n1
    ks.secret_key_dict[2] = n2
