from PyKCS11 import Session, MechanismAESGENERATEKEY, MechanismRSAGENERATEKEYPAIR
from PyKCS11.LowLevel import \
    CKA_VALUE_LEN, CKA_LABEL, CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT, \
    CK_TRUE, CK_FALSE, CK_OBJECT_HANDLE

from my_types import DEFAULT_HANDLE_TEMPLATE
from pykcs11_knowledge_set import PyKCS11KnowledgeSet
from pykcs11_utils import convert_handle_of_public_key_to_rsa_key

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

    templatePub = [
        (CKA_MODULUS_BITS, 512 * 8),
        (CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
    ]
    templatePriv = [
        (CKA_EXTRACTABLE, CK_TRUE),
        (CKA_SENSITIVE, CK_FALSE)
    ]
    pub, priv = session.generateKeyPair(templatePub, templatePriv, MechanismRSAGENERATEKEYPAIR)

    knowledge_set.handle_dict[0] = n0
    knowledge_set.handle_dict[1] = n1
    knowledge_set.secret_key_dict[2] = n2
    knowledge_set.public_key_dict[3] = convert_handle_of_public_key_to_rsa_key(session, pub)
    knowledge_set.handle_dict[4] = priv

    return knowledge_set


def reset_knowledge_set(session: Session, knowledge_set: PyKCS11KnowledgeSet):
    raise NotImplementedError()
