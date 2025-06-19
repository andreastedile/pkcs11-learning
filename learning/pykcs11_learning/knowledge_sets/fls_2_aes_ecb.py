import secrets

from Crypto.Cipher import AES
from PyKCS11 import Session, MechanismAESGENERATEKEY
from PyKCS11.LowLevel import *

from pkcs11_learning.pykcs11_adapt.pykcs11_knowledge_set import PyKCS11KnowledgeSet


def create_initial_knowledge_set_aes_ecb(session: Session) -> PyKCS11KnowledgeSet:
    """
    The intruder knows the handles h(n1, k1), h(n2, k2);
    n1 has the attributes sensitive, extract and whereas n2 has the attribute extract set.
    The intruder also knows {k3}k2.
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

    k2 = secrets.token_bytes(16)
    n2_template = [
        (CKA_VALUE, k2),
        (CKA_VALUE_LEN, 16),
        (CKA_EXTRACTABLE, CK_TRUE),
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    n2 = session.generateKey(n2_template, MechanismAESGENERATEKEY)

    k3 = secrets.token_bytes(16)

    cipher = AES.new(k2, AES.MODE_ECB)
    k3_k2 = cipher.encrypt(k3)

    knowledge_set = PyKCS11KnowledgeSet()
    knowledge_set.handle_dict[0] = n1
    knowledge_set.handle_dict[1] = n2
    knowledge_set.aes_ecb_senc_dict[2] = k3_k2

    return knowledge_set


def reset_knowledge_set_aes_ecb(session: Session, knowledge_set: PyKCS11KnowledgeSet):
    n1 = knowledge_set.handle_dict[0]
    n2 = knowledge_set.handle_dict[1]
    encrypted_key = knowledge_set.aes_ecb_senc_dict[2]

    for handle in knowledge_set.handle_dict.values():
        if handle == n1:
            continue
        if handle == n2:
            continue
        session.destroyObject(handle)

    n1_template = [
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    session.setAttributeValue(n1, n1_template)

    n2_template = [
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    session.setAttributeValue(n2, n2_template)

    knowledge_set.clear()
    knowledge_set.handle_dict[0] = n1
    knowledge_set.handle_dict[1] = n2
    knowledge_set.aes_ecb_senc_dict[2] = encrypted_key
