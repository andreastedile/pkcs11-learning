import secrets

from PyKCS11 import Session, MechanismAESGENERATEKEY, MechanismRSAGENERATEKEYPAIR
from PyKCS11.LowLevel import *

from pkcs11_learning.pykcs11_adapt.pykcs11_knowledge_set import (PyKCS11KnowledgeSet)
from pkcs11_learning.pykcs11_adapt.pykcs11_utils import convert_handle_of_public_key_to_rsa_key


def create_initial_knowledge_set(session: Session) -> PyKCS11KnowledgeSet:
    n1_template = [
        (CKA_VALUE_LEN, 16),
        (CKA_SENSITIVE, CK_TRUE),
        (CKA_EXTRACTABLE, CK_TRUE),
        (CKA_WRAP_WITH_TRUSTED, CK_TRUE),
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    n1 = session.generateKey(n1_template, MechanismAESGENERATEKEY)

    n2_template = [
        (CKA_LABEL, "dks6"),
    ]
    n2_list = session.findObjects(n2_template)
    assert len(n2_list) == 1, "trusted key with label 'dks6' not found"
    n2 = n2_list[0]

    k3 = secrets.token_bytes(16)

    public_template = [
        (CKA_MODULUS_BITS, 512 * 8),
    ]
    private_template = [
        (CKA_UNWRAP, CK_TRUE),
    ]
    pub, n3 = session.generateKeyPair(public_template, private_template, MechanismRSAGENERATEKEYPAIR)

    knowledge_set = PyKCS11KnowledgeSet()
    knowledge_set.handle_dict[0] = n1
    knowledge_set.handle_dict[1] = n2
    knowledge_set.secret_key_dict[2] = k3
    knowledge_set.public_key_dict[3] = convert_handle_of_public_key_to_rsa_key(session, pub)
    knowledge_set.handle_dict[4] = n3

    return knowledge_set


def reset_knowledge_set(session: Session, knowledge_set: PyKCS11KnowledgeSet):
    n1 = knowledge_set.handle_dict[0]
    n2 = knowledge_set.handle_dict[1]
    k3 = knowledge_set.secret_key_dict[2]
    rsa = knowledge_set.public_key_dict[3]
    n3 = knowledge_set.handle_dict[4]

    for handle in knowledge_set.handle_dict.values():
        if handle == n1:
            continue
        if handle == n2:
            continue
        if handle == n3:
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

    n3_template = [
        (CKA_UNWRAP, CK_TRUE),
    ]
    session.setAttributeValue(n3, n3_template)

    knowledge_set.clear()
    knowledge_set.handle_dict[0] = n1
    knowledge_set.handle_dict[1] = n2
    knowledge_set.secret_key_dict[2] = k3
    knowledge_set.public_key_dict[3] = rsa
    knowledge_set.handle_dict[4] = n3
