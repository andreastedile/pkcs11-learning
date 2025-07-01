import secrets

from PyKCS11 import Session, Mechanism
from PyKCS11.LowLevel import *


def wrap_and_decrypt_attack_des_ecb(session: Session, patched: bool):
    """
    The intruder knows h(n1, k1) and h(n2, k2).
    The name n2 has the attributes wrap and decrypt set whereas n1 has the attribute sensitive and extract set.
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
        (CKA_VALUE_LEN, 8),
        (CKA_WRAP, CK_TRUE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_TRUE),
    ]
    n2 = session.generateKey(n2_template, Mechanism(CKM_DES_KEY_GEN))

    # Wrap: h(n2, k2), h(n1, k1) → senc(k1, k2)
    k1_k2 = session.wrapKey(n2, n1, Mechanism(CKM_DES_ECB))

    # SDecrypt: h(n2, k2), senc(k1, k2) → k1
    recovered = session.decrypt(n2, k1_k2[:-8] if patched else k1_k2, Mechanism(CKM_DES_ECB))

    assert k1 == bytes(recovered)
