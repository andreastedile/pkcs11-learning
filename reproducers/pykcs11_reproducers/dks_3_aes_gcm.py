import secrets

from PyKCS11 import Session, AES_GCM_Mechanism
from PyKCS11.LowLevel import *

from pkcs11_learning.core.cryptographic_parameters import AESGCMParams


def dks3_attack_aes_gcm(session: Session):
    """
    The intruder knows the handles h(n1, k1), h(n2, k2);
    n1 has the attributes sensitive, extract and whereas n2 has the attribute extract set.
    """
    k1 = secrets.token_bytes(16)
    n1_template = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_AES),
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
        (CKA_VALUE_LEN, 16),
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    n2 = session.generateKey(n2_template)

    # AES-GCM mechanism with default parameters
    params = AESGCMParams.default()
    mechanism = AES_GCM_Mechanism(params.iv, params.aad, params.tag_bit_length)

    # Set_wrap: h(n2, k2) → wrap(n2)
    session.setAttributeValue(n2, [(CKA_WRAP, CK_TRUE)])

    # Wrap: h(n2, k2), h(n2, k2) → senc(k2, k2)
    k2_k2 = session.wrapKey(n2, n2, mechanism)

    # Set_unwrap: h(n2, k2) → unwrap(n2)
    session.setAttributeValue(n2, [(CKA_UNWRAP, CK_TRUE)])

    # Unwrap: h(n2, k2), senc(k2, k2) → h(n4, k2)
    template = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_AES),
    ]
    n4 = session.unwrapKey(n2, k2_k2, template, mechanism)

    # Wrap: h(n2, k2), h(n1, k1) → senc(k1, k2)
    k1_k2 = session.wrapKey(n2, n1, mechanism)

    # Set_decrypt: h(n4, k2) → decrypt(n4)
    session.setAttributeValue(n4, [(CKA_DECRYPT, CK_TRUE)])

    # SDecrypt: h(n4, k2), senc(k1, k2) → k1
    recovered = session.decrypt(n4, k1_k2, mechanism)

    assert k1 == bytes(recovered)
