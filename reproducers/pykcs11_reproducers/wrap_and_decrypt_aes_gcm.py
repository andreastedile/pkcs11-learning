import secrets

from PyKCS11 import Session, AES_GCM_Mechanism
from PyKCS11.LowLevel import *

from pkcs11_learning.core.cryptographic_parameters import AESGCMParams


def wrap_and_decrypt_attack_aes_gcm(session: Session):
    """
    The intruder knows h(n1, k1) and h(n2, k2).
    The name n2 has the attributes wrap and decrypt set whereas n1 has the attribute sensitive and extract set.
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
        (CKA_VALUE_LEN, 16),
        (CKA_WRAP, CK_TRUE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_TRUE),
    ]
    n2 = session.generateKey(n2_template)

    # AES-GCM mechanism with default parameters
    params = AESGCMParams.default()
    mechanism = AES_GCM_Mechanism(params.iv, params.aad, params.tag_bit_length)

    # Wrap: h(n2, k2), h(n1, k1) → senc(k1, k2)
    k0_k1 = session.wrapKey(n2, n1, mechanism)

    # SDecrypt: h(n2, k2), senc(k1, k2) → k1
    recovered = session.decrypt(n2, k0_k1, mechanism)

    assert k1 == bytes(recovered)
