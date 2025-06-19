import secrets

from Crypto.Cipher import AES
from PyKCS11 import Session, AES_GCM_Mechanism
from PyKCS11.LowLevel import *

from pkcs11_learning.core.cryptographic_parameters import AESGCMParams


def fls_2_attack_aes_gcm(session: Session):
    """
    The intruder knows the handles h(n1, k1), h(n2, k2);
    n1 has the attributes sensitive, extract and whereas n2 has the attribute extract set.
    The intruder also knows {k3}k2.
    """
    k1 = secrets.token_bytes(16)
    n1_template = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_AES),
        (CKA_VALUE, k1),
        (CKA_SENSITIVE, CK_TRUE),
        (CKA_EXTRACTABLE, CK_TRUE),
    ]
    n1 = session.createObject(n1_template)

    k2 = secrets.token_bytes(16)
    n2_template = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_AES),
        (CKA_VALUE, k2),
        (CKA_SENSITIVE, CK_TRUE),
        (CKA_EXTRACTABLE, CK_TRUE),
    ]
    n2 = session.createObject(n2_template)

    k3 = secrets.token_bytes(16)

    # AES-GCM mechanism with default parameters
    params = AESGCMParams.default()
    mechanism = AES_GCM_Mechanism(params.iv, params.aad, params.tag_bit_length)

    cipher = AES.new(k2, AES.MODE_GCM, nonce=params.iv, mac_len=int(params.tag_bit_length / 8)).update(params.aad)
    k3_k2, digest = cipher.encrypt_and_digest(k3)

    # Set_unwrap: h(n2, k2) → unwrap(n2, T)
    session.setAttributeValue(n2, [(CKA_UNWRAP, CK_TRUE)])

    # Unwrap: h(n2, k2), {k3}k2 → h(n3, k3)
    template = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_AES)
    ]
    n3 = session.unwrapKey(n2, k3_k2 + digest, template, mechanism)
    # Unwrap: h(n2, k2), {k3}k2 -> h(n4, k3)
    n4 = session.unwrapKey(n2, k3_k2 + digest, template, mechanism)

    # Set_wrap: h(n3, k3) → wrap(n3, T)
    session.setAttributeValue(n3, [(CKA_WRAP, CK_TRUE)])

    # Wrap: h(n3, k3), h(n1, k1) → {k1}k3
    k1_k3 = session.wrapKey(n3, n1, mechanism)

    # Set_decrypt: h(n4, k3) → decrypt(n4, T)
    session.setAttributeValue(n4, [(CKA_UNWRAP, CK_TRUE)])

    # Decrypt: h(n4, k3), {k1}k3 → k1
    recovered = session.decrypt(n4, k1_k3, mechanism)

    assert k1 == bytes(recovered)
