import secrets

from Crypto.Cipher import AES
from PyKCS11 import Session, AES_GCM_Mechanism
from PyKCS11.LowLevel import *

from pkcs11_learning.core import AESGCMParams


def dks2_attack_aes_gcm(session: Session):
    """
    The intruder knows the handles h(n1, k1), h(n2, k2) and the key k3;
    n1 has the attributes sensitive and extract set whereas n2 has the attributes unwrap and encrypt set.
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
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_TRUE),
        (CKA_ENCRYPT, CK_TRUE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    n2 = session.generateKey(n2_template)

    k3 = secrets.token_bytes(16)

    # AES-GCM mechanism with default parameters
    params = AESGCMParams.default()
    mechanism = AES_GCM_Mechanism(params.iv, params.aad, params.tag_bit_length)

    # SEncrypt: h(n2, k2), k3 → senc(k3, k2)
    k3_k2 = session.encrypt(n2, k3, mechanism)

    # Unwrap: h(n2, k2), senc(k3, k2) -> h(n3, k3)
    template = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_AES)
    ]
    n3 = session.unwrapKey(n2, k3_k2, template, mechanism)

    # Set_wrap: h(n3, k3) → wrap(n3)
    session.setAttributeValue(n3, [(CKA_WRAP, CK_TRUE)])

    # Wrap: h(n3, k3), h(n1, k1) → senc(k1, k3)
    k1_k3 = session.wrapKey(n3, n1, mechanism)

    # Intruder: senc(k1, k3), k3 → k1
    mac_len = int(params.tag_bit_length / 8)
    cipher = AES.new(k3, AES.MODE_GCM, nonce=params.iv, mac_len=mac_len).update(params.aad)
    recovered = cipher.decrypt_and_verify(bytes(k1_k3)[:-mac_len], bytes(k1_k3)[-mac_len:])

    assert k1 == recovered
