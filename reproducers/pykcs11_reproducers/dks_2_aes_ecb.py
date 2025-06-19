import secrets

from Crypto.Cipher import AES
from PyKCS11 import Session, Mechanism
from PyKCS11.LowLevel import *


def dks2_attack_aes_ecb(session: Session):
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

    # SEncrypt: h(n2, k2), k3 → senc(k3, k2)
    k3_k2 = session.encrypt(n2, k3, Mechanism(CKM_AES_ECB))

    # Unwrap: h(n2, k2), senc(k3, k2) -> h(n3, k3)
    template = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_AES)
    ]
    n3 = session.unwrapKey(n2, k3_k2, template, Mechanism(CKM_AES_ECB))

    # Set_wrap: h(n3, k3) → wrap(n3)
    session.setAttributeValue(n3, [(CKA_WRAP, CK_TRUE)])

    # Wrap: h(n3, k3), h(n1, k1) → senc(k1, k3)
    k1_k3 = session.wrapKey(n3, n1, Mechanism(CKM_AES_ECB))

    # Intruder: senc(k1, k3), k3 → k1
    cipher = AES.new(k3, AES.MODE_ECB)
    recovered = cipher.decrypt(bytes(k1_k3))

    assert k1 == recovered
