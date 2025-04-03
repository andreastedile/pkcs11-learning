from Crypto.Cipher import AES
from PyKCS11 import Session, MechanismAESGENERATEKEY
from PyKCS11.LowLevel import \
    CKA_VALUE_LEN, CKA_LABEL, CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_VALUE, \
    CK_TRUE, CK_FALSE

from my_types import IV, TAG_BYTES, AAD, AESGCMEncryptionWithDigest
from pykcs11_knowledge_set import PyKCS11KnowledgeSet


def fls_2_initial_knowledge_factory(session: Session, ks: PyKCS11KnowledgeSet):
    ks.clear()

    n1_template = [
        (CKA_VALUE_LEN, 16),
        (CKA_LABEL, "0"),
        (CKA_SENSITIVE, CK_TRUE),
        (CKA_EXTRACTABLE, CK_TRUE)
    ]
    n1 = session.generateKey(n1_template, MechanismAESGENERATEKEY)

    n2_template = [
        (CKA_VALUE_LEN, 16),
        (CKA_LABEL, "1"),
        (CKA_SENSITIVE, CK_FALSE),
        (CKA_EXTRACTABLE, CK_TRUE)
    ]
    n2 = session.generateKey(n2_template, MechanismAESGENERATEKEY)
    k2 = session.getAttributeValue(n2, [CKA_VALUE])[0]

    k3 = b'\x94\xf7\x1b\xa3.\xa0;g\x14\xa7\x1d\xdfL\xf9\x05Q'

    cipher = AES.new(bytes(k2), AES.MODE_GCM, nonce=IV, mac_len=TAG_BYTES)
    cipher = cipher.update(AAD)

    encrypted, tag = cipher.encrypt_and_digest(k3)
    k3_k2 = AESGCMEncryptionWithDigest(encrypted, tag)

    ks.handle_dict[0] = n1
    ks.handle_dict[1] = n2
    ks.senc_dict[2] = k3_k2
