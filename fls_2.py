from Crypto.Cipher import AES
from PyKCS11 import Session, MechanismAESGENERATEKEY
from PyKCS11.LowLevel import \
    CKA_VALUE_LEN, CKA_LABEL, CKA_VALUE, \
    CK_OBJECT_HANDLE

from my_types import IV, TAG_BYTES, AAD, AESGCMEncryptionWithDigest, DEFAULT_HANDLE_TEMPLATE
from pykcs11_knowledge_set import PyKCS11KnowledgeSet


def create_knowledge_set(session: Session) -> PyKCS11KnowledgeSet:
    knowledge_set = PyKCS11KnowledgeSet()

    n1_template = [
        (CKA_VALUE_LEN, 16),
        (CKA_LABEL, "0"),
        *DEFAULT_HANDLE_TEMPLATE
    ]
    n1 = session.generateKey(n1_template, MechanismAESGENERATEKEY)

    n2_template = [
        (CKA_VALUE_LEN, 16),
        (CKA_LABEL, "1"),
        *DEFAULT_HANDLE_TEMPLATE
    ]
    n2 = session.generateKey(n2_template, MechanismAESGENERATEKEY)
    k2 = session.getAttributeValue(n2, [CKA_VALUE])[0]

    k3 = b'\x94\xf7\x1b\xa3.\xa0;g\x14\xa7\x1d\xdfL\xf9\x05Q'

    cipher = AES.new(bytes(k2), AES.MODE_GCM, nonce=IV, mac_len=TAG_BYTES)
    cipher = cipher.update(AAD)

    encrypted, tag = cipher.encrypt_and_digest(k3)
    k3_k2 = AESGCMEncryptionWithDigest(encrypted, tag)

    knowledge_set.handle_dict[0] = n1
    knowledge_set.handle_dict[1] = n2
    knowledge_set.senc_dict[2] = k3_k2

    return knowledge_set


def reset_knowledge_set(session: Session, knowledge_set: PyKCS11KnowledgeSet):
    n0 = knowledge_set.handle_dict[0]
    n1 = knowledge_set.handle_dict[1]

    for obj in session.findObjects():
        assert isinstance(obj, CK_OBJECT_HANDLE)

        if obj.value() == n0.value():
            continue
        elif obj.value() == n1.value():
            continue
        else:
            session.destroyObject(obj)

    session.setAttributeValue(n0, DEFAULT_HANDLE_TEMPLATE)
    session.setAttributeValue(n1, DEFAULT_HANDLE_TEMPLATE)

    k3_k2 = knowledge_set.senc_dict[2]

    knowledge_set.clear()
    knowledge_set.handle_dict[0] = n0
    knowledge_set.handle_dict[1] = n1
    knowledge_set.senc_dict[2] = k3_k2
