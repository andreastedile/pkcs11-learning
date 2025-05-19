import pkcs11
import os
from base64 import b64encode, b64decode
import uuid

from pkcs11 import Session

SECURDEN_KEY_LABEL_IN_HSM = 'LLB_HSM_TEST'

lib_path = "/usr/local/primus/lib/libprimusP11.so"

slot_id = 0

slot_password = 'PRIMUSDEV'  # the default password when working on grimsel


def encrypt_decrypt():
    session = get_hsm_session()
    keyName = str(uuid.uuid4())
    generate_key(session, keyName)
    payload = b'INPUT DATA'
    ciphertext, iv = encrypt_payload(session, keyName, payload)
    decrypt_payload(session, b64decode(ciphertext), b64decode(iv), keyName)
    session.close()


def generate_key(session, keyName):
    session.generate_key(pkcs11.KeyType.AES, key_length=256, label=keyName, store=True,
                         template={pkcs11.Attribute.EXTRACTABLE: False, pkcs11.Attribute.SENSITIVE: True})
    print("AES key generated with key_length 256 and name: ", keyName)
    print("Encrypt key stored")
    return keyName


def encrypt_payload(session, keyName, payload):
    encrypt_key = load_key_from_keyName(keyName, session)

    # Get an initialisation vector
    iv = session.generate_random(128)  # AES blocks are fixed at 128 bits
    # Encrypt our data
    ciphertext = encrypt_key.encrypt(payload, mechanism_param=iv)

    print("Encrypt payload '" + str(payload) + "' with Key: " + keyName)
    return b64encode(ciphertext), b64encode(iv)


def decrypt_payload(session, ciphertext, iv, keyName):
    decrypt_key = load_key_from_keyName(keyName, session)

    # Encrypt our data
    print("Decrypt ciphertext with Key: " + keyName)
    plaintext = decrypt_key.decrypt(ciphertext, mechanism_param=iv)
    print("Plaintext: " + str(plaintext))


def load_key_from_keyName(keyName, session):
    key = session.get_key(object_class=pkcs11.ObjectClass.SECRET_KEY, label=keyName)
    return key


def get_hsm_session() -> Session:
    try:
        lib = pkcs11.lib(lib_path)
        slots = lib.get_slots(token_present=True)
        actual_slot = None
        actual_slot_id = slot_id
        for each_slot in slots:
            if actual_slot_id == each_slot.slot_id:
                actual_slot = each_slot
                break
        token = actual_slot.get_token()
        session = token.open(rw=True, user_pin=slot_password)
        return session
    except Exception as e:
        print("Exception occurred while creating session")


session: Session = get_hsm_session()
session.close()
