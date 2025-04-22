from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from PyKCS11 import PyKCS11Lib, MechanismRSAGENERATEKEYPAIR, MechanismAESGENERATEKEY, RSAOAEPMechanism
from PyKCS11.LowLevel import \
    CKA_VALUE_LEN, CKA_PUBLIC_EXPONENT, CKA_MODULUS_BITS, \
    CKM_SHA_1, \
    CKG_MGF1_SHA1

from my_types import AES_GCM_MECHANISM
from pykcs11_utils import convert_handle_of_private_key_to_rsa_key

CLEAR_TEXT = "hello, world!"


def main():
    pkcs11 = PyKCS11Lib()
    lib = pkcs11.load("/usr/local/lib/opencryptoki/libopencryptoki.so")
    slot = 3

    session = lib.openSession(slot)

    templatePub = [
        (CKA_MODULUS_BITS, 512 * 8),
        (CKA_PUBLIC_EXPONENT, bytes([3]))
    ]
    templatePriv = []
    (public_key, private_key) = session.generateKeyPair(templatePub, templatePriv,
                                                        MechanismRSAGENERATEKEYPAIR)

    secret_key = session.generateKey([(CKA_VALUE_LEN, 16)], MechanismAESGENERATEKEY)

    # we create a ciphertext that we later decrypt. 
    ciphertext = session.encrypt(public_key, CLEAR_TEXT, RSAOAEPMechanism(CKM_SHA_1, CKG_MGF1_SHA1))

    # wrap and decrypt the key. 
    wrapped_key = session.wrapKey(secret_key, private_key, AES_GCM_MECHANISM)
    decrypted_key = session.decrypt(secret_key, wrapped_key, AES_GCM_MECHANISM)

    # we can obtain an RSA key by importing its value. 
    imported = RSA.import_key(bytes(decrypted_key))

    cipher = PKCS1_OAEP.new(imported)
    cleartext = cipher.decrypt(bytes(ciphertext))
    assert cleartext is not None
    assert CLEAR_TEXT == cleartext.decode()

    converted = convert_handle_of_private_key_to_rsa_key(session, private_key)
    cipher = PKCS1_OAEP.new(converted)

    cleartext = cipher.decrypt(bytes(ciphertext))
    assert cleartext is not None

    assert CLEAR_TEXT == cleartext.decode()

    session.closeSession()


if __name__ == '__main__':
    main()
