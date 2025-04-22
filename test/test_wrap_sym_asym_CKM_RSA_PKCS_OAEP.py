from PyKCS11 import PyKCS11Lib, MechanismRSAGENERATEKEYPAIR, \
    MechanismAESGENERATEKEY, RSAOAEPMechanism
from PyKCS11.LowLevel import \
    CKA_CLASS, CKA_WRAP, CKA_VALUE_LEN, CKA_KEY_TYPE, CKA_PUBLIC_EXPONENT, CKA_MODULUS_BITS, \
    CKO_SECRET_KEY, CKK_AES, \
    CK_TRUE, CKM_SHA256, CKG_MGF1_SHA256

from my_types import AES_GCM_MECHANISM

CLEAR_TEXT = "hello, world!"


def main():
    pkcs11 = PyKCS11Lib()
    lib = pkcs11.load("/usr/local/lib/opencryptoki/libopencryptoki.so")
    slot = 3

    session = lib.openSession(slot)

    templatePub = [(CKA_MODULUS_BITS, 512 * 8), (CKA_PUBLIC_EXPONENT, bytes([3])), (CKA_WRAP, CK_TRUE)]
    templatePriv = []

    (handle_of_wrapping_key, handle_of_unwrapping_key) = session.generateKeyPair(templatePub, templatePriv,
                                                                                 MechanismRSAGENERATEKEYPAIR)

    handle_of_key_to_be_wrapped = session.generateKey([(CKA_VALUE_LEN, 16)], MechanismAESGENERATEKEY)

    #

    wrapped_key = session.wrapKey(handle_of_wrapping_key, handle_of_key_to_be_wrapped,
                                  RSAOAEPMechanism(CKM_SHA256, CKG_MGF1_SHA256))

    unwrap_template = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_AES),
    ]
    handle_of_recovered_key = session.unwrapKey(handle_of_unwrapping_key, wrapped_key, unwrap_template,
                                                RSAOAEPMechanism(CKM_SHA256, CKG_MGF1_SHA256))

    #

    encrypted_by_original = session.encrypt(handle_of_key_to_be_wrapped, CLEAR_TEXT, AES_GCM_MECHANISM)
    encrypted_by_recovered = session.encrypt(handle_of_recovered_key, CLEAR_TEXT, AES_GCM_MECHANISM)
    assert bytes(encrypted_by_original) == bytes(encrypted_by_recovered)

    session.closeSession()


if __name__ == '__main__':
    main()
