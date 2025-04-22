from Crypto.Cipher import PKCS1_OAEP
from PyKCS11 import PyKCS11Lib, CK_TRUE, RSAOAEPMechanism, MechanismRSAGENERATEKEYPAIR
from PyKCS11.LowLevel import CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT, CKA_WRAP, CKM_SHA_1, CKG_MGF1_SHA1

from pykcs11_utils import convert_handle_of_private_key_to_rsa_key

CLEAR_TEXT = "hello, world!"


def main():
    pkcs11 = PyKCS11Lib()
    lib = pkcs11.load("/usr/local/lib/opencryptoki/libopencryptoki.so")
    slot = 3

    session = lib.openSession(slot)

    templatePub = [(CKA_MODULUS_BITS, 512 * 8), (CKA_PUBLIC_EXPONENT, bytes([3])), (CKA_WRAP, CK_TRUE)]
    templatePriv = []

    (pub, priv) = session.generateKeyPair(templatePub, templatePriv, MechanismRSAGENERATEKEYPAIR)

    converted = convert_handle_of_private_key_to_rsa_key(session, priv)
    cipher = PKCS1_OAEP.new(converted)

    encrypted_by_pkcs11 = session.encrypt(pub, CLEAR_TEXT, RSAOAEPMechanism(CKM_SHA_1, CKG_MGF1_SHA1))
    print("encrypted by pkcs11:              ", bytes(encrypted_by_pkcs11).hex())

    encrypted_by_pkcs11_second = session.encrypt(pub, CLEAR_TEXT, RSAOAEPMechanism(CKM_SHA_1, CKG_MGF1_SHA1))
    print("encrypted by pkcs11 (second time):", bytes(encrypted_by_pkcs11_second).hex())

    # PKCS#1 v1.5 padding introduces randomness
    assert bytes(encrypted_by_pkcs11) != bytes(encrypted_by_pkcs11_second)

    encrypted_by_pkcs11_then_decrypted_by_pkcs11 = session.decrypt(priv, encrypted_by_pkcs11,
                                                                   RSAOAEPMechanism(CKM_SHA_1, CKG_MGF1_SHA1))
    print("encrypted by pkcs11 then decrypted by pkcs11:", bytes(encrypted_by_pkcs11_then_decrypted_by_pkcs11).decode())

    encrypted_by_pkcs11_then_decrypted_by_cipher = cipher.decrypt(bytes(encrypted_by_pkcs11))
    assert encrypted_by_pkcs11_then_decrypted_by_cipher is not None
    print("encrypted by pkcs11 then decrypted by cipher:", encrypted_by_pkcs11_then_decrypted_by_cipher.decode())

    encrypted_by_cipher = cipher.encrypt(CLEAR_TEXT.encode())
    print("encrypted by cipher:              ", encrypted_by_cipher.hex())

    encrypted_by_cipher_second = cipher.encrypt(CLEAR_TEXT.encode())
    print("encrypted by cipher (second time):", encrypted_by_cipher_second.hex())

    encrypted_by_cipher_then_decrypted_by_cipher = cipher.decrypt(encrypted_by_cipher)
    assert encrypted_by_cipher_then_decrypted_by_cipher is not None
    print("encrypted by cipher then decrypted by cipher:", encrypted_by_cipher_then_decrypted_by_cipher.decode())

    encrypted_by_cipher_then_decrypted_by_pkcs11 = session.decrypt(priv, encrypted_by_cipher,
                                                                   RSAOAEPMechanism(CKM_SHA_1, CKG_MGF1_SHA1))
    print("encrypted by cipher then decrypted by pkcs11:", bytes(encrypted_by_cipher_then_decrypted_by_pkcs11).decode())

    session.closeSession()


if __name__ == '__main__':
    main()
