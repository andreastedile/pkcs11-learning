from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, inverse
from PyKCS11 import PyKCS11Lib, CK_TRUE, MechanismRSAPKCS1, MechanismRSAGENERATEKEYPAIR
from PyKCS11.LowLevel import CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT, \
    CKA_WRAP, CKA_MODULUS, CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2, CKA_EXPONENT_1, \
    CKA_EXPONENT_2, CKA_COEFFICIENT

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
    cipher = PKCS1_v1_5.new(converted)

    encrypted_by_pkcs11 = session.encrypt(pub, CLEAR_TEXT, MechanismRSAPKCS1)
    print("encrypted by pkcs11:              ", bytes(encrypted_by_pkcs11).hex())

    encrypted_by_pkcs11_second = session.encrypt(pub, CLEAR_TEXT, MechanismRSAPKCS1)
    print("encrypted by pkcs11 (second time):", bytes(encrypted_by_pkcs11_second).hex())

    # PKCS#1 v1.5 padding introduces randomness
    assert bytes(encrypted_by_pkcs11) != bytes(encrypted_by_pkcs11_second)

    encrypted_by_pkcs11_then_decrypted_by_pkcs11 = session.decrypt(priv, encrypted_by_pkcs11, MechanismRSAPKCS1)
    print("encrypted by pkcs11 then decrypted by pkcs11:", bytes(encrypted_by_pkcs11_then_decrypted_by_pkcs11).decode())

    encrypted_by_pkcs11_then_decrypted_by_cipher = cipher.decrypt(bytes(encrypted_by_pkcs11), None,
                                                                  len(CLEAR_TEXT))
    assert encrypted_by_pkcs11_then_decrypted_by_cipher is not None
    print("encrypted by pkcs11 then decrypted by cipher:", encrypted_by_pkcs11_then_decrypted_by_cipher.decode())

    encrypted_by_cipher = cipher.encrypt(CLEAR_TEXT.encode())
    print("encrypted by cipher:              ", encrypted_by_cipher.hex())

    encrypted_by_cipher_second = cipher.encrypt(CLEAR_TEXT.encode())
    print("encrypted by cipher (second time):", encrypted_by_cipher_second.hex())

    encrypted_by_cipher_then_decrypted_by_cipher = cipher.decrypt(encrypted_by_cipher, None, len(CLEAR_TEXT))
    assert encrypted_by_cipher_then_decrypted_by_cipher is not None
    print("encrypted by cipher then decrypted by cipher:", encrypted_by_cipher_then_decrypted_by_cipher.decode())

    encrypted_by_cipher_then_decrypted_by_pkcs11 = session.decrypt(priv, encrypted_by_cipher, MechanismRSAPKCS1)
    print("encrypted by cipher then decrypted by pkcs11:", bytes(encrypted_by_cipher_then_decrypted_by_pkcs11).decode())

    session.closeSession()


if __name__ == '__main__':
    main()
