# https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html

# encrypted by pkcs11 b'!\xbfQ\xc1\xc5\x03G\x15\xaex\x9c\xe7\xd2\x97\x9a\xfa\xde'
# encrypted by cipher b'!\xbfQ\xc1\xc5\x03G\x15\xaex\x9c\xe7\xd2'
# encrypted by pkcs11 then decrypted by pkcs11	 b'hello, world!'
# encrypted by cipher then decrypted by decipher	 b'hello, world!'
# encrypted by cipher then decrypted by pkcs11	 PyKCS11.PyKCS11Error: CKR_ENCRYPTED_DATA_INVALID (0x00000040)
# encrypted by pkcs11 then decrypted by decipher	 b'hello, world!l\x98n\xd8'

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PyKCS11 import PyKCS11Lib, AES_GCM_Mechanism
from PyKCS11.LowLevel import CKA_VALUE_LEN, CKA_VALUE

IV = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
AAD = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
AES_GCM_MECHANISM = AES_GCM_Mechanism(IV, AAD, 32)

CLEAR_TEXT = b"hello, world!"
PADDED = pad(CLEAR_TEXT, 16)


# PADDED = CLEAR_TEXT


def main():
    pkcs11 = PyKCS11Lib()
    lib = pkcs11.load("/usr/local/lib/opencryptoki/libopencryptoki.so")
    slot = 3

    session = lib.openSession(slot)

    handle_of_secret_key = session.generateKey([(CKA_VALUE_LEN, 16)])  # default mecha is CKM_AES_KEY_GEN
    secret_key: list[int] = session.getAttributeValue(handle_of_secret_key, [CKA_VALUE])[0]

    #

    encrypted_by_pkcs11 = session.encrypt(handle_of_secret_key, PADDED, mecha=AES_GCM_MECHANISM)
    print("encrypted by pkcs11", bytes(encrypted_by_pkcs11))

    cipher = AES.new(bytes(secret_key), AES.MODE_GCM, nonce=IV)
    cipher = cipher.update(AAD)
    encrypted_by_cipher = cipher.encrypt(PADDED)
    print("encrypted by cipher", encrypted_by_cipher)

    #

    encrypted_by_pkcs11_then_decrypted_by_pkcs11 = session.decrypt(handle_of_secret_key, encrypted_by_pkcs11,
                                                                   mecha=AES_GCM_MECHANISM)
    print("encrypted by pkcs11 then decrypted by pkcs11\t", bytes(encrypted_by_pkcs11_then_decrypted_by_pkcs11))

    decipher = AES.new(bytes(secret_key), AES.MODE_GCM, nonce=IV)
    decipher = decipher.update(AAD)
    encrypted_by_cipher_then_decrypted_by_decipher = decipher.decrypt(encrypted_by_cipher)
    print("encrypted by cipher then decrypted by decipher\t", encrypted_by_cipher_then_decrypted_by_decipher)

    # encrypted_by_cipher_then_decrypted_by_pkcs11 = session.decrypt(handle_of_secret_key, encrypted_by_cipher,
    #                                                                mecha=AES_GCM_MECHANISM)
    # print("encrypted by cipher then decrypted by pkcs11\t", bytes(encrypted_by_cipher_then_decrypted_by_pkcs11))
    print("encrypted by cipher then decrypted by pkcs11\t",
          "PyKCS11.PyKCS11Error: CKR_ENCRYPTED_DATA_INVALID (0x00000040)")

    decipher = AES.new(bytes(secret_key), AES.MODE_GCM, nonce=IV)
    decipher = decipher.update(AAD)
    encrypted_by_pkcs11_then_decrypted_by_cipher = decipher.decrypt(bytes(encrypted_by_pkcs11))
    print("encrypted by pkcs11 then decrypted by decipher\t", encrypted_by_pkcs11_then_decrypted_by_cipher)

    session.closeSession()


if __name__ == '__main__':
    main()
