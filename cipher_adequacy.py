# https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html

# encrypted by pkcs11		b'!\xabgU\xe8\xf0\xbe\xbf\xfe\x9f\x1b\x0fy\x80\x12\xc6\x13\x94\xdc\xa7'
# encrypted by cipher, tag	b'!\xabgU\xe8\xf0\xbe\xbf\xfe\x9f\x1b\x0fy\x80\x12\xc6' b'\x13\x94\xdc\xa7'
# encrypted by pkcs11 then decrypted by pkcs11	 b'hello, world!\x03\x03\x03'
# encrypted by cipher then decrypted by decipher b'hello, world!\x03\x03\x03'
# encrypted by cipher then decrypted by pkcs11	 b'hello, world!\x03\x03\x03'
# encrypted by pkcs11 then decrypted by decipher b'hello, world!\x03\x03\x03'

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PyKCS11 import PyKCS11Lib, AES_GCM_Mechanism
from PyKCS11.LowLevel import CKA_VALUE_LEN, CKA_VALUE

IV = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
AAD = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
TAG_BYTES = 4
AES_GCM_MECHANISM = AES_GCM_Mechanism(IV, AAD, TAG_BYTES * 8)

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
    print("encrypted by pkcs11\t\t\t", bytes(encrypted_by_pkcs11))

    cipher = AES.new(bytes(secret_key), AES.MODE_GCM, nonce=IV, mac_len=TAG_BYTES)
    cipher = cipher.update(AAD)
    encrypted_by_cipher, tag = cipher.encrypt_and_digest(PADDED)
    print("encrypted by cipher, tag\t", encrypted_by_cipher, tag)

    #

    encrypted_by_pkcs11_then_decrypted_by_pkcs11 = session.decrypt(handle_of_secret_key, encrypted_by_pkcs11,
                                                                   mecha=AES_GCM_MECHANISM)
    print("encrypted by pkcs11 then decrypted by pkcs11\t", bytes(encrypted_by_pkcs11_then_decrypted_by_pkcs11))

    decipher = AES.new(bytes(secret_key), AES.MODE_GCM, nonce=IV, mac_len=TAG_BYTES)
    decipher = decipher.update(AAD)
    encrypted_by_cipher_then_decrypted_by_decipher = decipher.decrypt_and_verify(encrypted_by_cipher, tag)
    print("encrypted by cipher then decrypted by decipher\t", encrypted_by_cipher_then_decrypted_by_decipher)

    encrypted_by_cipher_then_decrypted_by_pkcs11 = session.decrypt(handle_of_secret_key, encrypted_by_cipher + tag,
                                                                   mecha=AES_GCM_MECHANISM)
    print("encrypted by cipher then decrypted by pkcs11\t", bytes(encrypted_by_cipher_then_decrypted_by_pkcs11))

    decipher = AES.new(bytes(secret_key), AES.MODE_GCM, nonce=IV, mac_len=TAG_BYTES)
    decipher = decipher.update(AAD)
    encrypted_by_pkcs11_then_decrypted_by_cipher = decipher.decrypt_and_verify(bytes(encrypted_by_pkcs11[:-TAG_BYTES]),
                                                                               bytes(encrypted_by_pkcs11[-TAG_BYTES:]))
    print("encrypted by pkcs11 then decrypted by decipher\t", encrypted_by_pkcs11_then_decrypted_by_cipher)

    session.closeSession()


if __name__ == '__main__':
    main()
