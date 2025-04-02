# https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html

# encrypted by pkcs11 b'\x96\xbc{A\x87\xae\xde\xcf\x9fk\xee"\xc6\xee\xab\x9e\x17\xdc\xa1\xec'
# encrypted by cipher b'\x96\xbc{A\x87\xae\xde\xcf\x9fk\xee"\xc6\xee\xab\x9e'
# decrypted by pkcs11 b'hello, world!\x03\x03\x03'
# decrypted by decipher b'hello, world!\x03\x03\x03'

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PyKCS11 import PyKCS11Lib, AES_GCM_Mechanism
from PyKCS11.LowLevel import CKA_VALUE_LEN, CKA_VALUE

IV = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
AAD = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
AES_GCM_MECHANISM = AES_GCM_Mechanism(IV, AAD, 32)

CLEAR_TEXT = b"hello, world!"
PADDED = pad(CLEAR_TEXT, 16)


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

    decrypted_by_pkcs11 = session.decrypt(handle_of_secret_key, encrypted_by_pkcs11, mecha=AES_GCM_MECHANISM)
    print("decrypted by pkcs11", bytes(decrypted_by_pkcs11))

    decipher = AES.new(bytes(secret_key), AES.MODE_GCM, nonce=IV)
    decipher = decipher.update(AAD)
    decrypted_by_decipher = decipher.decrypt(encrypted_by_cipher)
    print("decrypted by decipher", decrypted_by_decipher)

    session.closeSession()


if __name__ == '__main__':
    main()
