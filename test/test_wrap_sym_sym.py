from Crypto.Cipher import AES
from PyKCS11 import PyKCS11Lib, MechanismAESGENERATEKEY
from PyKCS11.LowLevel import \
    CKA_CLASS, \
    CKA_VALUE, CKA_VALUE_LEN, CKA_KEY_TYPE, \
    CKO_SECRET_KEY, CKK_AES

from my_types import AES_GCM_MECHANISM, IV, TAG_BYTES, AAD

CLEAR_TEXT = "hello, world!"


def main():
    pkcs11 = PyKCS11Lib()
    lib = pkcs11.load("/usr/local/lib/opencryptoki/libopencryptoki.so")
    slot = 3

    session = lib.openSession(slot)

    handle_of_wrapping_key = session.generateKey([(CKA_VALUE_LEN, 16)], MechanismAESGENERATEKEY)
    handle_of_key_to_be_wrapped = session.generateKey([(CKA_VALUE_LEN, 16)], MechanismAESGENERATEKEY)

    handle_of_wrapping_key_value = session.getAttributeValue(handle_of_wrapping_key, [CKA_VALUE])[0]
    handle_of_key_to_be_wrapped_value = session.getAttributeValue(handle_of_key_to_be_wrapped, [CKA_VALUE])[0]

    #

    wrapped_by_pkcs11 = session.wrapKey(handle_of_wrapping_key, handle_of_key_to_be_wrapped, AES_GCM_MECHANISM)
    print("wrapped by pkcs11      :  ", bytes(wrapped_by_pkcs11).hex())

    encrypted_by_pkcs11 = session.encrypt(handle_of_wrapping_key, bytes(handle_of_key_to_be_wrapped_value),
                                          AES_GCM_MECHANISM)
    print("encrypted by pkcs11:      ", bytes(encrypted_by_pkcs11).hex())

    cipher = AES.new(bytes(handle_of_wrapping_key_value), AES.MODE_GCM, nonce=IV, mac_len=TAG_BYTES)
    cipher = cipher.update(AAD)
    encrypted_by_cipher, tag = cipher.encrypt_and_digest(bytes(handle_of_key_to_be_wrapped_value))
    print("encrypted by cipher + tag:", encrypted_by_cipher.hex() + tag.hex())

    # Recover the wrapped key and check it

    unwrap_template = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_AES),
    ]
    handle_of_recovered_key = session.unwrapKey(handle_of_wrapping_key, wrapped_by_pkcs11, unwrap_template,
                                                AES_GCM_MECHANISM)

    encrypted_by_original = session.encrypt(handle_of_key_to_be_wrapped, CLEAR_TEXT, AES_GCM_MECHANISM)
    encrypted_by_recovered = session.encrypt(handle_of_recovered_key, CLEAR_TEXT, AES_GCM_MECHANISM)
    assert bytes(encrypted_by_original) == bytes(encrypted_by_recovered)

    #

    wrapped_by_pkcs11_then_decrypted_by_pkcs11 = session.decrypt(handle_of_wrapping_key, wrapped_by_pkcs11,
                                                                 AES_GCM_MECHANISM)
    print("wrapped by pkcs11 then decrypted by pkcs11:    ", bytes(wrapped_by_pkcs11_then_decrypted_by_pkcs11).hex())

    decipher = AES.new(bytes(handle_of_wrapping_key_value), AES.MODE_GCM, nonce=IV, mac_len=TAG_BYTES)
    decipher = decipher.update(AAD)
    encrypted_by_pkcs11_then_decrypted_by_decipher = decipher.decrypt(bytes(encrypted_by_pkcs11))
    print("encrypted by pkcs11 then decrypted by decipher:",
          encrypted_by_pkcs11_then_decrypted_by_decipher[:-TAG_BYTES].hex())

    session.closeSession()


if __name__ == '__main__':
    main()
