from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Util.number import bytes_to_long, inverse
from PyKCS11 import Session
from PyKCS11.LowLevel import *


def convert_handle_of_public_key_to_rsa_key(session: Session, handle_of_public_key: CK_OBJECT_HANDLE) -> RsaKey:
    attributes = session.getAttributeValue(handle_of_public_key, [
        CKA_MODULUS,
        CKA_PUBLIC_EXPONENT,
    ])
    modulus = bytes_to_long(bytes(attributes[0]))
    public_exponent = bytes_to_long(bytes(attributes[1]))

    public_key = RSA.construct((modulus, public_exponent))

    return public_key


def convert_handle_of_private_key_to_rsa_key(session: Session, handle_of_private_key: CK_OBJECT_HANDLE) -> RsaKey:
    """
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203370
    """
    attributes = session.getAttributeValue(handle_of_private_key, [
        CKA_MODULUS,
        CKA_PUBLIC_EXPONENT,
        CKA_PRIVATE_EXPONENT,
        CKA_PRIME_1,
        CKA_PRIME_2,
        CKA_EXPONENT_1,
        CKA_EXPONENT_2,
        CKA_COEFFICIENT
    ])
    modulus = bytes_to_long(bytes(attributes[0]))
    public_exponent = bytes_to_long(bytes(attributes[1]))
    private_exponent = bytes_to_long(bytes(attributes[2]))
    prime1 = bytes_to_long(bytes(attributes[3]))
    prime2 = bytes_to_long(bytes(attributes[4]))
    inv = inverse(prime1, prime2)

    private_key = RSA.construct((modulus, public_exponent, private_exponent, prime1, prime2, inv))

    return private_key
