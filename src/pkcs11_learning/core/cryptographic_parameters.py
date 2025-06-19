from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AESECBParams:
    def __str__(self):
        return "AES-ECB"


@dataclass
class AESGCMParams:
    """
    https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
    """
    iv: bytes
    """initialization vector"""
    aad: bytes
    """additional authenticated data"""
    tag_bit_length: int
    """bit length of the authentication tag"""

    @staticmethod
    def default() -> AESGCMParams:
        iv = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        aad = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
        tag_bit_length = 32
        return AESGCMParams(iv, aad, tag_bit_length)

    def __str__(self):
        return "AES-GCM"


@dataclass
class RSAPKCSParams:
    def __str__(self):
        return "RSA-PKCS"


@dataclass
class RSAPKCSOAEPParams:
    """
    https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.1
    """
    hash: str
    """hash function"""
    mfg: str
    """mask generation function"""

    @staticmethod
    def default() -> RSAPKCSOAEPParams:
        return RSAPKCSOAEPParams("SHA256", "MGF1_SHA256")

    def __str__(self):
        return "RSA-PKCS-OAEP"


SymmetricCryptographyParams = AESECBParams | AESGCMParams
AsymmetricCryptographyParams = RSAPKCSParams | RSAPKCSOAEPParams
