from __future__ import annotations

from dataclasses import dataclass

from PyKCS11 import AES_GCM_Mechanism


@dataclass
class AESGCMEncryptionWithDigest:
    encryption: bytes
    digest: bytes

    @staticmethod
    def from_pkcs11_aes_gcm(value: bytes, tag_bytes: int) -> AESGCMEncryptionWithDigest:
        return AESGCMEncryptionWithDigest(value[:-tag_bytes], value[-tag_bytes:])

    def __bytes__(self) -> bytes:
        return self.encryption + self.digest


IV = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
AAD = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
TAG_BYTES = 4
AES_GCM_MECHANISM = (
    AES_GCM_Mechanism(IV, AAD, TAG_BYTES * 8))
