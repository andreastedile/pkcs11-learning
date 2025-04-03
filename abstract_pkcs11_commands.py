__all__ = [
    "NOT_APPLICABLE", "OP_OK", "OP_FAIL",

    "AbstractPKCS11Wrap",
    "AbstractPKCS11WrapSymSym", "AbstractPKCS11WrapSymAsym", "AbstractPKCS11WrapAsymSym",

    "AbstractPKCS11Unwrap",
    "AbstractPKCS11UnwrapSymSym", "AbstractPKCS11UnwrapAsymSym", "AbstractPKCS11UnwrapSymAsym",

    "AbstractPKCS11Encrypt",
    "AbstractPKCS11EncryptSymSym", "AbstractPKCS11EncryptSymAsym",

    "AbstractPKCS11Decrypt",
    "AbstractPKCS11DecryptSymSym", "AbstractPKCS11DecryptSymAsym",

    "AbstractDeduceEncrypt",
    "AbstractDeduceEncryptSymSym", "AbstractDeduceEncryptSymAsym",

    "AbstractDeduceDecrypt",
    "AbstractDeduceDecryptSymSym", "AbstractDeduceDecryptAsymSym", "AbstractDeduceDecryptSymAsym",

    "AbstractPKCS11SetWrap", "AbstractPKCS11UnsetWrap",
    "AbstractPKCS11SetUnwrap", "AbstractPKCS11UnsetUnwrap",
    "AbstractPKCS11SetEncrypt", "AbstractPKCS11UnsetEncrypt",
    "AbstractPKCS11SetDecrypt", "AbstractPKCS11UnsetDecrypt"
]

from dataclasses import dataclass

NOT_APPLICABLE = "not-applicable"
OP_FAIL = "fail"
OP_OK = "ok"


# https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html


@dataclass
class AbstractPKCS11Wrap:
    """
    see:
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203354
    """
    handle_of_wrapping_key: int
    handle_of_key_to_be_wrapped: int
    wrapped_key: int

    def __repr__(self):
        return str(self)

    def __str__(self) -> str:
        return f"wrap({self.handle_of_wrapping_key},{self.handle_of_key_to_be_wrapped})={self.wrapped_key}"


@dataclass
class AbstractPKCS11WrapSymSym(AbstractPKCS11Wrap):
    """
    Wrap a secret key with a secret key. 
    """
    pass


@dataclass
class AbstractPKCS11WrapSymAsym(AbstractPKCS11Wrap):
    """
    Wrap a secret key with a public key that supports encryption and decryption.
    """
    pass


@dataclass
class AbstractPKCS11WrapAsymSym(AbstractPKCS11Wrap):
    """
    Wrap a private key with a secret key.
    """
    pass


@dataclass
class AbstractPKCS11Unwrap:
    """
    see:
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203355
    """
    handle_of_unwrapping_key: int
    key_to_be_unwrapped: int
    handle_of_recovered_key: int

    def __repr__(self):
        return str(self)

    def __str__(self) -> str:
        return f"unwrap({self.handle_of_unwrapping_key},{self.key_to_be_unwrapped})={self.handle_of_recovered_key}"


@dataclass
class AbstractPKCS11UnwrapSymSym(AbstractPKCS11Unwrap):
    pass


@dataclass
class AbstractPKCS11UnwrapSymAsym(AbstractPKCS11Unwrap):
    pass


@dataclass
class AbstractPKCS11UnwrapAsymSym(AbstractPKCS11Unwrap):
    pass


@dataclass
class AbstractPKCS11Encrypt:
    """
    see:
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203293
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203294
    """
    handle_of_encryption_key: int
    key_to_be_encrypted: int
    encrypted_key: int

    def __repr__(self):
        return str(self)

    def __str__(self) -> str:
        return f"encrypt({self.handle_of_encryption_key},{self.key_to_be_encrypted})={self.encrypted_key}"


@dataclass
class AbstractPKCS11EncryptSymSym(AbstractPKCS11Encrypt):
    pass


@dataclass
class AbstractPKCS11EncryptSymAsym(AbstractPKCS11Encrypt):
    pass


@dataclass
class AbstractPKCS11Decrypt:
    """
    see:
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203304
    https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203305
    """
    handle_of_decryption_key: int
    key_to_be_decrypted: int
    decrypted_key: int

    def __repr__(self):
        return str(self)

    def __str__(self) -> str:
        return f"decrypt({self.handle_of_decryption_key},{self.key_to_be_decrypted})={self.decrypted_key}"


@dataclass
class AbstractPKCS11DecryptSymSym(AbstractPKCS11Decrypt):
    pass


@dataclass
class AbstractPKCS11DecryptSymAsym(AbstractPKCS11Decrypt):
    pass


@dataclass
class AbstractDeduceEncrypt:
    encryption_key: int
    key_to_be_encrypted: int
    encrypted_key: int

    def __repr__(self):
        return str(self)

    def __str__(self) -> str:
        return f"deduceEncrypt({self.encryption_key},{self.key_to_be_encrypted})={self.encrypted_key}"


@dataclass
class AbstractDeduceEncryptSymSym(AbstractDeduceEncrypt):
    pass


@dataclass
class AbstractDeduceEncryptSymAsym(AbstractDeduceEncrypt):
    pass


@dataclass
class AbstractDeduceDecrypt:
    decryption_key: int
    key_to_be_decrypted: int
    decrypted_key: int

    def __repr__(self):
        return str(self)

    def __str__(self) -> str:
        return f"deduceDecrypt({self.decryption_key},{self.key_to_be_decrypted})={self.decrypted_key}"


@dataclass
class AbstractDeduceDecryptSymSym(AbstractDeduceDecrypt):
    pass


@dataclass
class AbstractDeduceDecryptAsymSym(AbstractDeduceDecrypt):
    pass


@dataclass
class AbstractDeduceDecryptSymAsym(AbstractDeduceDecrypt):
    pass


@dataclass
class AbstractPKCS11SetWrap:
    handle: int

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"setWrap({self.handle})"


@dataclass
class AbstractPKCS11UnsetWrap:
    handle: int

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"unsetWrap({self.handle})"


@dataclass
class AbstractPKCS11SetUnwrap:
    handle: int

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"setUnwrap({self.handle})"


@dataclass
class AbstractPKCS11UnsetUnwrap:
    handle: int

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"unsetUnwrap({self.handle})"


@dataclass
class AbstractPKCS11SetEncrypt:
    handle: int

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"setEncrypt({self.handle})"


@dataclass
class AbstractPKCS11UnsetEncrypt:
    handle: int

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"unsetEncrypt({self.handle})"


@dataclass
class AbstractPKCS11SetDecrypt:
    handle: int

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"setDecrypt({self.handle})"


@dataclass
class AbstractPKCS11UnsetDecrypt:
    handle: int

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"unsetDecrypt({self.handle})"
