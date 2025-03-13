from dataclasses import dataclass

NOT_APPLICABLE = "not-applicable"
OP_FAIL = "fail"
OP_OK = "ok"


# https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203351

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
class AbstractDeduceEncrypt:
    encryption_key: int
    key_to_be_encrypted: int
    encrypted_key: int

    def __repr__(self):
        return str(self)

    def __str__(self) -> str:
        return f"i-Encrypt({self.encryption_key},{self.key_to_be_encrypted})={self.encrypted_key}"


@dataclass
class AbstractDeduceDecrypt:
    decryption_key: int
    key_to_be_decrypted: int
    decrypted_key: int

    def __repr__(self):
        return str(self)

    def __str__(self) -> str:
        return f"i-Decrypt({self.decryption_key},{self.key_to_be_decrypted})={self.decrypted_key}"


AbstractPKCS11Functions = AbstractPKCS11Wrap | AbstractPKCS11Unwrap | AbstractPKCS11Encrypt | AbstractPKCS11Decrypt | AbstractDeduceDecrypt


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
