import sys
import typing

from PyKCS11 import *
from PyKCS11.LowLevel import *

from pkcs11_learning.core.abstract_pkcs11_commands import *
from pkcs11_learning.core.cryptographic_parameters import *
from pkcs11_learning.pykcs11_adapt.pykcs11_command.command import PyKCS11Command
from pkcs11_learning.pykcs11_adapt.cryptographic_parameters_to_pykcs11 import RSAPKCSOAEPParams_to_pykcs11
from pkcs11_learning.pykcs11_adapt.pykcs11_knowledge_set import PyKCS11KnowledgeSet


class PyKCS11WrapSymSym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11WrapSymSym, params: SymmetricCryptographyParams):
        self.command = command
        self.params = params

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_wrapping_key = ks.handle_dict.get(self.command.handle_of_wrapping_key)
        if handle_of_wrapping_key is None:
            return NOT_APPLICABLE

        handle_of_key_to_be_wrapped = ks.handle_dict.get(self.command.handle_of_key_to_be_wrapped)
        if handle_of_key_to_be_wrapped is None:
            return NOT_APPLICABLE

        try:
            match self.params:
                case AESECBParams():
                    mechanism = Mechanism(CKM_AES_ECB)
                    wrapped_key = session.wrapKey(handle_of_wrapping_key, handle_of_key_to_be_wrapped, mechanism)

                    existing_wrapped_key = ks.aes_ecb_senc_dict.get(self.command.wrapped_key)
                    if existing_wrapped_key is None:
                        ks.aes_ecb_senc_dict[self.command.wrapped_key] = bytes(wrapped_key)
                    else:
                        assert bytes(wrapped_key) == existing_wrapped_key
                case AESGCMParams():
                    mechanism = AES_GCM_Mechanism(self.params.iv, self.params.aad, self.params.tag_bit_length)
                    wrapped_key = session.wrapKey(handle_of_wrapping_key, handle_of_key_to_be_wrapped, mechanism)

                    existing_wrapped_key = ks.aes_gcm_senc_dict.get(self.command.wrapped_key)
                    if existing_wrapped_key is None:
                        ks.aes_gcm_senc_dict[self.command.wrapped_key] = bytes(wrapped_key)
                    else:
                        assert bytes(wrapped_key) == existing_wrapped_key
                case other:
                    typing.assert_never(other)
            return OP_OK
        except PyKCS11Error as e:
            # diagnosis
            wrap = session.getAttributeValue(handle_of_wrapping_key, [CKA_WRAP])[0]
            if not wrap:
                return OP_FAIL  # do not log
            wrap_with_trusted = session.getAttributeValue(handle_of_key_to_be_wrapped, [CKA_WRAP_WITH_TRUSTED])[0]
            trusted = session.getAttributeValue(handle_of_wrapping_key, [CKA_TRUSTED])[0]
            if not trusted and wrap_with_trusted:
                return OP_FAIL  # do not log
            print(self.command, e, file=sys.stderr)  # anomaly
            return OP_FAIL


class PyKCS11WrapSymAsym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11WrapSymAsym, params: AsymmetricCryptographyParams):
        self.command = command
        self.params = params

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_wrapping_key = ks.handle_dict.get(self.command.handle_of_wrapping_key)
        if handle_of_wrapping_key is None:
            return NOT_APPLICABLE

        handle_of_key_to_be_wrapped = ks.handle_dict.get(self.command.handle_of_key_to_be_wrapped)
        if handle_of_key_to_be_wrapped is None:
            return NOT_APPLICABLE

        try:
            match self.params:
                case RSAPKCSParams():
                    mechanism = MechanismRSAPKCS1
                    wrapped_key = session.wrapKey(handle_of_wrapping_key, handle_of_key_to_be_wrapped, mechanism)

                    existing_wrapped_key = ks.rsa_pkcs_aenc_dict.get(self.command.wrapped_key)
                    if existing_wrapped_key is None:
                        ks.rsa_pkcs_aenc_dict[self.command.wrapped_key] = bytes(wrapped_key)
                    else:
                        # we cannot compare as this cryptographic mechanism introduces randomness.
                        pass
                case RSAPKCSOAEPParams():
                    mechanism = RSAPKCSOAEPParams_to_pykcs11(self.params)
                    wrapped_key = session.wrapKey(handle_of_wrapping_key, handle_of_key_to_be_wrapped, mechanism)

                    existing_wrapped_key = ks.rsa_pkcs_oaep_aenc_dict.get(self.command.wrapped_key)
                    if existing_wrapped_key is None:
                        ks.rsa_pkcs_oaep_aenc_dict[self.command.wrapped_key] = bytes(wrapped_key)
                    else:
                        # we cannot compare as this cryptographic mechanism introduces randomness.
                        pass
                case other:
                    typing.assert_never(other)
            return OP_OK
        except PyKCS11Error as e:
            # diagnosis
            wrap = session.getAttributeValue(handle_of_wrapping_key, [CKA_WRAP])[0]
            if not wrap:
                return OP_FAIL  # do not log
            wrap_with_trusted = session.getAttributeValue(handle_of_key_to_be_wrapped, [CKA_WRAP_WITH_TRUSTED])[0]
            trusted = session.getAttributeValue(handle_of_wrapping_key, [CKA_TRUSTED])[0]
            if not trusted and wrap_with_trusted:
                return OP_FAIL  # do not log
            print(self.command, e, file=sys.stderr)  # anomaly
            return OP_FAIL


class PyKCS11WrapAsymSym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11WrapAsymSym, params: SymmetricCryptographyParams):
        self.command = command
        self.params = params

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_wrapping_key = ks.handle_dict.get(self.command.handle_of_wrapping_key)
        if handle_of_wrapping_key is None:
            return NOT_APPLICABLE

        handle_of_key_to_be_wrapped = ks.handle_dict.get(self.command.handle_of_key_to_be_wrapped)
        if handle_of_key_to_be_wrapped is None:
            return NOT_APPLICABLE

        try:
            match self.params:
                case AESECBParams():
                    mechanism = Mechanism(CKM_AES_ECB)
                    wrapped_key = session.wrapKey(handle_of_wrapping_key, handle_of_key_to_be_wrapped, mechanism)

                    existing_wrapped_key = ks.aes_ecb_senc_dict.get(self.command.wrapped_key)
                    if existing_wrapped_key is None:
                        ks.aes_ecb_senc_dict[self.command.wrapped_key] = bytes(wrapped_key)
                    else:
                        assert bytes(wrapped_key) == existing_wrapped_key
                case AESGCMParams():
                    mechanism = AES_GCM_Mechanism(self.params.iv, self.params.aad, self.params.tag_bit_length)
                    wrapped_key = session.wrapKey(handle_of_wrapping_key, handle_of_key_to_be_wrapped, mechanism)

                    existing_wrapped_key = ks.aes_gcm_senc_dict.get(self.command.wrapped_key)
                    if existing_wrapped_key is None:
                        ks.aes_gcm_senc_dict[self.command.wrapped_key] = bytes(wrapped_key)
                    else:
                        assert bytes(wrapped_key) == existing_wrapped_key
                case other:
                    typing.assert_never(other)
            return OP_OK
        except PyKCS11Error as e:
            # diagnosis
            wrap = session.getAttributeValue(handle_of_wrapping_key, [CKA_WRAP])[0]
            if not wrap:
                return OP_FAIL  # do not log
            wrap_with_trusted = session.getAttributeValue(handle_of_key_to_be_wrapped, [CKA_WRAP_WITH_TRUSTED])[0]
            trusted = session.getAttributeValue(handle_of_wrapping_key, [CKA_TRUSTED])[0]
            if not trusted and wrap_with_trusted:
                return OP_FAIL  # do not log
            print(self.command, e, file=sys.stderr)  # anomaly
            return OP_FAIL
