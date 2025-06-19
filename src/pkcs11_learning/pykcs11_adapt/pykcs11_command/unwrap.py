import sys
import typing

from PyKCS11 import *
from PyKCS11.LowLevel import *

from pkcs11_learning.core.abstract_pkcs11_commands import *
from pkcs11_learning.core.cryptographic_parameters import *
from pkcs11_learning.pykcs11_adapt.pykcs11_command.command import PyKCS11Command
from pkcs11_learning.pykcs11_adapt.cryptographic_parameters_to_pykcs11 import RSAPKCSOAEPParams_to_pykcs11
from pkcs11_learning.pykcs11_adapt.pykcs11_knowledge_set import PyKCS11KnowledgeSet


class PyKCS11UnwrapSymSym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11UnwrapSymSym, params: SymmetricCryptographyParams):
        self.command = command
        self.params = params

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_unwrapping_key = ks.handle_dict.get(self.command.handle_of_unwrapping_key)
        if handle_of_unwrapping_key is None:
            return NOT_APPLICABLE

        try:
            match self.params:
                case AESECBParams():
                    key_to_be_unwrapped = ks.aes_ecb_senc_dict.get(self.command.key_to_be_unwrapped)
                    if key_to_be_unwrapped is None:
                        return NOT_APPLICABLE

                    template = [(CKA_CLASS, CKO_SECRET_KEY), (CKA_KEY_TYPE, CKK_AES)]
                    mechanism = Mechanism(CKM_AES_ECB)
                    handle_of_recovered_key = session.unwrapKey(handle_of_unwrapping_key, key_to_be_unwrapped,
                                                                template, mechanism)

                    if self.command.handle_of_recovered_key in ks.handle_dict:
                        session.destroyObject(handle_of_recovered_key)
                    else:
                        ks.handle_dict[self.command.handle_of_recovered_key] = handle_of_recovered_key
                case AESGCMParams():
                    key_to_be_unwrapped = ks.aes_gcm_senc_dict.get(self.command.key_to_be_unwrapped)
                    if key_to_be_unwrapped is None:
                        return NOT_APPLICABLE

                    template = [(CKA_CLASS, CKO_SECRET_KEY), (CKA_KEY_TYPE, CKK_AES)]
                    mechanism = AES_GCM_Mechanism(self.params.iv, self.params.aad, self.params.tag_bit_length)
                    handle_of_recovered_key = session.unwrapKey(handle_of_unwrapping_key, key_to_be_unwrapped,
                                                                template, mechanism)

                    if self.command.handle_of_recovered_key in ks.handle_dict:
                        session.destroyObject(handle_of_recovered_key)
                    else:
                        ks.handle_dict[self.command.handle_of_recovered_key] = handle_of_recovered_key
                case other:
                    typing.assert_never(other)
            return OP_OK
        except PyKCS11Error as e:
            # diagnosis
            can_unwrap = session.getAttributeValue(handle_of_unwrapping_key, [CKA_UNWRAP])[0]
            if can_unwrap:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL


class PyKCS11UnwrapSymAsym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11UnwrapSymAsym, params: AsymmetricCryptographyParams):
        self.command = command
        self.params = params

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_unwrapping_key = ks.handle_dict.get(self.command.handle_of_unwrapping_key)
        if handle_of_unwrapping_key is None:
            return NOT_APPLICABLE

        try:
            match self.params:
                case RSAPKCSParams():
                    key_to_be_unwrapped = ks.rsa_pkcs_aenc_dict.get(self.command.key_to_be_unwrapped)
                    if key_to_be_unwrapped is None:
                        return NOT_APPLICABLE

                    template = [(CKA_CLASS, CKO_SECRET_KEY), (CKA_KEY_TYPE, CKK_AES)]
                    mechanism = MechanismRSAPKCS1
                    handle_of_recovered_key = session.unwrapKey(handle_of_unwrapping_key, key_to_be_unwrapped,
                                                                template, mechanism)

                    if self.command.handle_of_recovered_key in ks.handle_dict:
                        session.destroyObject(handle_of_recovered_key)
                    else:
                        ks.handle_dict[self.command.handle_of_recovered_key] = handle_of_recovered_key
                case RSAPKCSOAEPParams():
                    key_to_be_unwrapped = ks.rsa_pkcs_oaep_aenc_dict.get(self.command.key_to_be_unwrapped)
                    if key_to_be_unwrapped is None:
                        return NOT_APPLICABLE

                    template = [(CKA_CLASS, CKO_SECRET_KEY), (CKA_KEY_TYPE, CKK_AES)]
                    mechanism = RSAPKCSOAEPParams_to_pykcs11(self.params)
                    handle_of_recovered_key = session.unwrapKey(handle_of_unwrapping_key, key_to_be_unwrapped,
                                                                template, mechanism)

                    if self.command.handle_of_recovered_key in ks.handle_dict:
                        session.destroyObject(handle_of_recovered_key)
                    else:
                        ks.handle_dict[self.command.handle_of_recovered_key] = handle_of_recovered_key
                case other:
                    typing.assert_never(other)
            return OP_OK
        except PyKCS11Error as e:
            # diagnosis
            can_unwrap = session.getAttributeValue(handle_of_unwrapping_key, [CKA_UNWRAP])[0]
            if can_unwrap:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL


class PyKCS11UnwrapAsymSym(PyKCS11Command):
    def __init__(self, command: AbstractPKCS11UnwrapAsymSym, params: SymmetricCryptographyParams):
        self.command = command
        self.params = params

    def __str__(self):
        return str(self.command)

    def execute(self, ks: PyKCS11KnowledgeSet, session: Session) -> str:
        handle_of_unwrapping_key = ks.handle_dict.get(self.command.handle_of_unwrapping_key)
        if handle_of_unwrapping_key is None:
            return NOT_APPLICABLE

        try:
            match self.params:
                case AESECBParams():
                    key_to_be_unwrapped = ks.aes_ecb_senc_dict.get(self.command.key_to_be_unwrapped)
                    if key_to_be_unwrapped is None:
                        return NOT_APPLICABLE

                    template = [(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_RSA)]
                    mechanism = Mechanism(CKM_AES_ECB)
                    handle_of_recovered_key = session.unwrapKey(handle_of_unwrapping_key, key_to_be_unwrapped,
                                                                template, mechanism)

                    if self.command.handle_of_recovered_key in ks.handle_dict:
                        session.destroyObject(handle_of_recovered_key)
                    else:
                        ks.handle_dict[self.command.handle_of_recovered_key] = handle_of_recovered_key
                case AESGCMParams():
                    key_to_be_unwrapped = ks.aes_gcm_senc_dict.get(self.command.key_to_be_unwrapped)
                    if key_to_be_unwrapped is None:
                        return NOT_APPLICABLE

                    template = [(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_RSA)]
                    mechanism = AES_GCM_Mechanism(self.params.iv, self.params.aad, self.params.tag_bit_length)
                    handle_of_recovered_key = session.unwrapKey(handle_of_unwrapping_key, key_to_be_unwrapped,
                                                                template, mechanism)

                    if self.command.handle_of_recovered_key in ks.handle_dict:
                        session.destroyObject(handle_of_recovered_key)
                    else:
                        ks.handle_dict[self.command.handle_of_recovered_key] = handle_of_recovered_key
                case other:
                    typing.assert_never(other)
            return OP_OK
        except PyKCS11Error as e:
            # diagnosis
            can_unwrap = session.getAttributeValue(handle_of_unwrapping_key, [CKA_UNWRAP])[0]
            if can_unwrap:
                print(self.command, e, file=sys.stderr)
            return OP_FAIL
