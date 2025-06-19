from PyKCS11 import RSAOAEPMechanism
from PyKCS11.LowLevel import \
    CKM_SHA_1, CKM_SHA256, CKM_SHA512, \
    CKG_MGF1_SHA1, CKG_MGF1_SHA256, CKG_MGF1_SHA512

from pkcs11_learning.core.cryptographic_parameters import RSAPKCSOAEPParams


def RSAPKCSOAEPParams_to_pykcs11(params: RSAPKCSOAEPParams) -> RSAOAEPMechanism:
    hash: int
    mgf: int
    if params.hash == "SHA1":
        hash = CKM_SHA_1
        mgf = CKG_MGF1_SHA1
    elif params.hash == "SHA256":
        hash = CKM_SHA256
        mgf = CKG_MGF1_SHA256
    elif params.hash == "SHA512":
        hash = CKM_SHA512
        mgf = CKG_MGF1_SHA512
    else:
        raise NotImplementedError(params.hash)

    return RSAOAEPMechanism(hash, mgf)
