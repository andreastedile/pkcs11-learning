import argparse

from PyKCS11 import PyKCS11Lib
from dotenv import dotenv_values

from pkcs11_learning.pykcs11_adapt import run

from dks_2_aes_ecb import dks2_attack_aes_ecb
from dks_2_aes_gcm import dks2_attack_aes_gcm
from dks_3_aes_ecb import dks3_attack_aes_ecb
from dks_3_aes_gcm import dks3_attack_aes_gcm
from dks_6_aes_ecb_rsa_pkcs import dks_6_attack_aes_ecb_rsa_pkcs, create_trusted_key
from dks_6_aes_gcm_rsa_pkcs_oaep import dks_6_attack_aes_gcm_rsa_pkcs_oaep
from fls_2_aes_ecb import fls_2_attack_aes_ecb
from fls_2_aes_gcm import fls_2_attack_aes_gcm
from dks_3_des_ecb import dks3_attack_des_ecb
from wrap_and_decrypt_des_ecb import wrap_and_decrypt_attack_des_ecb
from wrap_and_decrypt_aes_ecb import wrap_and_decrypt_attack_aes_ecb
from wrap_and_decrypt_aes_gcm import wrap_and_decrypt_attack_aes_gcm

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reproduce known PKCS#11 attacks")
    parser.add_argument("--opencryptoki", action="store_true", default=False)
    parser.add_argument("--opencryptoki-patched", action="store_true", default=False)
    parser.add_argument("--securosys", action="store_true", default=False)
    args = parser.parse_args()

    if args.opencryptoki_patched:
        values = dotenv_values("opencryptoki.env")
        so, slot, pin = values["SO"], int(values["SLOT"]), values["PIN"]

        lib = PyKCS11Lib()

        print("reproducing attacks using openCryptoki")
        print("reproducing wrap and decrypt DES-ECB")
        run(lib, so, slot, pin, lambda session: wrap_and_decrypt_attack_des_ecb(session, True))
        print("reproducing DKS 3 DES-ECB")
        run(lib, so, slot, pin, lambda session: dks3_attack_des_ecb(session, True))

    elif args.opencryptoki:
        values = dotenv_values("opencryptoki.env")
        so, slot, pin = values["SO"], int(values["SLOT"]), values["PIN"]

        lib = PyKCS11Lib()

        print("reproducing attacks using openCryptoki")
        print("reproducing wrap and decrypt DES-ECB")
        run(lib, so, slot, pin, lambda session: wrap_and_decrypt_attack_des_ecb(session, False))
        print("reproducing wrap and decrypt AES-ECB")
        run(lib, so, slot, pin, wrap_and_decrypt_attack_aes_ecb)
        print("reproducing wrap and decrypt AES-GCM")
        run(lib, so, slot, pin, wrap_and_decrypt_attack_aes_gcm)
        print("reproducing DKS 2 AES-ECB")
        run(lib, so, slot, pin, dks2_attack_aes_ecb)
        print("reproducing DKS 2 AES-GCM")
        run(lib, so, slot, pin, dks2_attack_aes_gcm)
        print("reproducing DKS 3 DES-ECB")
        run(lib, so, slot, pin, lambda session: dks3_attack_des_ecb(session, False))
        print("reproducing DKS 3 AES-ECB")
        run(lib, so, slot, pin, dks3_attack_aes_ecb)
        print("reproducing DKS 3 AES-GCM")
        run(lib, so, slot, pin, dks3_attack_aes_gcm)
        print("reproducing DKS 6 AES-ECB RSA-PKCS")
        create_trusted_key(lib, so, slot, "12345678")
        run(lib, so, slot, pin, dks_6_attack_aes_ecb_rsa_pkcs)
        print("reproducing DKS 6 AES-GCM RSA-PKCS-OAEP")
        run(lib, so, slot, pin, dks_6_attack_aes_gcm_rsa_pkcs_oaep)
        print("reproducing FLS 2 AES-ECB")
        run(lib, so, slot, pin, fls_2_attack_aes_ecb)
        print("reproducing FLS 2 AES-GCM")
        run(lib, so, slot, pin, fls_2_attack_aes_gcm)

    elif args.securosys:
        values = dotenv_values("securosys.env")
        so, slot, pin = values["SO"], int(values["SLOT"]), values["PIN"]

        lib = PyKCS11Lib()

        print("reproducing attacks using Securosys")
        print("reproducing wrap and decrypt AES-ECB")
        run(lib, so, slot, pin, wrap_and_decrypt_attack_aes_ecb)
        print("reproducing wrap and decrypt AES-GCM")
        run(lib, so, slot, pin, wrap_and_decrypt_attack_aes_gcm)
        print("reproducing DKS 2 AES-ECB")
        run(lib, so, slot, pin, dks2_attack_aes_ecb)
        print("reproducing DKS 2 AES-GCM")
        run(lib, so, slot, pin, dks2_attack_aes_gcm)
        print("reproducing DKS 3 AES-ECB")
        run(lib, so, slot, pin, dks3_attack_aes_ecb)
        print("reproducing DKS 3 AES-GCM")
        run(lib, so, slot, pin, dks3_attack_aes_gcm)
        print("reproducing FLS 2 AES-ECB")
        run(lib, so, slot, pin, fls_2_attack_aes_ecb)
        print("reproducing FLS 2 AES-GCM")
        run(lib, so, slot, pin, fls_2_attack_aes_gcm)
