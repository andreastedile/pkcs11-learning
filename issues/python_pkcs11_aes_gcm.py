# https://github.com/pyauth/python-pkcs11/issues/196

import pkcs11
from pkcs11 import KeyType, Attribute, Mechanism, Token, WrapMixin

if __name__ == "__main__":
    so = "/usr/local/lib/opencryptoki/libopencryptoki.so"
    token_label = "primo"
    user_pin = "1234"

    lib = pkcs11.lib(so)
    token: Token = lib.get_token(token_label=token_label)

    with token.open(user_pin=user_pin) as session:
        # opencryptoki: CKM_RSA_PKCS_KEY_PAIR_GEN 512-4096 bits	
        pub, priv = session.generate_keypair(KeyType.RSA,
                                             key_length=512 * 8,
                                             private_template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
                                             mechanism=Mechanism.RSA_PKCS_KEY_PAIR_GEN)

        # opencryptoki: CKM_AES_KEY_GEN	16-32 bytes	
        secret = session.generate_key(KeyType.AES,
                                      key_length=32 * 8,
                                      template={Attribute.SENSITIVE: False},
                                      mechanism=Mechanism.AES_KEY_GEN)

        secret: WrapMixin
        iv = session.generate_random(128)
        # pkcs11.exceptions.MechanismParamInvalid
        wrapped = secret.wrap_key(priv, mechanism=Mechanism.AES_GCM, mechanism_param=iv)
