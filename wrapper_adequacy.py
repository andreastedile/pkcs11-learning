def test_python_pkcs11_adequacy():
    import pkcs11
    from pkcs11 import Session, KeyType, Attribute, Token, WrapMixin, UnwrapMixin, EncryptMixin, DecryptMixin, Mechanism

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

        assert isinstance(pub, WrapMixin)
        assert not isinstance(pub, UnwrapMixin)
        assert isinstance(pub, EncryptMixin)
        assert not isinstance(pub, DecryptMixin)

        assert not isinstance(priv, WrapMixin)
        assert isinstance(priv, UnwrapMixin)
        assert not isinstance(priv, EncryptMixin)
        assert isinstance(priv, DecryptMixin)

        # opencryptoki: CKM_AES_KEY_GEN	16-32 bytes	
        secret = session.generate_key(KeyType.AES,
                                      key_length=32 * 8,
                                      template={Attribute.SENSITIVE: False},
                                      mechanism=Mechanism.AES_KEY_GEN)

        # print("secret key", secret[Attribute.VALUE])

        assert isinstance(secret, WrapMixin)
        assert isinstance(secret, UnwrapMixin)
        assert isinstance(secret, EncryptMixin)
        assert isinstance(secret, DecryptMixin)

        # scenario 1

        # Wrap (sym/asym):
        # pub: WrapMixin
        # wrapped = pub.wrap_key(secret, mechanism=Mechanism.RSA_PKCS)

        # ADecrypt
        # priv: DecryptMixin
        # decrypted = priv.decrypt(wrapped, mechanism=Mechanism.RSA_PKCS)
        # print("decrypted ", decrypted)

        # scenario 2

        # Wrap (asym/sym)
        secret: WrapMixin
        iv = session.generate_random(128)
        wrapped = secret.wrap_key(priv, mechanism=Mechanism.AES_GCM, mechanism_param=iv)


def test_pykcs11_adequacy():
    from PyKCS11 import PyKCS11Lib
    from PyKCS11.LowLevel import CKF_RW_SESSION, \
        CKA_CLASS, CKA_KEY_TYPE, \
        CKA_VALUE_LEN, \
        CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT, CKA_EXTRACTABLE, CKA_SENSITIVE, \
        CK_TRUE, CK_FALSE, \
        CKO_PRIVATE_KEY, \
        CKK_RSA
    from PyKCS11 import AES_GCM_Mechanism

    pkcs11 = PyKCS11Lib()
    lib = pkcs11.load("/usr/local/lib/opencryptoki/libopencryptoki.so")
    slot = 3

    session = pkcs11.openSession(slot, CKF_RW_SESSION)

    pub_template = [
        (CKA_MODULUS_BITS, 512 * 8),
        (CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
    ]
    priv_template = [
        (CKA_EXTRACTABLE, CK_TRUE),
        (CKA_SENSITIVE, CK_FALSE)
    ]

    pub, priv = session.generateKeyPair(pub_template, priv_template)  # default mecha is MechanismRSAGENERATEKEYPAIR

    secret = session.generateKey([(CKA_VALUE_LEN, 16)])  # default mecha is CKM_AES_KEY_GEN

    # iv = session.generateRandom(128)
    iv = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
    aad = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
    aes_gcm_mechanism = AES_GCM_Mechanism(iv, aad, 32)
    wrapped = session.wrapKey(secret, priv, mecha=aes_gcm_mechanism)
    print("wrapped key:")
    print("len:", len(wrapped))
    print("".join(f"{byte:02x}" for byte in wrapped))

    unwrap_template = [
        (CKA_CLASS, CKO_PRIVATE_KEY),
        (CKA_KEY_TYPE, CKK_RSA),
        # (CKA_SENSITIVE, CK_FALSE)
        # (CKA_ENCRYPT, CK_TRUE)
    ]
    recovered = session.unwrapKey(secret, wrapped, unwrap_template, mecha=aes_gcm_mechanism)

    # did unwrap work? try to sign the same thing

    # signed_by_priv = session.sign(priv, "hello, world")
    # signed_by_recovered = session.sign(recovered, "hello, world")
    # print("".join(f"{byte:02x}" for byte in signed_by_priv))
    # print("".join(f"{byte:02x}" for byte in signed_by_recovered))

    decrypted = session.decrypt(secret, wrapped, mecha=aes_gcm_mechanism)
    print("decrypted:")
    print("".join(f"{byte:02x}" for byte in decrypted))

    print("test:")

    signed_by_priv = session.sign(priv, "hello, world")
    signed_by_recovered = session.sign(recovered, "hello, world")
    print("".join(f"{byte:02x}" for byte in signed_by_priv))
    print("".join(f"{byte:02x}" for byte in signed_by_recovered))

    session.closeSession()


if __name__ == "__main__":
    # test_python_pkcs11_adequacy()
    test_pykcs11_adequacy()
