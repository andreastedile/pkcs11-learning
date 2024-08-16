import pkcs11
from pkcs11.types import *
import argparse


def main():
    parser = argparse.ArgumentParser(description='wrap-decrypt with DES3')

    parser.add_argument('so', help="Shared object")
    parser.add_argument('token_label', help="Token label")
    parser.add_argument('user_pin', help="User PIN")

    args = parser.parse_args()

    so = args.so
    token_label = args.token_label
    user_pin = args.user_pin

    lib = pkcs11.lib(so)
    token: Token = lib.get_token(token_label=token_label)

    with token.open(user_pin=user_pin) as session:
        print('in the session')

        flag: SecretKey = session.generate_key(KeyType.DES3)
        assert flag[Attribute.SENSITIVE]

        wrapping_key: SecretKey = session.generate_key(KeyType.DES3)

        wrapping_key: WrapMixin
        wrapped_key: bytes = wrapping_key.wrap_key(flag, mechanism=Mechanism.DES3_ECB)
        print('Wrapped key:', ''.join(f'{byte:02X}' for byte in wrapped_key))

        wrapping_key: DecryptMixin
        plaintext: bytes = wrapping_key.decrypt(wrapped_key, mechanism=Mechanism.DES3_ECB)
        print('Plaintext:', ''.join(f'{byte:02X}' for byte in plaintext))


if __name__ == '__main__':
    main()
