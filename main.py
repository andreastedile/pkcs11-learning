import argparse

import pkcs11
from aalpy import SUL, RandomWalkEqOracle, run_Lstar, save_automaton_to_file
from aalpy.automata import MealyMachine
from pkcs11.types import *
import graphviz


class PKCS_SUL(SUL):
    __slots__ = ["session", "flag0", "wrapping0", "wrapped0"]

    def __init__(self, session: Session):
        super().__init__()

        self.session = session
        self.flag0: SecretKey | None = None
        self.wrapping0: SecretKey | None = None
        self.wrapped0: bytes | None = None

    def pre(self):
        return

    def post(self):
        # objects = self.session.get_objects()
        # for obj in objects:
        #     obj: pkcs11.types.Object
        #     obj.destroy()

        if self.flag0 is not None:
            self.flag0.destroy()
            self.flag0 = None

        if self.wrapping0 is not None:
            self.wrapping0.destroy()
            self.wrapping0 = None

        self.wrapped0 = None

    def step(self, letter):
        if letter == 'C_GenerateKey@flag0':
            if self.flag0 is not None:
                return 'unapplicable'  # do not overwrite the existing key
            else:
                print("C_GenerateKey@flag0")
                self.flag0 = self.session.generate_key(KeyType.DES3, template={Attribute.SENSITIVE: False})
                return 'ok'

        elif letter == 'C_GenerateKey@wrapping0':
            if self.wrapping0 is not None:
                return 'unapplicable'  # do not overwrite the existing key
            else:
                print("C_GenerateKey@wrapping0")
                self.wrapping0 = self.session.generate_key(KeyType.DES3)
                return 'ok'

        # Attribute.SENSITIVE

        elif letter == 'C_SetAttribute@flag0#SENSITIVE=True':
            if self.flag0 is None:
                return 'unapplicable'
            else:
                print("C_SetAttribute@flag0#SENSITIVE=True")
                self.flag0[Attribute.SENSITIVE] = True
                return 'ok'

        elif letter == 'C_SetAttribute@wrapping0#SENSITIVE=True':
            if self.wrapping0 is None:
                return 'unapplicable'
            else:
                print("C_SetAttribute@wrapping0#SENSITIVE=True")
                self.wrapping0[Attribute.SENSITIVE] = True
                return 'ok'

        # Attribute.WRAP

        # elif letter == 'C_SetAttribute@flag0#WRAP=True':
        #     if self.flag0 is None:
        #         return 'unapplicable'
        #     else:
        #         print("C_SetAttribute@flag0#WRAP=True")
        #         self.flag0[Attribute.WRAP] = True
        #         return 'ok'
        #
        # elif letter == 'C_SetAttribute@flag0#WRAP=False':
        #     if self.flag0 is None:
        #         return 'unapplicable'
        #     else:
        #         print("C_SetAttribute@flag0#WRAP=False")
        #         self.flag0[Attribute.WRAP] = False
        #         return 'ok'

        elif letter == 'C_SetAttribute@wrapping0#WRAP=True':
            if self.wrapping0 is None:
                return 'unapplicable'
            else:
                print("C_SetAttribute@wrapping0#WRAP=True")
                self.wrapping0[Attribute.WRAP] = True
                return 'ok'

        elif letter == 'C_SetAttribute@wrapping0#WRAP=False':
            if self.wrapping0 is None:
                return 'unapplicable'
            else:
                print("C_SetAttribute@wrapping0#WRAP=False")
                self.wrapping0[Attribute.WRAP] = False
                return 'ok'

        # Attribute.EXTRACTABLE

        elif letter == 'C_SetAttribute@flag0#EXTRACTABLE=False':
            if self.flag0 is None:
                return 'unapplicable'
            else:
                print("C_SetAttribute@flag0#EXTRACTABLE=False")
                self.flag0[Attribute.EXTRACTABLE] = False
                return 'ok'

        # Attribute.DECRYPT

        # elif letter == 'C_SetAttribute@flag0#DECRYPT=True':
        #     if self.flag0 is None:
        #         return 'unapplicable'
        #     else:
        #         print("C_SetAttribute@flag0#DECRYPT=True")
        #         self.flag0[Attribute.DECRYPT] = True
        #         return 'ok'
        #
        # elif letter == 'C_SetAttribute@flag0#DECRYPT=False':
        #     if self.flag0 is None:
        #         return 'unapplicable'
        #     else:
        #         print("C_SetAttribute@flag0#DECRYPT=False")
        #         self.flag0[Attribute.DECRYPT] = False
        #         return 'ok'

        elif letter == 'C_SetAttribute@wrapping0#DECRYPT=True':
            if self.wrapping0 is None:
                return 'unapplicable'
            else:
                print("C_SetAttribute@wrapping0#DECRYPT=True")
                self.wrapping0[Attribute.DECRYPT] = True
                return 'ok'

        elif letter == 'C_SetAttribute@wrapping0#DECRYPT=False':
            if self.wrapping0 is None:
                return 'unapplicable'
            else:
                print("C_SetAttribute@wrapping0#DECRYPT=False")
                self.wrapping0[Attribute.DECRYPT] = False
                return 'ok'

        #

        elif letter == 'C_WrapKey@flag0':
            if self.wrapping0 is None:
                return 'unapplicable'
            elif self.flag0 is None:
                return 'unapplicable'
            elif self.wrapped0 is not None:
                return 'unapplicable'  # do not overwrite the existing bytes
            else:
                print("C_WrapKey@flag0")
                self.wrapping0: WrapMixin
                try:
                    self.wrapped0: bytes = self.wrapping0.wrap_key(self.flag0, mechanism=Mechanism.DES3_ECB)
                except Exception:
                    c1 = not self.wrapping0[Attribute.WRAP]
                    c2 = not self.flag0[Attribute.EXTRACTABLE]
                    assert c1 or c2
                    return 'fail'
                return 'ok'

        elif letter == 'C_Decrypt@wrapped0':
            if self.wrapped0 is None:
                return 'unapplicable'
            else:
                print("C_Decrypt@wrapped0")
                self.wrapping0: DecryptMixin
                try:
                    plaintext: bytes = self.wrapping0.decrypt(self.wrapped0, mechanism=Mechanism.DES3_ECB)
                except Exception:
                    assert not self.wrapping0[Attribute.DECRYPT]
                    return 'fail'
                return 'ok'

        #

        elif letter == 'C_GetAttribute@flag0#VALUE':
            if self.flag0 is None:
                return 'unapplicable'
            else:
                print('C_GetAttribute@flag0#VALUE')
                try:
                    value = self.flag0[Attribute.VALUE]
                except pkcs11.exceptions.AttributeSensitive:
                    return 'fail'
                return 'ok'

        else:
            raise Exception(f'Unhandled letter: {letter}')


def main():
    parser = argparse.ArgumentParser(description='PKCS#11 automata learning')

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
        print("in the session")

        sul = PKCS_SUL(session)
        input_alphabet = ['C_GenerateKey@flag0',
                          'C_GenerateKey@wrapping0',
                          'C_SetAttribute@flag0#SENSITIVE=True',
                          'C_SetAttribute@wrapping0#SENSITIVE=True',
                          # 'C_SetAttribute@flag0#WRAP=True',
                          # 'C_SetAttribute@flag0#WRAP=False',
                          'C_SetAttribute@wrapping0#WRAP=True',
                          'C_SetAttribute@wrapping0#WRAP=False',
                          'C_SetAttribute@flag0#EXTRACTABLE=False',
                          # 'C_SetAttribute@flag0#DECRYPT=True',
                          # 'C_SetAttribute@flag0#DECRYPT=False',
                          'C_SetAttribute@wrapping0#DECRYPT=True',
                          'C_SetAttribute@wrapping0#DECRYPT=False',
                          'C_WrapKey@flag0',
                          'C_Decrypt@wrapped0',
                          # 'C_GetAttribute@flag0#VALUE'
                          ]
        eq_oracle = RandomWalkEqOracle(input_alphabet, sul, num_steps=2000, reset_after_cex=True, reset_prob=0.05)
        learned_pkcs: MealyMachine = run_Lstar(input_alphabet, sul, eq_oracle=eq_oracle, automaton_type='mealy',
                                               cache_and_non_det_check=True, print_level=2)

        # from aalpy import visualize_automaton
        # visualize_automaton(learned_pkcs, display_same_state_trans=True)

        save_automaton_to_file(learned_pkcs)

        with open('LearnedModel.dot', 'r') as LearnedModel:
            lines = LearnedModel.readlines()
            filtered_lines = [line for line in lines if "/unapplicable" not in line]
            joined_lines = '\n'.join(filtered_lines)

            graph = graphviz.Source(joined_lines)
            graph.render('SimplifiedLearnedModel', format='pdf', cleanup=True)


if __name__ == '__main__':
    main()
