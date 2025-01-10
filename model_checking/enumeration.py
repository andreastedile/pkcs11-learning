import mathsat
from pysmt.fnode import FNode
from pysmt.shortcuts import *
from pysmt.solvers.msat import MathSAT5Solver

from grammar.my_types import HandleNode, KeyNode


def enumerate_models(graph: dict[int, HandleNode | KeyNode], high_security_node: int) -> list[list[FNode]]:
    high_security_node_attr = graph[high_security_node]
    assert isinstance(high_security_node_attr, KeyNode)
    assert len(high_security_node_attr.decrypt_in) > 0 or len(high_security_node_attr.intruder_decrypt_in) > 0

    assertions = []

    for n, attr in graph.items():
        print(n, attr)

        if isinstance(attr, HandleNode):
            implications_out = []
            for implication in attr.wrap_out:
                implications_out.append(Symbol(str(implication)))
            for implication in attr.unwrap_out:
                implications_out.append(Symbol(str(implication)))
            for implication in attr.encrypt_out:
                implications_out.append(Symbol(str(implication)))
            for implication in attr.decrypt_out:
                implications_out.append(Symbol(str(implication)))
            iff = Iff(Symbol(str(n)), Or(implications_out))
            print(iff)
            assertions.append(iff)

            for implication in attr.wrap_out:
                impl = Implies(Symbol(str(implication)),
                               And(
                                   Symbol(str(implication.handle_of_wrapping_key)),
                                   Symbol(str(implication.handle_of_key_to_be_wrapped)),
                                   Symbol(str(implication.wrapped_key))))
                assertions.append(impl)
            for implication in attr.unwrap_out:
                impl = Implies(Symbol(str(implication)),
                               And(
                                   Symbol(str(implication.handle_of_unwrapping_key)),
                                   Symbol(str(implication.key_to_be_unwrapped)),
                                   Symbol(str(implication.handle_of_recovered_key))))
                assertions.append(impl)
            for implication in attr.encrypt_out:
                impl = Implies(Symbol(str(implication)),
                               And(
                                   Symbol(str(implication.handle_of_encryption_key)),
                                   Symbol(str(implication.key_to_be_encrypted)),
                                   Symbol(str(implication.encrypted_key))))
                assertions.append(impl)
            for implication in attr.decrypt_out:
                impl = Implies(Symbol(str(implication)),
                               And(
                                   Symbol(str(implication.handle_of_decryption_key)),
                                   Symbol(str(implication.key_to_be_decrypted)),
                                   Symbol(str(implication.decrypted_key))))
                assertions.append(impl)

            if attr.unwrap_in is not None:
                iff = Iff(Symbol(str(n)), Symbol(str(attr.unwrap_in)))
                print(iff)
                assertions.append(iff)

                # a command requires both its operands
                impl = Implies(Symbol(str(attr.unwrap_in)),
                               And(
                                   Symbol(str(attr.unwrap_in.handle_of_unwrapping_key)),
                                   Symbol(str(attr.unwrap_in.key_to_be_unwrapped)),
                                   Symbol(str(attr.unwrap_in.handle_of_recovered_key))))
                print(impl)
                assertions.append(impl)
            else:
                assert attr.initial
                # can be freely satisfied
        elif isinstance(attr, KeyNode):
            if n != high_security_node:
                implications_out = []
                for implication in attr.unwrap_out:
                    implications_out.append(Symbol(str(implication)))
                for implication in attr.encrypt_out:
                    implications_out.append(Symbol(str(implication)))
                for implication in attr.decrypt_out:
                    implications_out.append(Symbol(str(implication)))
                for implication in attr.intruder_decrypt_out:
                    implications_out.append(Symbol(str(implication)))
                iff = Iff(Symbol(str(n)), Or(implications_out))
                print(iff)
                assertions.append(iff)

                for implication in attr.unwrap_out:
                    impl = Implies(Symbol(str(implication)),
                                   And(
                                       Symbol(str(implication.handle_of_unwrapping_key)),
                                       Symbol(str(implication.key_to_be_unwrapped)),
                                       Symbol(str(implication.handle_of_recovered_key))))
                    assertions.append(impl)
                for implication in attr.encrypt_out:
                    impl = Implies(Symbol(str(implication)),
                                   And(
                                       Symbol(str(implication.handle_of_encryption_key)),
                                       Symbol(str(implication.key_to_be_encrypted)),
                                       Symbol(str(implication.encrypted_key))))
                    assertions.append(impl)
                for implication in attr.decrypt_out:
                    impl = Implies(Symbol(str(implication)),
                                   And(
                                       Symbol(str(implication.handle_of_decryption_key)),
                                       Symbol(str(implication.key_to_be_decrypted)),
                                       Symbol(str(implication.decrypted_key))))
                    assertions.append(impl)
                for implication in attr.intruder_decrypt_out:
                    impl = Implies(Symbol(str(implication)),
                                   And(
                                       Symbol(str(implication.decryption_key)),
                                       Symbol(str(implication.key_to_be_decrypted)),
                                       Symbol(str(implication.decrypted_key))))
                    assertions.append(impl)
            if attr.initial and attr.copy.known:
                # can be freely satisfied
                pass
            else:
                implications_in = []
                for implication in attr.wrap_in:
                    implications_in.append(Symbol(str(implication)))
                for implication in attr.encrypt_in:
                    implications_in.append(Symbol(str(implication)))
                for implication in attr.decrypt_in:
                    implications_in.append(Symbol(str(implication)))
                for implication in attr.intruder_decrypt_in:
                    implications_in.append(Symbol(str(implication)))

                iif = Iff(Symbol(str(n)), Or(implications_in))
                print(iif)
                assertions.append(iif)

                amo = AtMostOne(implications_in)
                assertions.append(amo)

                # a command requires both its operands
                for implication in attr.wrap_in:
                    impl = Implies(Symbol(str(implication)),
                                   And(
                                       Symbol(str(implication.handle_of_wrapping_key)),
                                       Symbol(str(implication.handle_of_key_to_be_wrapped)),
                                       Symbol(str(implication.wrapped_key))))
                    print(impl)
                    assertions.append(impl)
                for implication in attr.encrypt_in:
                    impl = Implies(Symbol(str(implication)),
                                   And(
                                       Symbol(str(implication.handle_of_encryption_key)),
                                       Symbol(str(implication.key_to_be_encrypted)),
                                       Symbol(str(implication.encrypted_key))))
                    print(impl)
                    assertions.append(impl)
                for implication in attr.decrypt_in:
                    impl = Implies(Symbol(str(implication)),
                                   And(
                                       Symbol(str(implication.handle_of_decryption_key)),
                                       Symbol(str(implication.key_to_be_decrypted)),
                                       Symbol(str(implication.decrypted_key))))
                    print(impl)
                    assertions.append(impl)
                for implication in attr.intruder_decrypt_in:
                    impl = Implies(Symbol(str(implication)),
                                   And(
                                       Symbol(str(implication.decryption_key)),
                                       Symbol(str(implication.key_to_be_decrypted)),
                                       Symbol(str(implication.decrypted_key))))
                    print(impl)
                    assertions.append(impl)

    for n1, attr1 in graph.items():
        if isinstance(attr1, HandleNode):
            for wrap in attr1.wrap_out:
                wrapped_key: KeyNode = graph[wrap.wrapped_key]
                for unwrap in wrapped_key.unwrap_out:
                    if unwrap.handle_of_recovered_key == wrap.handle_of_key_to_be_wrapped:
                        cycle = And(Symbol(str(wrap)), Symbol(str(unwrap)))
                        assertions.append(Not(cycle))
                    elif unwrap.handle_of_recovered_key == wrap.handle_of_wrapping_key:
                        cycle = And(Symbol(str(wrap)), Symbol(str(unwrap)))
                        assertions.append(Not(cycle))
        elif isinstance(attr1, KeyNode):
            for encrypt in attr1.encrypt_out:
                encrypted_key: KeyNode = graph[encrypt.encrypted_key]
                for decrypt in encrypted_key.decrypt_out:
                    if decrypt.decrypted_key == encrypt.key_to_be_encrypted:
                        cycle = And(Symbol(str(encrypt)), Symbol(str(decrypt)))
                        assertions.append(Not(cycle))
            for encrypt in attr1.encrypt_out:
                encrypted_key: KeyNode = graph[encrypt.encrypted_key]
                for intruder_decrypt in encrypted_key.intruder_decrypt_out:
                    if intruder_decrypt.decrypted_key == encrypt.key_to_be_encrypted:
                        cycle = And(Symbol(str(encrypt)), Symbol(str(intruder_decrypt)))
                        assertions.append(Not(cycle))

    assertions.append(Symbol(str(high_security_node)))

    formula: FNode = And(assertions)

    atoms = formula.get_atoms()  # same as formula.get_free_variables() since the problem is purely boolean
    print(f"{len(atoms)} atoms:", *atoms)

    models: list[list[FNode]] = []

    with Solver(name="msat") as msat:
        msat: MathSAT5Solver

        msat.add_assertion(formula)

        def callback(model: list[mathsat.msat_term]):
            nonlocal models
            py_model: list[FNode] = [msat.converter.back(v) for v in model]
            models.append(py_model)
            return 1

        important = [msat.converter.convert(atom) for atom in atoms]

        print("run MathSAT")
        mathsat.msat_all_sat(msat.msat_env(), important, callback)

    return models


def print_model(model: list[FNode]):
    py_model_true_nodes = [node for node in model if node.is_symbol()]  # same as if not node.is_not()
    print(py_model_true_nodes)
