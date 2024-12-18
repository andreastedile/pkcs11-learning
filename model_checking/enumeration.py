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
                match implication:
                    case (n1, None, n3):
                        implications_out.append(Symbol(f"wrap({n1},{n})={n3}"))
                    case (None, n2, n3):
                        implications_out.append(Symbol(f"wrap({n},{n2})={n3}"))
                    case other:
                        raise ValueError(other)
            for (n2, n3) in attr.unwrap_out:
                implications_out.append(Symbol(f"unwrap({n},{n2})={n3}"))
            for (n2, n3) in attr.encrypt_out:
                implications_out.append(Symbol(f"encrypt({n},{n2})={n3}"))
            for (n2, n3) in attr.decrypt_out:
                implications_out.append(Symbol(f"decrypt({n},{n2})={n3}"))
            iff = Iff(Symbol(str(n)), Or(implications_out))
            print("qui", iff)
            assertions.append(iff)

            for implication in attr.wrap_out:
                match implication:
                    case (n1, None, n3):
                        impl = Implies(Symbol(f"wrap({n1},{n})={n3}"),
                                       And(Symbol(str(n1)), Symbol(str(n)), Symbol(str(n3))))
                        assertions.append(impl)
                    case (None, n2, n3):
                        impl = Implies(Symbol(f"wrap({n},{n2})={n3}"),
                                       And(Symbol(str(n)), Symbol(str(n2)), Symbol(str(n3))))
                        assertions.append(impl)
                    case other:
                        raise ValueError(other)
            for (n2, n3) in attr.unwrap_out:
                impl = Implies(Symbol(f"unwrap({n},{n2})={n3}"),
                               And(Symbol(str(n)), Symbol(str(n2)), Symbol(str(n3))))
                assertions.append(impl)
            for (n2, n3) in attr.encrypt_out:
                impl = Implies(Symbol(f"encrypt({n},{n2})={n3}"),
                               And(Symbol(str(n)), Symbol(str(n2)), Symbol(str(n3))))
                assertions.append(impl)
            for (n2, n3) in attr.decrypt_out:
                impl = Implies(Symbol(f"decrypt({n},{n2})={n3}"),
                               And(Symbol(str(n)), Symbol(str(n2)), Symbol(str(n3))))
                assertions.append(impl)

            match attr.unwrap_in:
                case (e1, e2) if not attr.initial:
                    iff = Iff(Symbol(str(n)), Symbol(f"unwrap({e1},{e2})={n}"))
                    print(iff)
                    assertions.append(iff)

                    # a command requires both its operands
                    impl = Implies(Symbol(f"unwrap({e1},{e2})={n}"),
                                   And(Symbol(str(e1)), Symbol(str(e2)), Symbol(str(n))))
                    print(impl)
                    assertions.append(impl)
                case None:
                    assert attr.initial
                    # can be freely satisfied
        elif isinstance(attr, KeyNode):
            if n != high_security_node:
                implications_out = []
                for (n1, n3) in attr.unwrap_out:
                    implications_out.append(Symbol(f"unwrap({n1},{n})={n3}"))
                for (n1, n3) in attr.encrypt_out:
                    implications_out.append(Symbol(f"encrypt({n1},{n})={n3}"))
                for (n1, n3) in attr.decrypt_out:
                    implications_out.append(Symbol(f"decrypt({n1},{n})={n3}"))
                for implication in attr.intruder_decrypt_out:
                    match implication:
                        case (n1, None, n3):
                            implications_out.append(Symbol(f"intruder_decrypt({n1},{n})={n3}"))
                        case (None, n2, n3):
                            implications_out.append(Symbol(f"intruder_decrypt({n},{n2})={n3}"))
                        case other:
                            raise ValueError(other)
                iff = Iff(Symbol(str(n)), Or(implications_out))
                print(iff)
                assertions.append(iff)

                for (n1, n3) in attr.unwrap_out:
                    impl = Implies(Symbol(f"unwrap({n1},{n})={n3}"),
                                   And(Symbol(str(n1)), Symbol(str(n)), Symbol(str(n3))))
                    assertions.append(impl)
                for (n1, n3) in attr.encrypt_out:
                    impl = Implies(Symbol(f"encrypt({n1},{n})={n3}"),
                                   And(Symbol(str(n1)), Symbol(str(n)), Symbol(str(n3))))
                    assertions.append(impl)
                for (n1, n3) in attr.decrypt_out:
                    impl = Implies(Symbol(f"decrypt({n1},{n})={n3}"),
                                   And(Symbol(str(n1)), Symbol(str(n)), Symbol(str(n3))))
                    assertions.append(impl)
                for implication in attr.intruder_decrypt_out:
                    match implication:
                        case (n1, None, n3):
                            impl = Implies(Symbol(f"intruder_decrypt({n1},{n})={n3}"),
                                           And(Symbol(str(n1)), Symbol(str(n)), Symbol(str(n3))))
                            assertions.append(impl)
                        case (None, n2, n3):
                            impl = Implies(Symbol(f"intruder_decrypt({n},{n2})={n3}"),
                                           And(Symbol(str(n)), Symbol(str(n2)), Symbol(str(n3))))
                            assertions.append(impl)
                        case other:
                            raise ValueError(other)
            if attr.initial and attr.copy.known:
                # can be freely satisfied
                pass
            else:
                implications = []
                for (e1, e2) in attr.wrap_in:
                    implications.append(Symbol(f"wrap({e1},{e2})={n}"))
                for (e1, e2) in attr.encrypt_in:
                    implications.append(Symbol(f"encrypt({e1},{e2})={n}"))
                for (e1, e2) in attr.decrypt_in:
                    implications.append(Symbol(f"decrypt({e1},{e2})={n}"))
                for (e1, e2) in attr.intruder_decrypt_in:
                    implications.append(Symbol(f"intruder_decrypt({e1},{e2})={n}"))

                iif = Iff(Symbol(str(n)), Or(implications))
                print(iif)
                assertions.append(iif)

                amo = AtMostOne(implications)
                assertions.append(amo)

                # a command requires both its operands
                for (e1, e2) in attr.wrap_in:
                    impl = Implies(Symbol(f"wrap({e1},{e2})={n}"),
                                   And(Symbol(str(e1)), Symbol(str(e2)), Symbol(str(n))))
                    print(impl)
                    assertions.append(impl)
                for (e1, e2) in attr.encrypt_in:
                    impl = Implies(Symbol(f"encrypt({e1},{e2})={n}"),
                                   And(Symbol(str(e1)), Symbol(str(e2)), Symbol(str(n))))
                    print(impl)
                    assertions.append(impl)
                for (e1, e2) in attr.decrypt_in:
                    impl = Implies(Symbol(f"decrypt({e1},{e2})={n}"),
                                   And(Symbol(str(e1)), Symbol(str(e2)), Symbol(str(n))))
                    print(impl)
                    assertions.append(impl)
                for (e1, e2) in attr.intruder_decrypt_in:
                    impl = Implies(Symbol(f"intruder_decrypt({e1},{e2})={n}"),
                                   And(Symbol(str(e1)), Symbol(str(e2)), Symbol(str(n))))
                    print(impl)
                    assertions.append(impl)

    for n1, attr1 in graph.items():
        if isinstance(attr1, HandleNode):
            match attr1.unwrap_in:
                case (n2, n3):
                    for implication in attr1.wrap_out:
                        match implication:
                            case (m1, None, m3) if n3 == m3:
                                cycle = And(Symbol(f"unwrap({n2},{n3})={n1}"), Symbol(f"wrap({m1},{n1})={m3}"))
                                print("cycle to be removed:", cycle)
                                assertions.append(Not(cycle))
                            case (None, m2, m3) if n3 == m3:
                                cycle = And(Symbol(f"unwrap({n2},{n3})={n1}"), Symbol(f"wrap({n1},{m2})={m3}"))
                                print("cycle to be removed:", cycle)
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
