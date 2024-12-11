import mathsat
from pysmt.fnode import FNode
from pysmt.shortcuts import *
from pysmt.solvers.msat import MathSAT5Solver

from grammar.my_types import HandleNode, KeyNode


def run_sat(graph: dict[int, HandleNode | KeyNode], high_security_node: int, print_models=False):
    high_security_node_attr = graph[high_security_node]
    assert isinstance(high_security_node_attr, KeyNode)
    assert len(high_security_node_attr.decrypt_in) > 0 or len(high_security_node_attr.intruder_decrypt_in) > 0
    print(graph[0])

    assertions = []

    for n, attr in graph.items():
        if isinstance(attr, HandleNode):
            if attr.initial:
                pass
            else:
                match attr.unwrap_in:
                    case (e1, e2):
                        iif = Iff(Symbol(str(n)), Symbol(f"unwrap({e1},{e2})={n}"))
                        assertions.append(iif)
                        impl = Implies(Symbol(f"unwrap({e1},{e2})={n}"),
                                       And(Symbol(str(e1)), Symbol(str(e2))))
                        assertions.append(impl)
        elif isinstance(attr, KeyNode):
            if attr.initial and attr.copy.known:
                pass
            else:
                if attr.is_implied_by_other_nodes():
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
                    assertions.append(iif)

                    amo = AtMostOne(implications)
                    if amo != TRUE():  # so that it does not appear when printing assertions
                        assertions.append(amo)

                    # a command requires both its operands
                    for (e1, e2) in attr.wrap_in:
                        impl = Implies(Symbol(f"wrap({e1},{e2})={n}"),
                                       And(Symbol(str(e1)), Symbol(str(e2))))
                        assertions.append(impl)
                    for (e1, e2) in attr.encrypt_in:
                        impl = Implies(Symbol(f"encrypt({e1},{e2})={n}"),
                                       And(Symbol(str(e1)), Symbol(str(e2))))
                        assertions.append(impl)
                    for (e1, e2) in attr.decrypt_in:
                        impl = Implies(Symbol(f"decrypt({e1},{e2})={n}"),
                                       And(Symbol(str(e1)), Symbol(str(e2))))
                        assertions.append(impl)
                    for (e1, e2) in attr.intruder_decrypt_in:
                        impl = Implies(Symbol(f"intruder_decrypt({e1},{e2})={n}"),
                                       And(Symbol(str(e1)), Symbol(str(e2))))
                        assertions.append(impl)

    assertions.append(Symbol(str(high_security_node)))

    print(f"{len(assertions)} assertions:")
    for assertion in assertions:
        print(assertion)

    formula: FNode = And(assertions)

    atoms = formula.get_atoms()  # same as formula.get_free_variables() since the problem is purely boolean
    print(f"{len(atoms)} atoms:", *atoms)

    with Solver(name="msat") as msat:
        msat: MathSAT5Solver

        msat.add_assertion(formula)

        models: list[list[FNode]] = []

        def callback(model: list[mathsat.msat_term]):
            nonlocal models
            py_model: list[FNode] = [msat.converter.back(v) for v in model]
            models.append(py_model)
            return 1

        important = [msat.converter.convert(atom) for atom in atoms]

        print("run MathSAT")
        mathsat.msat_all_sat(msat.msat_env(), important, callback)

        print(f"found {len(models)} models")
        if print_models:
            for i, model in enumerate(models):
                py_model_true_nodes = [node for node in model if not node.is_not()]
                print(f"Model {i + 1}: {py_model_true_nodes}")
