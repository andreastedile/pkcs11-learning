import re

import mathsat
from pysmt.fnode import FNode
from pysmt.shortcuts import *
from pysmt.solvers.msat import MathSAT5Solver

from grammar.my_types import HandleNode, KeyNode
from grammar.visualization import convert_graph_to_dot


def run_sat(graph: dict[int, HandleNode | KeyNode], high_security_node: int, print_models=False):
    high_security_node_attr = graph[high_security_node]
    assert isinstance(high_security_node_attr, KeyNode)
    assert len(high_security_node_attr.decrypt_in) > 0 or len(high_security_node_attr.intruder_decrypt_in) > 0

    assertions = []

    for n, attr in graph.items():
        print(n, attr)

        if isinstance(attr, HandleNode):
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

    assertions.append(Symbol(str(high_security_node)))

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
                py_model_true_nodes = [node for node in model if node.is_symbol()]  # same as if not node.is_not()
                print(f"Model {i}: {py_model_true_nodes}")

        prog = re.compile(r"^(?:\d+|(wrap|unwrap|encrypt|decrypt|intruder_decrypt)\((\d+),(\d+)\)=(\d+))$")

        for i, model in enumerate(models):
            visible_nodes = []
            visible_wrap_implications = []
            visible_unwrap_implications = []
            visible_encrypt_implications = []
            visible_decrypt_implications = []
            visible_intruder_decrypt_implications = []

            for atom in model:
                if atom.is_symbol():
                    name: str = atom.symbol_name()
                    match = re.match(prog, name)
                    if match:
                        if match.group(1) is None:
                            visible_nodes.append(int(name))
                        else:
                            command, param1, param2, result = match.groups()
                            match command:
                                case "wrap":
                                    visible_wrap_implications.append((int(param1), int(param2), int(result)))
                                case "unwrap":
                                    visible_unwrap_implications.append((int(param1), int(param2), int(result)))
                                case "encrypt":
                                    visible_encrypt_implications.append((int(param1), int(param2), int(result)))
                                case "decrypt":
                                    visible_decrypt_implications.append((int(param1), int(param2), int(result)))
                                case "intruder_decrypt":
                                    visible_intruder_decrypt_implications.append(
                                        (int(param1), int(param2), int(result)))
                                case other:
                                    raise ValueError(other)
                    else:
                        print("Input does not match the pattern:", atom.symbol_name())
                else:
                    assert atom.is_not()

            dot = convert_graph_to_dot(graph,
                                       visible_nodes,
                                       visible_wrap_implications,
                                       visible_unwrap_implications,
                                       visible_encrypt_implications,
                                       visible_decrypt_implications,
                                       visible_intruder_decrypt_implications)
            dot.write(f"model_{i}.svg", format="svg")
