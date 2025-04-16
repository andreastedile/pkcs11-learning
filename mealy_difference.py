from automata.fa.dfa import DFA
from automata.fa.nfa import NFA
from pydot import Dot, graph_from_dot_file, Node, Edge
from pygraphviz import AGraph


def unquote(quoted: str) -> str:
    quoted = quoted.removeprefix("\"")
    unquoted = quoted.removesuffix("\"")
    return unquoted


def remove_extra_node(nodes: list[Node], edges: list[Edge]):
    start0 = nodes.pop()
    assert start0.get_name() == "__start0"

    start0_to_s0_edge = edges.pop()
    assert start0_to_s0_edge.get_source() == "__start0"
    assert start0_to_s0_edge.get_destination() == "s0"


def convert_to_nfa(nodes: list[Node], edges: list[Edge], input_symbols: set[str]) -> NFA:
    states = set()
    for node in nodes:
        states.add(node.get_name())

    transitions = dict()
    for node in nodes:
        transitions[node.get_name()] = dict()
    for edge in edges:
        source = edge.get_source()
        attributes = edge.get_attributes()
        label = attributes["label"]
        transitions[source][unquote(label)] = set()
    for edge in edges:
        source = edge.get_source()
        destination = edge.get_destination()
        attributes = edge.get_attributes()
        label = attributes["label"]
        transitions[source][unquote(label)].add(destination)

    del nodes
    del edges
    del dot

    nfa = NFA(
        states=states,
        input_symbols=input_symbols,
        transitions=transitions,
        initial_state="s0",
        final_states=states,
    )

    return nfa


def extract_input_symbols(edges: list[Edge]) -> set[str]:
    input_symbols = set()
    for edge in edges:
        attributes = edge.get_attributes()
        label = attributes["label"]
        input_symbols.add(unquote(label))

    return input_symbols


if __name__ == "__main__":
    from pathlib import Path

    dot1 = graph_from_dot_file(
        Path("known_attacks", "wrap_and_decrypt", "wrap_and_decrypt_alphabet_model_0_Lsharp.dot"))
    dot2 = graph_from_dot_file(
        Path("known_attacks", "wrap_and_decrypt", "wrap_and_decrypt_alphabet_model_0_Lsharp.dot"))
    assert dot1 is not None
    assert dot2 is not None

    dot1 = dot1[0]
    dot2 = dot2[0]
    assert isinstance(dot1, Dot)
    assert isinstance(dot2, Dot)

    nodes1, edges1 = dot1.get_nodes(), dot1.get_edges()
    nodes2, edges2 = dot2.get_nodes(), dot2.get_edges()
    remove_extra_node(nodes1, edges1)
    remove_extra_node(nodes2, edges2)

    input_symbols1 = extract_input_symbols(edges1)
    input_symbols2 = extract_input_symbols(edges2)

    nfa1 = convert_to_nfa(nodes1, edges1, input_symbols1 | input_symbols2)
    nfa2 = convert_to_nfa(nodes1, edges2, input_symbols1 | input_symbols2)

    dfa1 = DFA.from_nfa(nfa1)
    dfa2 = DFA.from_nfa(nfa2)

    diff = dfa1.difference(dfa2)

    digraph = AGraph(directed=True)
    digraph.add_node("__start0", style="invis")
    digraph.add_edge("__start0", diff.initial_state)
    for state in diff.states:
        digraph.add_node(state, label=f"s{state}")
    for source, commands_with_destinations in diff.transitions.items():
        for command, destination in commands_with_destinations.items():
            digraph.add_edge(source, destination, label=command)
    digraph.write("difference.dot")

    # not a DFA: for example, s0 does not have a transition for symbol decrypt(1,4)=6/ok
