import re

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

    nfa = NFA(
        states=states,
        input_symbols=input_symbols,
        transitions=transitions,
        initial_state="__start0",
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


def dfa_to_agraph(dfa: DFA) -> AGraph:
    digraph = AGraph(directed=True)
    digraph.add_node("__start0", style="invis")
    digraph.add_edge("__start0", dfa.initial_state)
    for state in dfa.states:
        digraph.add_node(state, label=state, shape="doublecircle" if state in dfa.final_states else "circle")
    for source, commands_with_destinations in dfa.transitions.items():
        for command, destination in commands_with_destinations.items():
            digraph.add_edge(source, destination, label=command)
    return digraph


PATTERN = re.compile(r"(wrap|unwrap|encrypt|decrypt|deduceEncrypt|deduceDecrypt)\((\d+),(\d+)\)=(\d+)")

if __name__ == "__main__":
    from pathlib import Path

    dot1 = graph_from_dot_file(Path("vulnerable.dot"))
    dot2 = graph_from_dot_file(Path("patched.dot"))
    assert dot1 is not None
    assert dot2 is not None

    dot1 = dot1[0]
    dot2 = dot2[0]
    assert isinstance(dot1, Dot)
    assert isinstance(dot2, Dot)

    nodes1, edges1 = dot1.get_nodes(), dot1.get_edges()
    nodes2, edges2 = dot2.get_nodes(), dot2.get_edges()

    input_symbols1 = extract_input_symbols(edges1)
    input_symbols2 = extract_input_symbols(edges2)

    nfa1 = convert_to_nfa(nodes1, edges1, input_symbols1 | input_symbols2)
    nfa2 = convert_to_nfa(nodes1, edges2, input_symbols1 | input_symbols2)

    dfa1 = DFA.from_nfa(nfa1)
    dfa2 = DFA.from_nfa(nfa2)

    diff = dfa1.difference(dfa2)

    dfa_to_agraph(diff).write("difference.dot")

    words_of_length = diff.words_of_length(4)
    for i, word in enumerate(words_of_length):
        matches = re.findall(PATTERN, word)
        for match in matches:
            function_name, n1, n2, result = match
            print(f"{function_name}({n1},{n2})={result}", end=" ")
        print()

    # not a DFA: for example, s0 does not have a transition for symbol decrypt(1,4)=6/ok
