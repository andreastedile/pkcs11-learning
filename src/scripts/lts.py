import argparse
from pathlib import Path

from pydot import Dot, graph_from_dot_file


def dot_node_to_number(node: str) -> int:
    without_s = node.removeprefix("s")
    n = int(without_s)
    return n


def export_dot_as_aut(dot: Dot, path: Path):
    """
    https://mcrl2.org/web/user_manual/tools/lts.html
    """
    nodes = dot.get_nodes()
    edges = dot.get_edges()

    start0 = nodes.pop()
    assert start0.get_name() == "__start0"

    start0_to_s0_edge = edges.pop()
    assert start0_to_s0_edge.get_source() == "__start0"
    assert start0_to_s0_edge.get_destination() == "s0"

    # TODO: remove "not applicable" transitions?

    aut_header = f"des (0, {len(edges)}, {len(nodes)})\n"

    aut_edges = []
    for edge in edges:
        source = edge.get_source()
        destination = edge.get_destination()
        dot_node_to_number(source)
        attributes = edge.get_attributes()
        label = attributes["label"]
        aut_edge = f"({dot_node_to_number(source)}, {label}, {dot_node_to_number(destination)})\n"
        aut_edges.append(aut_edge)

    with open(path.with_suffix(".aut"), "w") as f:
        f.write(aut_header)
        f.writelines(aut_edges)


def main():
    parser = argparse.ArgumentParser(description="Convert .dot to .aut")
    parser.add_argument("dot_file_path", help="Path of the dot file")
    args = parser.parse_args()

    dot_file_path = args.dot_file_path

    dot = graph_from_dot_file(dot_file_path)
    assert dot is not None
    dot = dot[0]
    export_dot_as_aut(dot, Path(dot_file_path))


if __name__ == "__main__":
    main()
