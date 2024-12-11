from unittest import TestCase

from grammar.pruning import prune_graph
from grammar.my_types import HandleNode, KeyNode, Security


class Test(TestCase):
    def test_empty_graph(self):
        g0 = {}
        g1 = prune_graph(g0)

        self.assertDictEqual(g1, {})

    def test_graph_with_one_non_initial_key_node(self):
        g0 = {
            0: KeyNode(False, 0, False, Security.LOW, [], [], [], [], [], [], [], [], []),
        }
        g1 = prune_graph(g0)

        self.assertDictEqual(g1, {})

    def test_graph_with_one_initial_key_node(self):
        g0 = {
            0: KeyNode(True, 0, False, Security.LOW, [], [], [], [], [], [], [], [], []),
        }
        g1 = prune_graph(g0)

        self.assertDictEqual(g1, g0)

    def test_graph_with_one_initial_key_node_and_initial_handle_node_pointing_to_it(self):
        g0 = {
            0: KeyNode(True, 0, False, Security.LOW, [1], [], [], [], [], [], [], [], []),
            1: HandleNode(True, 0, True, None, [], [], [], []),
        }
        g1 = prune_graph(g0)

        self.assertDictEqual(g1, g0)

    def test_wrap(self):
        g0 = {
            0: KeyNode(True, 0, False, Security.LOW, [1], [], [], [], [], [], [], [], []),
            1: HandleNode(True, 0, True, None, [(3, 4)], [], [], []),
            2: KeyNode(True, 1, False, Security.LOW, [3], [], [], [], [], [], [], [], []),
            3: HandleNode(True, 2, True, None, [(1, 4)], [], [], []),
            4: KeyNode(False, (0, 1), True, Security.LOW, [], [(3, 1)], [], [], [], [], [], [], []),
        }
        g1 = prune_graph(g0)

        self.assertEqual(len(g1), 4)
        self.assertNotIn(4, g1)

    def test_unwrap(self):
        g0 = {
            0: KeyNode(True, 0, False, Security.LOW, [1], [], [], [], [], [], [], [], []),
            1: HandleNode(True, 0, True, None, [], [(2, 4)], [], []),
            2: KeyNode(True, (1, 0), True, Security.LOW, [], [], [], [], [], [(1, 4)], [], [], []),
            3: KeyNode(False, 1, False, Security.LOW, [4], [], [], [], [], [], [], [], []),
            4: HandleNode(False, 3, True, (1, 2), [], [], [], []),
        }
        g1 = prune_graph(g0)

        self.assertEqual(len(g1), 3)
        self.assertNotIn(3, g1)
        self.assertNotIn(4, g1)

    def test_encrypt(self):
        g0 = {
            0: KeyNode(True, 0, False, Security.LOW, [1], [], [], [], [], [], [], [], []),
            1: HandleNode(True, 0, True, None, [], [], [(2, 3)], []),
            2: KeyNode(True, 1, True, Security.LOW, [], [], [], [], [], [], [(1, 3)], [], []),
            3: KeyNode(False, (1, 0), True, Security.LOW, [], [], [(1, 2)], [], [], [], [], [], []),
        }
        g1 = prune_graph(g0)

        self.assertEqual(len(g1), 3)
        self.assertNotIn(3, g1)

    def test_decrypt(self):
        g0 = {
            0: KeyNode(True, 0, False, Security.LOW, [1], [], [], [], [], [], [], [], []),
            1: HandleNode(True, 0, True, None, [], [], [], [(2, 3)]),
            2: KeyNode(True, (1, 0), True, Security.LOW, [], [], [], [], [], [], [], [(1, 3)], []),
            3: KeyNode(False, 1, True, Security.LOW, [], [], [], [(1, 2)], [], [], [], [], []),
        }
        g1 = prune_graph(g0)

        self.assertEqual(len(g1), 3)
        self.assertNotIn(3, g1)

    def test_intruder_decrypt(self):
        g0 = {
            0: KeyNode(True, 0, True, Security.LOW, [], [], [], [], [], [], [], [], [(1, 2)]),
            1: KeyNode(True, (1, 0), True, Security.LOW, [], [], [], [], [], [], [], [], [(0, 2)]),
            2: KeyNode(False, 1, False, Security.LOW, [], [], [], [], [(0, 1)], [], [], [], []),
        }
        g1 = prune_graph(g0)

        self.assertEqual(len(g1), 2)
        self.assertNotIn(2, g1)
