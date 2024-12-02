from unittest import TestCase

from grammar.pruning import prune_graph
from grammar.my_types import HandleNode, KeyNode


class Test(TestCase):
    def test_empty_graph(self):
        g0 = {}
        g1 = prune_graph(g0, set())

        self.assertEqual(g1, {})

    def test_graph_with_one_key_node(self):
        g0 = {
            0: KeyNode(0, False, [], [], [], [], [], True),
        }
        g1 = prune_graph(g0, set())

        self.assertEqual(g1, {})

    def test_graph_with_one_key_node_that_is_blocked(self):
        g0 = {
            0: KeyNode(0, False, [], [], [], [], [], True),
        }
        g1 = prune_graph(g0, {0})

        self.assertEqual(g1, g0)

    def test_graph_with_one_blocked_key_node_and_handle_node_pointing_to_it(self):
        g0 = {
            0: KeyNode(0, False, [1], [], [], [], [], True),
            1: HandleNode(0, None, True, True),
        }
        g1 = prune_graph(g0, {0})

        self.assertEqual(len(g1), 1)
        n0: KeyNode = g1[0]
        # once we remove a handle node, we must update the pointed key node
        # so that it is no longer pointed by the handle
        self.assertListEqual(n0.handle_in, [])

    def test_graph_with_one_blocked_key_node_and_blocked_handle_node_pointing_to_it(self):
        g0 = {
            0: KeyNode(0, False, [1], [], [], [], [], True),
            1: HandleNode(0, None, True, True),
        }
        g1 = prune_graph(g0, {0, 1})

        self.assertDictEqual(g1, g0)

    def test_wrap(self):
        g0 = {
            0: KeyNode(0, False, [1], [], [], [], [], True),
            1: HandleNode(0, None, True, True),
            2: KeyNode(1, False, [3], [], [], [], [], True),
            3: HandleNode(2, None, True, True),
            4: KeyNode((0, 1), True, [], [(3, 1)], [], [], [], True),
        }
        g1 = prune_graph(g0, {0, 1, 2, 3})

        self.assertEqual(len(g1), 4)
        self.assertNotIn(4, g1)

    def test_unwrap(self):
        g0 = {
            0: KeyNode(0, False, [1], [], [], [], [], True),
            1: HandleNode(0, None, True, True),
            2: KeyNode((1, 0), True, [], [], [], [], [], True),
            3: KeyNode(1, False, [4], [], [], [], [], True),
            4: HandleNode(3, (1, 2), True, True),
        }
        g1 = prune_graph(g0, {0, 1, 2})

        self.assertEqual(len(g1), 3)
        self.assertNotIn(3, g1)
        self.assertNotIn(4, g1)

    def test_encrypt(self):
        g0 = {
            0: KeyNode(0, False, [1], [], [], [], [], True),
            1: HandleNode(0, None, True, True),
            2: KeyNode(1, True, [], [], [], [], [], True),
            3: KeyNode((1, 0), True, [], [], [(1, 2)], [], [], True),
        }
        g1 = prune_graph(g0, {0, 1, 2})

        self.assertEqual(len(g1), 3)
        self.assertNotIn(3, g1)

    def test_decrypt(self):
        g0 = {
            0: KeyNode(0, False, [1], [], [], [], [], True),
            1: HandleNode(0, None, True, True),
            2: KeyNode((1, 0), True, [], [], [], [], [], True),
            3: KeyNode(1, True, [], [], [], [(1, 2)], [], True),
        }
        g1 = prune_graph(g0, {0, 1, 2})

        self.assertEqual(len(g1), 3)
        self.assertNotIn(3, g1)

    def test_intruder_decrypt(self):
        g0 = {
            0: KeyNode(0, True, [], [], [], [], [], True),
            1: KeyNode((1, 0), True, [], [], [], [], [], True),
            2: KeyNode(1, False, [], [], [], [], [(0, 1)], True),
        }
        g1 = prune_graph(g0, {0, 1})

        self.assertEqual(len(g1), 2)
        self.assertNotIn(2, g1)
