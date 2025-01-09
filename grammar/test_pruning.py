from unittest import TestCase

from grammar.pruning import prune_graph
from grammar.my_types import HandleNode, KeyNode, Security, WrapImplication, EncryptImplication, DecryptImplication, \
    IntruderDecryptImplication, UnwrapImplication


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
            1: HandleNode(True, 0, True, None, [WrapImplication(3, 1, 4)], [], [], []),
            2: KeyNode(True, 1, False, Security.LOW, [3], [], [], [], [], [], [], [], []),
            3: HandleNode(True, 2, True, None, [WrapImplication(3, 1, 4)], [], [], []),
            4: KeyNode(False, (0, 1), True, Security.LOW, [], [WrapImplication(3, 1, 4)], [], [], [], [], [], [], []),
        }
        g1 = prune_graph(g0)

        self.assertEqual(len(g1), 4)
        self.assertNotIn(4, g1)

    def test_unwrap(self):
        g0 = {
            0: KeyNode(True, 0, False, Security.LOW, [1], [], [], [], [], [], [], [], []),
            1: HandleNode(True, 0, True, None, [], [UnwrapImplication(1, 2, 4)], [], []),
            2: KeyNode(True, (1, 0), True, Security.LOW, [], [], [], [], [], [UnwrapImplication(1, 2, 4)], [], [], []),
            3: KeyNode(False, 1, False, Security.LOW, [4], [], [], [], [], [], [], [], []),
            4: HandleNode(False, 3, True, UnwrapImplication(1, 2, 4), [], [], [], []),
        }
        g1 = prune_graph(g0)

        self.assertEqual(len(g1), 3)
        self.assertNotIn(3, g1)
        self.assertNotIn(4, g1)

    def test_encrypt(self):
        g0 = {
            0: KeyNode(True, 0, False, Security.LOW, [1], [], [], [], [], [], [], [], []),
            1: HandleNode(True, 0, True, None, [], [], [EncryptImplication(1, 2, 3)], []),
            2: KeyNode(True, 1, True, Security.LOW, [], [], [], [], [], [], [EncryptImplication(1, 2, 3)], [], []),
            3: KeyNode(False, (1, 0), True, Security.LOW, [], [], [EncryptImplication(1, 2, 3)], [], [], [], [], [],
                       []),
        }
        g1 = prune_graph(g0)

        self.assertEqual(len(g1), 3)
        self.assertNotIn(3, g1)

    def test_decrypt(self):
        g0 = {
            0: KeyNode(True, 0, False, Security.LOW, [1], [], [], [], [], [], [], [], []),
            1: HandleNode(True, 0, True, None, [], [], [], [DecryptImplication(1, 2, 3)]),
            2: KeyNode(True, (1, 0), True, Security.LOW, [], [], [], [], [], [], [], [DecryptImplication(1, 2, 3)], []),
            3: KeyNode(False, 1, True, Security.LOW, [], [], [], [DecryptImplication(1, 2, 3)], [], [], [], [], []),
        }
        g1 = prune_graph(g0)

        self.assertEqual(len(g1), 3)
        self.assertNotIn(3, g1)

    def test_intruder_decrypt(self):
        g0 = {
            0: KeyNode(True, 0, True, Security.LOW, [], [], [], [], [], [], [], [],
                       [IntruderDecryptImplication(0, 1, 2)]),
            1: KeyNode(True, (1, 0), True, Security.LOW, [], [], [], [], [], [], [], [],
                       [IntruderDecryptImplication(0, 1, 2)]),
            2: KeyNode(False, 1, False, Security.LOW, [], [], [], [], [IntruderDecryptImplication(0, 1, 2)], [], [], [],
                       []),
        }
        g1 = prune_graph(g0)

        self.assertEqual(len(g1), 2)
        self.assertNotIn(2, g1)
