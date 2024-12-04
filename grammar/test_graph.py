from copy import deepcopy
from itertools import count
from unittest import TestCase

from grammar.graph import wrap, encrypt, unwrap, decrypt, intruder_decrypt
from grammar.my_types import HandleNode, KeyNode


class TestWrap(TestCase):
    def test_empty_graph_wrap(self):
        g0 = {}
        id_generator = count()

        g1 = deepcopy(g0)
        wrap(g0, g1, id_generator)

        self.assertEqual(len(g1), 0)

    def test_graph_wrap_with_one_key_node_and_handle_node_pointing_to_it_should_create_new_key_node(self):
        g0 = {
            0: KeyNode(True, 0, False, [1], [], [], [], []),
            1: HandleNode(True, 0, True, None)
        }
        id_generator = count(max(g0.keys()) + 1)

        g1 = deepcopy(g0)
        wrap(g0, g1, id_generator)

        self.assertEqual(len(g1), len(g0) + 1)

        attr2: KeyNode = g1[2]
        self.assertEqual(attr2.value, (0, 0))
        self.assertTrue(attr2.known)
        self.assertListEqual(attr2.wrap_in, [(1, 1)])

        # the same wrapping should not add a new node because it is already there

        g2 = deepcopy(g1)
        wrap(g1, g2, id_generator)

        self.assertEqual(len(g2), len(g1))

    def test_graph_wrap_with_one_key_node_and_handle_node_pointing_to_it_should_update_existing_key_node(self):
        g0 = {
            0: KeyNode(True, 0, False, [1], [], [], [], []),
            1: HandleNode(True, 0, True, None),
            2: KeyNode(True, (0, 0), False, [], [], [], [], [])
        }
        id_generator = count(max(g0.keys()) + 1)

        g1 = deepcopy(g0)
        wrap(g0, g1, id_generator)

        self.assertEqual(len(g1), 3)

        attr2: KeyNode = g1[2]
        self.assertTrue(attr2.known)

    def test_graph_wrap_with_two_key_nodes_and_handle_nodes_pointing_to_them_should_create_new_key_nodes(self):
        g0 = {
            0: KeyNode(True, 0, False, [1], [], [], [], []),
            1: HandleNode(True, 0, True, None),
            2: KeyNode(True, 1, False, [3], [], [], [], []),
            3: HandleNode(True, 2, True, None)
        }
        id_generator = count(max(g0.keys()) + 1)

        g1 = deepcopy(g0)
        wrap(g0, g1, id_generator)

        self.assertEqual(len(g1), len(g0) + 4)

        attr5: KeyNode = g1[5]
        self.assertEqual(attr5.value, (1, 0))
        self.assertTrue(attr5.known)
        self.assertListEqual(attr5.wrap_in, [(1, 3)])

        attr6: KeyNode = g1[6]
        self.assertEqual(attr6.value, (0, 1))
        self.assertTrue(attr6.known)
        self.assertListEqual(attr6.wrap_in, [(3, 1)])


class TestEncrypt(TestCase):
    def test_empty_graph_encrypt(self):
        g0 = {}
        id_generator = count()

        g1 = deepcopy(g0)
        encrypt(g0, g1, id_generator)

        self.assertEqual(len(g1), 0)

    def test_graph_encrypt_with_one_key_node_and_handle_node_pointing_to_it_should_create_new_key_node(self):
        g0 = {
            0: KeyNode(True, 0, True, [1], [], [], [], []),
            1: HandleNode(True, 0, True, None)
        }
        id_generator = count(max(g0.keys()) + 1)

        g1 = deepcopy(g0)
        encrypt(g0, g1, id_generator)

        self.assertEqual(len(g1), len(g0) + 1)

        attr2: KeyNode = g1[2]
        self.assertEqual(attr2.value, (0, 0))
        self.assertTrue(attr2.known)
        self.assertListEqual(attr2.encrypt_in, [(1, 0)])

    def test_graph_encrypt_with_one_key_node_and_handle_node_pointing_to_it_should_update_existing_new_key_node(self):
        g0 = {
            0: KeyNode(True, 0, True, [1], [], [], [], []),
            1: HandleNode(True, 0, True, None),
            2: KeyNode(True, (0, 0), False, [], [], [(1, 0)], [], []),
        }
        id_generator = count(max(g0.keys()) + 1)

        g1 = deepcopy(g0)
        encrypt(g0, g1, id_generator)

        self.assertEqual(len(g1), 3)

        attr2: KeyNode = g1[2]
        self.assertTrue(attr2.known)

    def test_graph_encrypt_with_two_key_nodes_and_handle_nodes_pointing_to_them_should_create_new_key_nodes(self):
        g0 = {
            0: KeyNode(True, 0, True, [1], [], [], [], []),
            1: HandleNode(True, 0, True, None),
            2: KeyNode(True, 1, True, [3], [], [], [], []),
            3: HandleNode(True, 2, True, None)
        }
        id_generator = count(max(g0.keys()) + 1)

        g1 = deepcopy(g0)
        encrypt(g0, g1, id_generator)

        self.assertEqual(len(g1), len(g0) + 4)

        attr5: KeyNode = g1[5]
        self.assertEqual(attr5.value, (1, 0))
        self.assertTrue(attr5.known)
        self.assertListEqual(attr5.encrypt_in, [(1, 2)])

        attr6: KeyNode = g1[6]
        self.assertEqual(attr6.value, (0, 1))
        self.assertTrue(attr6.known)
        self.assertListEqual(attr6.encrypt_in, [(3, 0)])


class TestDecrypt(TestCase):
    def test_empty_graph_decrypt(self):
        g0 = {}
        id_generator = count()

        g1 = deepcopy(g0)
        decrypt(g0, g1, id_generator)

        self.assertEqual(len(g1), 0)

    def test_graph_decrypt_should_create_new_key_node(self):
        g0 = {
            0: KeyNode(True, 0, False, [1], [], [], [], []),
            1: HandleNode(True, 0, True, None),
            2: KeyNode(True, (1, 0), True, [], [], [], [], [])
        }
        id_generator = count(max(g0.keys()) + 1)

        g1 = deepcopy(g0)
        decrypt(g0, g1, id_generator)

        self.assertEqual(len(g1), len(g0) + 1)

        attr3: KeyNode = g1[3]
        self.assertEqual(attr3.value, 1)
        self.assertTrue(attr3.known)
        self.assertListEqual(attr3.decrypt_in, [(1, 2)])

        # the same decryption should not add a new node because it is already there

        g2 = deepcopy(g1)
        decrypt(g1, g2, id_generator)

        self.assertEqual(len(g2), len(g1))

    def test_graph_decrypt_should_update_existing_key_node(self):
        g0 = {
            0: KeyNode(True, 0, False, [1], [], [], [], []),
            1: HandleNode(True, 0, True, None),
            2: KeyNode(True, (1, 0), True, [], [], [], [], []),
            3: KeyNode(True, 1, False, [], [], [], [], [])
        }
        id_generator = count(max(g0.keys()) + 1)

        g1 = deepcopy(g0)
        decrypt(g0, g1, id_generator)

        self.assertEqual(len(g1), 4)

        attr2: KeyNode = g1[2]
        self.assertTrue(attr2.known)


class TestIntruderDecrypt(TestCase):
    def test_empty_graph_intruder_decrypt(self):
        g0 = {}
        id_generator = count()

        g1 = deepcopy(g0)
        intruder_decrypt(g0, g1, id_generator)

        self.assertEqual(len(g1), 0)

    def test_graph_intruder_decrypt_should_create_new_key_node(self):
        g0 = {
            0: KeyNode(True, 0, True, [], [], [], [], []),
            1: KeyNode(True, (1, 0), True, [], [], [], [], [])
        }
        id_generator = count(max(g0.keys()) + 1)

        g1 = deepcopy(g0)
        intruder_decrypt(g0, g1, id_generator)

        self.assertEqual(len(g1), len(g0) + 1)

        attr2: KeyNode = g1[2]
        self.assertEqual(attr2.value, 1)
        self.assertTrue(attr2.known)
        self.assertListEqual(attr2.intruder_decrypt_in, [(0, 1)])

        # the same intruder_decryption should not add a new node because it is already there

        g2 = deepcopy(g1)
        intruder_decrypt(g1, g2, id_generator)

        self.assertEqual(len(g2), len(g1))

    def test_graph_intruder_decrypt_should_update_existing_key_node(self):
        g0 = {
            0: KeyNode(True, 0, True, [], [], [], [], []),
            1: KeyNode(True, (1, 0), True, [], [], [], [], []),
            2: KeyNode(True, 1, False, [], [], [], [], []),
        }
        id_generator = count(max(g0.keys()) + 1)

        g1 = deepcopy(g0)
        intruder_decrypt(g0, g1, id_generator)

        self.assertEqual(len(g1), len(g0))

        attr2: KeyNode = g1[2]
        self.assertTrue(attr2.known)
        self.assertListEqual(attr2.intruder_decrypt_in, [(0, 1)])


class TestUnwrap(TestCase):
    def test_empty_graph_unwrap(self):
        g0 = {}
        id_generator = count()

        g1 = deepcopy(g0)
        unwrap(g0, g1, id_generator)

        self.assertEqual(len(g1), 0)

    def test_graph_unwrap_should_create_new_key_node_and_two_handle_nodes_pointing_to_it(self):
        g0 = {
            0: KeyNode(True, 0, False, [1], [], [], [], []),
            1: HandleNode(True, 0, True, None),
            2: KeyNode(True, (1, 0), True, [], [], [], [], []),
        }
        id_generator = count(max(g0.keys()) + 1)

        g1 = deepcopy(g0)
        unwrap(g0, g1, id_generator)

        self.assertEqual(len(g1), len(g0) + 3)

        attr3: KeyNode = g1[3]
        self.assertEqual(attr3.value, 1)
        self.assertFalse(attr3.known)
        self.assertListEqual(attr3.handle_in, [4, 5])

        attr4: HandleNode = g1[4]
        self.assertEqual(attr4.points_to, 3)
        self.assertTupleEqual(attr4.unwrap_in, (1, 2))

        attr5: HandleNode = g1[5]
        self.assertEqual(attr5.points_to, 3)
        self.assertTupleEqual(attr5.unwrap_in, (1, 2))

    def test_graph_unwrap_should_create_new_handle_node(self):
        g0 = {
            0: KeyNode(True, 0, False, [1], [], [], [], []),
            1: HandleNode(True, 0, True, None),
            2: KeyNode(True, (1, 0), True, [], [], [], [], []),
            3: KeyNode(True, 1, False, [4], [], [], [], []),
            4: HandleNode(True, 3, True, (1, 2)),
        }
        id_generator = count(max(g0.keys()) + 1)

        g1 = deepcopy(g0)
        unwrap(g0, g1, id_generator)

        self.assertEqual(len(g1), len(g0) + 1)

        attr5: HandleNode = g1[5]
        self.assertEqual(attr5.points_to, 3)
        self.assertTupleEqual(attr5.unwrap_in, (1, 2))

        attr3: KeyNode = g1[3]
        self.assertListEqual(attr3.handle_in, [4, 5])

    def test_graph_unwrap_should_not_create_new_handle_node_with_condition(self):
        g0 = {
            0: KeyNode(True, 0, False, [1], [], [], [], []),
            1: HandleNode(True, 0, True, None),
            2: KeyNode(True, (1, 0), True, [], [], [], [], []),
        }
        id_generator = count(max(g0.keys()) + 1)

        g1 = deepcopy(g0)
        unwrap(g0, g1, id_generator, lambda _n, _graph: 0)

        self.assertEqual(len(g1), len(g0))
