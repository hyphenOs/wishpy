"""
Test cases for our dissectors
"""

import os
import unittest
import json
import pickle
from queue import Queue

from wishpy.wireshark.lib.dissector import *

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))

def setUpModule():
    setup_process()

def tearDownModule():
    cleanup_process()

class TestWishpyDissectorFile(unittest.TestCase):

    _96PINGS = os.path.join(_THIS_DIR, '96pings.pcap')
    filename = __file__

    @classmethod
    def setUpClass(cls):
        """Class Level initialization.
        """
        pass

    @classmethod
    def tearDownClass(cls):
        """Class Level teardown.
        """
        pass

    def test_raises_open_error_none_file(self):
        """Test if a None filename is given - raises Error.
        """

        dissector = WishpyDissectorFile(None)

        with self.assertRaises(WishpyErrorWthOpen) as e:
            for i in dissector.run():
                pass

    def test_raises_open_error_invalid_file(self):
        """Test case - raises Error on Invalid Pcap File.
        """

        dissector = WishpyDissectorFile(self.filename)

        with self.assertRaises(WishpyErrorWthOpen) as e:
            for i in dissector.run():
                pass


    def test_raises_open_error_unknonw_path(self):
        """Test case - raises Error on Unknown Path.
        """

        dissector = WishpyDissectorFile("foobar")

        with self.assertRaises(WishpyErrorWthOpen) as e:
            for i in dissector.run():
                pass

    def test_correct_packet_count(self):

        dissector = WishpyDissectorFile(self._96PINGS)

        count = 0
        for packet in dissector.run():
            count += 1

        self.assertEqual(count, 96, 'Invalid Count')


    def test_valid_packet_json_non_zero_count(self):
        """When count is passed as a non-zero value, assert that
        the frame number is same as count.
        """

        dissector = WishpyDissectorFile(self._96PINGS)

        count = 0
        for packet in dissector.run(count=2):
            pass

        packet = json.loads(packet)
        self.assertEqual(packet['frame']['frame.number'], 2)

    def test_valid_packet_json_non_zero_count_skip(self):
        """ When count and frame are both passed as non-zero,
        assert that frame number is still same as coun.
        """

        dissector = WishpyDissectorFile(self._96PINGS)

        count = 0
        for packet in dissector.run(count=0, skip=1):
            count += 1
            pass

        packet = json.loads(packet)
        self.assertEqual(count, 95)
        self.assertEqual(packet['frame']['frame.number'], 95)

    def test_dissector_file_filter_tcp(self):
        """ When a 'tcp' filter is applied, no packets should match."""

        dissector = WishpyDissectorFile(self._96PINGS)
        dissector.apply_filter("tcp")

        count = 0
        for packet in dissector.run(count=0, skip=1):
            count += 1
            pass

        self.assertEqual(count, 0)

    def test_dissector_file_filter_icmp(self):
        """ When a 'tcp' filter is applied, no packets should match."""

        dissector = WishpyDissectorFile(self._96PINGS)
        dissector.apply_filter("icmp")

        count = 0
        for packet in dissector.run(count=0):
            count += 1
            pass

        self.assertEqual(count, 96)
        self.assertNotEqual(packet, None)
        packet = json.loads(packet)
        self.assertEqual(packet['frame']['frame.number'], 96)


class TestWishpyDissectorPythonQueue(unittest.TestCase):

    _96PINGS_PICKLE = os.path.join(_THIS_DIR, '96pings.pcap.pickle')

    def setUp(self):
        self.packet_queue = Queue()

        with open(self._96PINGS_PICKLE, 'rb') as f:
            packets = pickle.loads(f.read())

        for packet in packets:
            self.packet_queue.put(packet)

        self.packet_queue.put(('stop', b''))

    def test_valid_packets_from_queue(self):
        """ Tests valid packets received from queue. """

        WishpyDissectorQueuePython.pretty_print(enabled=True)
        dissector = WishpyDissectorQueuePython(self.packet_queue)

        count = 0
        for _, _, packet in dissector.run():
            if packet is not None:
                count += 1
            pass

        self.assertEqual(count, 96)
        self.assertEqual(packet, None)

    def tearDown(self):
        """teardown function, we empty the queue."""

        while not self.packet_queue.empty():
            _ = self.packet_queue.get()
