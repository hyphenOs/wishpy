"""
Test cases for our dissectors
"""

import os
import unittest
import json

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
