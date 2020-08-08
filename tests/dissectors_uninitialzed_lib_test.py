"""
Single Test case for process level initialization Not Done
"""


import os
import unittest

from wishpy.wireshark.lib.dissector import *

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))


class  WishpyDissectorUninitilizedProcess(unittest.TestCase):

    _96PINGS = os.path.join(_THIS_DIR, '96pings.pcap')

    def test_raises_epan_lib_uninitialized_valid_file(self):
        """ Test, calling run without `setup_process` results in
        `WishpyEpanLibUninitializedError`
        """

        dissector = WishpyDissectorFile(self._96PINGS)

        with self.assertRaises(WishpyEpanLibUninitializedError) as e:
            for i in dissector.run():
                pass

