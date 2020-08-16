"""
Test cases for the libpcap 'Capturer' class
"""

import os
import unittest
import json
import pickle
import threading
import time
from queue import Queue

from wishpy.libpcap.lib.capturer import *

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))

class TestWishpyCapturerFileToQueue(unittest.TestCase):

    _96PINGS = os.path.join(_THIS_DIR, '96pings.pcap')

    def test_wishpy_capturer_valid_file(self):
        """ Tests wishpy capturer with valid file.
        """
        queue = Queue()
        capturer = WishpyCapturerFileToQueue(self._96PINGS, queue)

        howmany = 2
        capturer.open()
        capturer_thread = threading.Thread(target=capturer.start, args=(howmany,))
        capturer_thread.start()
        time.sleep(1)
        capturer.stop()
        capturer.close()

        capturer_thread.join()

        count = 0
        print(capturer.queue.empty())
        while not capturer.queue.empty():
            count += 1
            capturer.queue.get()

        self.assertEqual(count, howmany+1)

