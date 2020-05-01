import os
import sys
import time
import struct
import socket
from datetime import datetime as dt
import warnings

_MAX_TO_PROCESS = 10000000

from wishpy.wireshark.lib.dissector import WishpyDissector
from wishpy.wireshark.lib.dissector import setup_process, cleanup_process

if __name__ == '__main__':

    if not len(sys.argv) >= 2:
        print("Usage: tshark.py <filepath>")
        sys.exit(1)

    input_filepath = sys.argv[1]

    setup_process()

    dissector = WishpyDissector(input_filepath)

    then = dt.now()
    processed = dissector.run()
    now = dt.now()
    print("processed {} packets in {}".format(processed, now - then))

    then = dt.now()
    processed = dissector.run()
    now = dt.now()
    print("processed {} packets in {}".format(processed, now - then))

    cleanup_process()
