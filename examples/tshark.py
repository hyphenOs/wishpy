import os
import sys
import time
import struct
import socket
from datetime import datetime as dt
import warnings

_MAX_TO_PROCESS = 10000000

from wishpy.wireshark.lib.dissector import WishpyDissectorFile
from wishpy.wireshark.lib.dissector import setup_process, cleanup_process

if __name__ == '__main__':

    if not len(sys.argv) >= 2:
        print("Usage: tshark.py <filepath>")
        sys.exit(1)

    input_filepath = sys.argv[1]

    setup_process()

    dissector = WishpyDissectorFile(input_filepath)

    then = dt.now()
    processed = dissector.run()
    now = dt.now()
    print("processed {} packets in {}".format(processed, now - then))

    print("Performing dissection again to make sure the `epan` state is fine.")
    then = dt.now()
    processed = dissector.run(100)
    now = dt.now()
    print("processed {} packets in {}".format(processed, now - then))

    cleanup_process()
