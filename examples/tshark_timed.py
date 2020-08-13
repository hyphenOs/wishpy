import os
import sys
import time
import struct
import socket
from datetime import datetime as dt
import warnings
import logging

_MAX_TO_PROCESS = 10000000

from wishpy.wireshark.lib.dissector import WishpyDissectorFile
from wishpy.wireshark.lib.dissector import setup_process, cleanup_process

if __name__ == '__main__':

    logger = logging.getLogger()
    logging.basicConfig()

    if not len(sys.argv) >= 2:
        print("Usage: tshark.py <filepath>")
        sys.exit(1)

    count = 50000
    if len(sys.argv) == 3:
        try:
            count = int(sys.argv[2])
        except ValueError:
            pass
    input_filepath = sys.argv[1]

    setup_process()

    dissector = WishpyDissectorFile(input_filepath)

    then = dt.now()

    try:
        print("Running dissector for %d Packets." % count)
        then = time.time()
        for dissected in dissector.run(count=count, skip=0):
            pass #print(dissected)

        now = time.time()
        print("Total time taken in seconds:", now-then)
    except KeyboardInterrupt:
        cleanup_process()

    now = dt.now()

