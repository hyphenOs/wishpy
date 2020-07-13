import sys
from datetime import datetime as dt
import codecs
import binascii
from queue import Queue
import threading

MAX_COUNT = -1

from wishpy.libpcap.lib.capturer import LibpcapCapturer
from wishpy.wireshark.lib.dissector import (
        WishpyDissectorQueuePython,
        setup_process,
        cleanup_process)

then = dt.now()

packet_queue = Queue()
c = LibpcapCapturer('wlp2s0', packet_queue)
c.open()

capture_thread = threading.Thread(target=c.start, args=(MAX_COUNT,))
capture_thread.start()


setup_process()

dissector = WishpyDissectorQueuePython(packet_queue)


try:

    for _, _, dissected in dissector.run(count=100):
        print(dissected)

except KeyboardInterrupt:
    print("User interrupted.")

finally:
    cleanup_process()

c.stop()
now = dt.now()

capture_thread.join()

#print(now - then)
