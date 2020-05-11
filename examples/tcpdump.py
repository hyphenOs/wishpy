import sys
from datetime import datetime as dt
import codecs
import binascii
from queue import Queue
import threading

MAX_COUNT = -1

from wishpy.libpcap.lib.capturer import LibpcapCapturer

then = dt.now()

q = Queue()
c = LibpcapCapturer('wlp2s0', q)
c.open()

capture_thread = threading.Thread(target=c.start, args=(MAX_COUNT,))
capture_thread.start()

count = 0
try:
    while True:
        hdr, data = q.get()

        caplen = hdr[0].caplen
        print(hdr[0].ts.tv_sec, hdr[0].ts.tv_usec, hdr[0].len,
                hdr[0].caplen)
        total_sec = hdr[0].ts.tv_sec + hdr[0].ts.tv_usec/1000000

        print(dt.strftime(dt.fromtimestamp(total_sec), '%H:%M:%S.%f'),
                caplen, binascii.hexlify(bytes(data[0:caplen])))
except KeyboardInterrupt:
    print("User Cancelled. Stopping Capture.")
    c.stop()

now = dt.now()

capture_thread.join()

print(now - then)

