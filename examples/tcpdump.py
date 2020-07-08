import sys
from datetime import datetime as dt
import codecs
import binascii
from queue import Queue
import threading

MAX_COUNT = -1

from wishpy.libpcap.lib.capturer import LibpcapCapturer
from wishpy.wireshark.lib.dissector import WishpyDissectorQueuePython

then = dt.now()

packet_queue = Queue()
c = LibpcapCapturer('wlp2s0', packet_queue)
c.open()

capture_thread = threading.Thread(target=c.start, args=(MAX_COUNT,))
capture_thread.start()


d = WishpyDissectorQueuePython(packet_queue)
packet_generator = d.run()

while True:
    try:
        hdr, data = next(packet_generator)

        pktlen, caplen = hdr[0].len, hdr[0].caplen

        total_sec = hdr[0].ts.tv_sec + hdr[0].ts.tv_usec/1000000

        print(dt.strftime(dt.fromtimestamp(total_sec), '%H:%M:%S.%f'),
                pktlen, caplen, binascii.hexlify(bytes(data[0:caplen])))
    except StopIteration:
        break
    except KeyboardInterrupt:
        print("User interrupted.")
        try:
            packet_generator.send('stop')
        except StopIteration:
            pass

c.stop()
now = dt.now()

capture_thread.join()

print(now - then)

