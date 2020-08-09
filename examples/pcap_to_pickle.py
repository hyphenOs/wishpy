"""
A simple utility to generate a pickle dump of packets in a PCAP file.

Such a dump file is useful in testing the `WishpyDissectorQueue*`
dissectors.
"""

import sys
from threading import Thread
from queue import Queue
import pickle

from wishpy.libpcap.lib.capturer import WishpyCapturerFileToQueue

MAX_COUNT=-1

if __name__ == '__main__':

    if not len(sys.argv) == 2:
        print('Usage: pcap_to_pickle.py <pcap-file>')
        sys.exit(1)

    packet_queue = Queue()
    filename = sys.argv[1]


    capturer = WishpyCapturerFileToQueue(filename, packet_queue)
    capturer.open()

    capturer_thread = Thread(target=capturer.start, args=(MAX_COUNT, True))

    capturer_thread.start()

    packet_list = []
    while True:
        hdr, data = packet_queue.get()
        if hdr == 'stop':
            break

        packet_list.append((hdr, data))

    capturer_thread.join()

    assert pickle.loads(pickle.dumps(packet_list))  == packet_list

    pickle_filename = filename + ".pickle"

    with open(pickle_filename, 'wb') as f:
        f.write(pickle.dumps(packet_list))

