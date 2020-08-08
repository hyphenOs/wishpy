import sys
from datetime import datetime as dt
import codecs
import binascii
from queue import Queue
import threading

MAX_COUNT = -1

from wishpy.libpcap.lib.capturer import LibpcapCapturerIface
from wishpy.wireshark.lib.dissector import (
        WishpyDissectorQueuePython,
        setup_process,
        cleanup_process)

if __name__ == '__main__':

    if len(sys.argv) != 2:
        print("Usage: tcpdump.py <interface>")
        sys.exit(1)

    interface_name = sys.argv[1]

    packet_queue = Queue()
    c = LibpcapCapturerIface(interface_name, packet_queue)
    c.open()

    capture_thread = threading.Thread(target=c.start, args=(MAX_COUNT,))
    capture_thread.start()


    setup_process()

    dissector = WishpyDissectorQueuePython(packet_queue)


    try:

        for _, _, dissected in dissector.run(count=0):
            print(dissected)

    except KeyboardInterrupt:
        print("User interrupted.")

    except Exception as e:
        print(e)

    finally:
        cleanup_process()

    c.stop()
    capture_thread.join()

