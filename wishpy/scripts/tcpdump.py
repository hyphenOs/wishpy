import sys
from datetime import datetime as dt
import codecs
import binascii
from queue import Queue
import threading

import click

MAX_COUNT = -1

from wishpy.libpcap.lib.capturer import WishpyCapturerIfaceToQueue
from wishpy.wireshark.lib.dissector import (
        WishpyDissectorQueuePython,
        setup_process,
        cleanup_process)

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option("--pretty", is_flag=True, help="Pretty print output")
@click.option("-c", "--count", default=0, help="Number of Packets to dissect (default: 0 - unlimited.)")
@click.option("--elasticky", is_flag=True,
        help="Generate Elastic Friendly Json (Duplicate keys as arrays eg. `ip.addr`).")
@click.option("--filter", help="Filter string")
@click.argument('interface')
def dump(count, pretty, elasticky, filter, interface):
    """Capture and dump packets as json."""

    try:
        packet_queue = Queue()

        capture_thread = None
        c = WishpyCapturerIfaceToQueue(interface, packet_queue)
        c.open()

        capture_thread = threading.Thread(target=c.start, args=(MAX_COUNT, True))
        capture_thread.start()

        setup_process()

        WishpyDissectorQueuePython.set_pretty_print_details(enabled=pretty)

        if elasticky:
            WishpyDissectorQueuePython.set_elasticky(elasticky)

        dissector = WishpyDissectorQueuePython(packet_queue, interface)
        if filter:
            result, error = dissector.apply_filter(filter)
            if result != 0:
                raise ValueError(error)

        for _, _, dissected in dissector.run(count=count):
            print(dissected)

    except KeyboardInterrupt:
        print("User interrupted.")

    except Exception as e:
        print(e)

    finally:
        cleanup_process()
        c.stop()

    if capture_thread is not None:
        capture_thread.join()

if __name__ == '__main__':
    dump()
