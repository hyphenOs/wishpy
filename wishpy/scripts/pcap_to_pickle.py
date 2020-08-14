"""
A simple utility to generate a pickle dump of packets in a PCAP file.

Such a dump file is useful in testing the `WishpyDissectorQueue*`
dissectors.
"""

import sys
from threading import Thread
from queue import Queue
import pickle

import click

from wishpy.libpcap.lib.capturer import WishpyCapturerFileToQueue

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option("-c", "--count", default=100, help="Number of Packets to dissect (default: 0 - unlimited.)")
@click.argument('filename', type=click.Path(exists=True))
def pickler(count, filename):
    """pcap_to_pickle: Dump Packets from PCAP as Pickle dump of (Header, Data)."""

    pickle_filename = filename + ".pickle"

    click.echo("Dumping %d packets from %s to %s" % (count, filename, pickle_filename))
    packet_queue = Queue()

    capturer = WishpyCapturerFileToQueue(filename, packet_queue)
    capturer.open()

    capturer_thread = Thread(target=capturer.start, args=(count, True))

    capturer_thread.start()

    packet_list = []
    while True:
        hdr, data = packet_queue.get()
        if hdr == 'stop':
            break

        packet_list.append((hdr, data))

    capturer_thread.join()

    assert pickle.loads(pickle.dumps(packet_list))  == packet_list

    with open(pickle_filename, 'wb') as f:
        f.write(pickle.dumps(packet_list))


if __name__ == '__main__':

    pickler()
