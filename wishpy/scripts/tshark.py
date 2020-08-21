import os
import glob
import sys
import time
import struct
import socket
from datetime import datetime as dt
import warnings
import logging


import click

from wishpy.wireshark.lib.dissector import WishpyDissectorFile
from wishpy.wireshark.lib.dissector import setup_process, cleanup_process
from wishpy.utils.profiler import WishpyContextProfiler


def get_pcaps_in_dir(ctx, args, incomplete):
    """Basic auto-complete function for ``filename`` argument.

    See:
    https://click.palletsprojects.com/en/7.x/bashcomplete/ for details.
    """
    if not incomplete:
        dir_to_search = os.path.abspath(os.getcwd())
        glob_start = incomplete + "*pcap"

    else:
        maybe_expand = os.path.expanduser(incomplete)
        if os.path.isdir(maybe_expand):
            dir_to_search = maybe_expand
            incomplete = ""
        else:
            dir_to_search = os.path.abspath(os.path.dirname(incomplete))
            incomplete = os.path.basename(incomplete)
        glob_start = incomplete + "*pcap"

    to_glob = os.path.join(dir_to_search, glob_start)

    return glob.glob(to_glob)

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option("--pretty", is_flag=True, help="Pretty print output")
@click.option("-c", "--count", default=0, help="Number of Packets to dissect (default: 0 - unlimited.)")
@click.option("--elasticky", is_flag=True,
        help="Generate Elastic Friendly Json (Duplicate keys as arrays eg. `ip.addr`).")
@click.option("--add-proto-tree", is_flag=True, help="Print like a Wireshark Proto Tree.")
@click.option("--profiled", is_flag=True, help="Profile the operation.")
@click.option("--timed", is_flag=True, help="Time the operation.")
@click.option("--silent", is_flag=True, help="Don't print the output.")
@click.option("--filter", help="Filter string")
@click.argument('filename', type=click.Path(exists=True), autocompletion=get_pcaps_in_dir)
def dissect(filename, pretty, count, elasticky, add_proto_tree, profiled, timed, silent, filter):
    """tshark: dissect packets from a PCAPish file."""

    logger = logging.getLogger()
    logging.basicConfig()

    setup_process()

    WishpyDissectorFile.set_pretty_print_details(enabled=pretty, add_proto_tree=add_proto_tree)

    if elasticky:
        WishpyDissectorFile.set_elasticky(elasticky)

    dissector = WishpyDissectorFile(filename)

    if filter:
        result, error = dissector.apply_filter(filter)

        if result != 0:
            logger.error("Unable to apply filter: %s", error)
            sys.exit(1)

    then = dt.now()

    if profiled:
        timed = True

    if timed:
        click.echo("Running for calculating timing information.")
        silent = True
        if count == 0:
            count = 10000
            click.echo("Count argument not supplied, setting to %d." % count)

    try:
        then = time.time()

        with WishpyContextProfiler(enabled=profiled, contextstr="dissector-run") as p:
            for dissected in dissector.run(count=count, skip=0):
                if not silent:
                    print(dissected)

        now = time.time()

        if profiled:
            click.echo(p.get_profile_data())

        if timed:
            click.echo("Time taken to dissect %d Packets: %f seconds" % (count, (now-then)))

    except KeyboardInterrupt:
        pass
    except Exception as e:
        sys.exit(1)
    finally:
        cleanup_process()

if __name__ == '__main__':

    dissect()
