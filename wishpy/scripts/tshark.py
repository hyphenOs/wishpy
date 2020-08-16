import os
import sys
import time
import struct
import socket
from datetime import datetime as dt
import warnings
import logging


import click

_MAX_TO_PROCESS = 10000000

from wishpy.wireshark.lib.dissector import WishpyDissectorFile
from wishpy.wireshark.lib.dissector import setup_process, cleanup_process
from wishpy.utils.profiler import WishpyContextProfiler

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option("--pretty", is_flag=True, help="Pretty print output")
@click.option("--profiled", is_flag=True, help="Profile the operation.")
@click.option("--timed", is_flag=True, help="Time the operation.")
@click.option("--silent", is_flag=True, help="Don't print the output.")
@click.option("--count", default=0, help="Number of Packets to dissect (default: 0 - unlimited.)")
@click.option("--filter", help="Filter string")
@click.argument('filename', type=click.Path(exists=True))
def dissect(pretty, profiled, timed, silent, count, filter, filename):
    """tshark: dissect packets from a PCAPish file."""

    logger = logging.getLogger()
    logging.basicConfig()

    setup_process()

    WishpyDissectorFile.pretty_print(enabled=pretty)

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
            for dissected in dissector.run(count=10000, skip=0):
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
