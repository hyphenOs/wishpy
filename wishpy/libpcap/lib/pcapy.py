"""
pcapy compatible API

This module provides `pcapy` (https://github.com/helpsystems/pcapy)
"""

from .libpcap_ext import lib as _pcap_lib
from .libpcap_ext import ffi as _pcap_ffi


def open_live(device, snaplen, promisc, to_ms):
    pass

def open_offline(filename):
    pass


def lookupdev():
    pass


def findalldevs():
    pass


def compile():
    pass


def create():
    pass


class PcapError(Exception):
    pass


class BPFProgram:
    pass


class Reader:
    pass


class Pkthdr:
    """ Pkthdr class, wrapper over the `pcap_pkthdr` Struct

        This class is defined for using with Dumper and other classes,
        actually, eventually we'll support directly using the
        cdata structure itself.
    """

    def __init__(self, pcaphdr):
        """ Constructor:
            Args:
                pcaphdr: '<cdata struct pcap_pkthdr *>' object.
        """
        self.__ts = pcaphdr[0].ts
        self.__caplen = pcaphdr[0].caplen
        self.__len = pcaphdr[0].len

    @property
    def ts(self):
        return self.__ts

    @property
    def caplen(self):
        return self.__caplen

    @property
    def len(self):
        return self.__len

    def getts(self):
        return self.__ts.tv_sec, self.__ts.tv_usec

    def getcaplen(self):
        return self.__caplen

    def getlen(self):
        return self.__len


class _Dumper:
    """ Internal class Dumper. 'pcapy' does not provide an API to directly
        use this class. We may provide it.
    """
    _pcap_handle = None

    def __init__(self, pdumper):
        """ Constructor:

            Args:
                pdumper: ctype object for libpcap's `pcap_dumper_t`. The
                         constructor should not be called directly by the
                         application, instead should use the below
                         `from_filename` classmethod, to get the object.

        """
        self.__dumper = pdumper
    @classmethod
    def from_filename(cls, filename, pcap_handle):
        """ Constructs a 'Dumper' object from the filename.

            Args:
                filename :    File name to be used for creating the dumper
                              object.
                pcap_handle : Should be opened by caller and passed to us.
                              This is also required to ensure that the
                              lifetime of the pcap_handle is greater than
                              ours.
        """
        dumper = pcap_dump_open(pcap_handle, filename.encode())
        return cls(dumper)

    def dump(self, hdr, data):
        """ Dumps into the file.

            Args:
                hdr: type: Pkthdr
                data: type: bytes
        """
        if not isinstance(hdr, PktHdr):
            raise PcapError("Argument 'hdr' should be of type 'Pkthdr'")

        if not isintance(data, bytes):
            raise PcapError("Argument 'data' shouldbe of type 'bytes'")

        pcap_pkthdr = _pcap_ffi.new('struct pcap_pkthdr *')
        pcap_pkthdr[0].ts = hdr.ts
        pcap_pkthdr[0].caplen = hdr.caplen
        pcap_pkthdr[0].len = hdr.len

        user = _pcap_ffi.cast('unsigned char *', self.__dumper)
        pcap_dump(user, pcap_pkthdr, data)



    def close(self):
        pass

if __name__ == '__main__':

    h = _pcap_ffi.new('struct pcap_pkthdr *')
    ph = Pkthdr(h)
    print(ph.getts())
    print(ph.getlen())
    print(ph.getcaplen())

