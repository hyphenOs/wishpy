"""
pcapy compatible API

This module provides `pcapy` (https://github.com/helpsystems/pcapy)
"""
import warnings
import sys
import ipaddress

from .libpcap_ext import lib as _pcap_lib
from .libpcap_ext import ffi as _pcap_ffi


class PcapError(Exception):
    pass


def open_live(device, snaplen, promisc, to_ms):
    """Returns a live capture class Reader for a given device

    Internally performs `pcap_open_live` and `pcap_lookup_net`
    Args:
        device: string - Device to open
        snaplen: int - Requested snap length.
        promis: bool - Requested promiscuous mode.
        to_ms : int - Timeout in miliseconds.
    """
    err_buf = _pcap_ffi.new('char [256]')
    net = _pcap_ffi.new('bpf_u_int32 *')
    mask = _pcap_ffi.new('bpf_u_int32 *')
    error = _pcap_lib.pcap_lookupnet(device.encode(), net, mask, err_buf)
    if error != 0:
        raise PcapError(_pcap_ffi.string(err_buf).decode())

    net = net[0]
    mask = mask[0]

    promisc = int(bool(promisc))

    pcap_handle = _pcap_lib.pcap_open_live(
            device.encode(), snaplen, promisc, to_ms, err_buf)
    if pcap_handle == _pcap_ffi.NULL:
        raise PcapError(_pcap_ffi.string(err_buf).decode())

    return Reader(pcap_handle, net, mask)

def open_offline(filename):
    """ Returns a capture class `Reader` for a given filename.

    Internally performs `pcap_open_offline` and uses that to
    get the `Reader` object.
    Args:
        filename: string - Filename to open as `savefile`

    Returns:
        `Reader`

    Raises:
        `PcapError`
    """
    err_buf = _pcap_ffi.new('char [256]')
    pcap_handle = _pcap_lib.pcap_open_offline(filename.encode(), err_buf)
    if pcap_handle == _pcap_ffi.NULL:
        raise PcapError(_pcap_ffi.string(err_buf).decode())

    return Reader(pcap_handle)


def lookupdev():
    """Returns a device suitable for packet capture.

    This function is actually deprecated, but only supported for the
    existing users of `lookupdev`. Internally calls `findalldevs` and
    returns the name of the first device returned by that call.
    """

    message = "`lookupdev` is deprecated. Use `findalldevs` and the first "\
            "device returned by `findalldevs`."
    warnings.warn(message, DeprecationWarning, stacklevel=2)

    interfaces = findalldevs()
    if len(interfaces) > 0:
        return interfaces[0]
    else:
        return None


def findalldevs():
    """ Return's a 'list' of names of devices for packet capture.

    This function is a wrapeprover pcap_findalldevs.
    """

    err_buf = _pcap_ffi.new('char [256]')
    interfaces = _pcap_ffi.new('pcap_if_t **')
    result = _pcap_lib.pcap_findalldevs(interfaces, err_buf)
    if result != 0:
        raise PcapError(_pcap_ffi.string(err_buf).decode())

    interface_names = []
    iface = interfaces[0][0]
    while iface != _pcap_ffi.NULL:
        name = _pcap_ffi.string(iface.name).decode()
        interface_names.append(name)
        iface = iface.next

    _pcap_lib.pcap_freealldevs(interfaces[0])

    return interface_names

def compile():
    pass


def create():
    pass


class BPFProgram:
    pass


class Reader:
    """Reader Class (internal)

    This class performs all the work. This class is obtained typically by
    calling `open_live`. Takes `pcap_handle`  and net / mask as parameters.
    """

    def __init__(self, pcap_handle, net=0, mask=0):
        """Args:
            pcap_handle: `pcap_t *` handle.
            net :        network address
            mask:        netmask
        """
        self.__pcap_handle = pcap_handle
        self.__net = net
        self.__mask = mask

    def __del__(self):
        """Cleanup when the object is deleted.
        """
        self._do_close()

    def _do_close(self):
        """Cleans up internal handle.
        """
        try:
            pcap_close(self.__pcap_handle)
        except:
            pass
        finally:
            self.__pcap_handle = None

    def _raise_if_closed(self):
        """internal function that raises `PcapError` if the `__pcap_handle`
        is closed or is None.
        """

        if self.__pcap_handle is None:
            raise ValueError("Pcap Handle is already closed.")


    def activate(self):
        """Activate a capture handle created using `create`

        This function is usually not required to be called if we get the handle
        to the `Reader` object through `open_live` because, the `__pcap_handle`
        is then already activated

        """
        self._raise_if_closed()

        result = _pcap_lib.pcap_activate(self.__pcap_handle)

        if result < 0:
            result_str = _pcap_lib.pcap_geterr(self.__pcap_handle)
            raise PcapError(_pcap_ffi.string(result_str).decode())

        # FIXME: Also handle warnings
        return result

    def close(self):
        """Closes the internal PCAP handle, raising exception if already
        closed.
        """
        self._raise_if_closed()
        self._do_close()

    def datalink(self):
        """Returns data-link Layer Type for the pcap.

        Also Raises `PcapError` if  __pcap_handle is closed.
        """
        self._raise_if_closed()

        result = _pcap_lib.pcap_datalink(self.__pcap_handle)
        if result < 0:
            result_str = _pcap_lib.pcap_geterr(self.__pcap_handle)
            raise PcapError(_pcap_ffi.string(result_str).decode())

        return result

    def dispatch(self, count, callback, user_data=_pcap_ffi.NULL):
        """Dispatches a callback function using `pcap_dispatch`

        `cffi` library takes care of releasing the GIL, so we are not required
        to worry about that we can simply call the func.
        """
        self._raise_if_closed()

        result = _pcap_lib.pcap_dispatch(self.__pcap_handle, count,
                callback, user_data)
        if result < 0:
            if result == _pcap_lib.PCAP_ERROR_BREAK:
                # We are returning because someone called `pcap_breakloop`
                return 0
            else:
                result_str = _pcap_lib.pcap_geterr(self.__pcap_handle)
                raise PcapError(_pcap_ffi.string(result_str).decode())

        return result

    def dump_open(self, filename):
        """Opens a given `filename` as `savefile`.
        """
        dump_handle = _pcap_lib.pcap_dump_open(self.__pcap_handle, filename.encode())

        if dump_handle == _pcap_ffi.NULL:
            result_str = _pcap_lib.pcap_geterr(self.__pcap_handle)
            raise PcapError(_pcap_ffi.string(result_str).decode())

        return _Dumper(dump_handle)

    def get_fd(self):
        """Returns the file descriptor corresponding to internal handle.
        """
        self._raise_if_closed()

        if sys.platform == 'win32':
            raise PcapError("This operation is not supported on 'Windows'.")

        return _pcap_lib.pcap_get_selectable_fd(self.__pcap_handle)

    def getmask(self):
        """Returns the netmask corresponding to interface for which `handle`
        is opened.
        """
        return str(ipaddress.IPv4Address(self.__mask))

    def getnet(self):
        """Returns the network corresponding to interface for which `handle`
        is opened.
        """
        return str(ipaddress.IPv4Address(self.__net))

    def getnonblock(self):
        """Returns the current non-blocking mode of the internal handle.
        Raises an error if the corresponding `pcap` call fails.
        """
        err_buf = _pcap_ffi.new('char [256]')
        result = _pcap_lib.pcap_getnonblock(self.__pcap_handle, err_buf)
        if result != 0:
            raise PcapError(_pcap_ffi.string(err_buf).decode())

        return result

    def loop(self):
        """Loops through internal pcap handle. Calls the callback. See
        `dispatch` above.
        """
        self._raise_if_closed()

        result = _pcap_lib.pcap_loop(self.__pcap_handle, count,
                callback, user_data)
        if result < 0:
            if result == _pcap_lib.PCAP_ERROR_BREAK:
                # We are returning because someone called `pcap_breakloop`
                return 0
            else:
                result_str = _pcap_lib.pcap_geterr(self.__pcap_handle)
                raise PcapError(_pcap_ffi.string(result_str).decode())

        return result

    def next(self):
        """Returns the next packet data as `Pkthdr` and `buffer`
        """
        self._raise_if_closed()

        pkthdr_ptr = _pcap_ffi.new('struct pcap_pkthdr **')
        pktbuf_ptr = _pcap_ffi.new('unsigned char **')

        result = _pcap_lib.pcap_next_ex(self.__pcap_handle, pkthdr_ptr,
                pktbuf_ptr)
        if result <= 0:
            if result in [0, _pcap_lib.PCAP_ERROR_BREAK]:
                return None, b''
            else:
                result_str = _pcap_lib.pcap_geterr(self.__pcap_handle)
                raise PcapError(_pcap_ffi.string(result_str).decode())

        pkthdr_ptr0 = pkthdr_ptr[0]
        caplen = pkthdr_ptr0.caplen

        pkt_data = _pcap_ffi.string(pktbuf_ptr[0])
        pkt_hdr = Pkthdr(pkthdr_ptr0)

        return pkt_hdr, pkt_data


    def sendpacket(self, data, length):
        """Sends the given data on the given PCAP Handle.
        """
        self._raise_if_closed()

        result = _pcap_lib.pcap_sendpacket(self.__pcap_handle, data, length)
        if result < 0:
            result_str = _pcap_lib.pcap_geterr(self.__pcap_handle)
            raise PcapError(_pcap_ffi.string(result_str).decode())

        return result

    def set_buffer_size(self, buffersz):
        """Set's the pcap Buffer size to `buffersz`.
        """
        self._raise_if_closed()

        result = _pcap_lib.pcap_set_buffer_size(self.__pcap_handle, buffersz)
        if result < 0:
            result_str = _pcap_lib.pcap_geterr(self.__pcap_handle)
            raise PcapError(_pcap_ffi.string(result_str).decode())

        return result

    def set_promisc(self, promisc):
        """Set's the promiscuous mode.
        """
        self._raise_if_closed()

        promisc = int(bool(promisc))
        result = _pcap_lib.pcap_set_promisc(self.__pcap_handle, promisc)
        if result < 0:
            result_str = _pcap_lib.pcap_geterr(self.__pcap_handle)
            raise PcapError(_pcap_ffi.string(result_str).decode())

        return result

    def set_rfmon(self, rfmon):
        """Set's the rf monitor mode.
        """
        self._raise_if_closed()

        rfmon = int(bool(rfmon))
        result = _pcap_lib.pcap_set_rfmon(self.__pcap_handle, rfmon)
        if result < 0:
            result_str = _pcap_lib.pcap_geterr(self.__pcap_handle)
            raise PcapError(_pcap_ffi.string(result_str).decode())

        return result

    def set_snaplen(self, snaplen):
        """Set's the snaplen on captured packets.
        """
        self._raise_if_closed()

        result = _pcap_lib.pcap_set_snaplen(self.__pcap_handle, snaplen)
        if result < 0:
            result_str = _pcap_lib.pcap_geterr(self.__pcap_handle)
            raise PcapError(_pcap_ffi.string(result_str).decode())

        return result

    def set_timeout(self, to_ms):
        """Set's the snaplen on captured packets.
        """
        self._raise_if_closed()

        result = _pcap_lib.pcap_set_timeout(self.__pcap_handle, to_ms)
        if result < 0:
            result_str = _pcap_lib.pcap_geterr(self.__pcap_handle)
            raise PcapError(_pcap_ffi.string(result_str).decode())

        return result

    def setdirection(self, direction):
        """Set's the snaplen on captured packets.
        """
        self._raise_if_closed()

        result = _pcap_lib.pcap_setdirection(self.__pcap_handle, direction)
        if result < 0:
            result_str = _pcap_lib.pcap_geterr(self.__pcap_handle)
            raise PcapError(_pcap_ffi.string(result_str).decode())

        return result

    def setfilter(self):
        raise NotImplementedError("Not implemented yet")

    def setnonblock(self, non_blocking):
        """Set's the current non-blocking mode of the internal handle.
        Raises an error if the corresponding `pcap` call fails.
        """
        non_blocking = int(bool(non_blocking))
        err_buf = _pcap_ffi.new('char [256]')
        result = _pcap_lib.pcap_setnonblock(self.__pcap_handle,
                non_blocking, err_buf)
        if result != 0:
            raise PcapError(_pcap_ffi.string(err_buf).decode())

        return result

    def stats(self):
        """Get's the PCAP Stats.
        """
        stats = _pcap_ffi.new('struct pcap_stat *')
        result = _pcap_lib.pcap_setdirection(self.__pcap_handle, direction)
        if result < 0:
            result_str = _pcap_lib.pcap_geterr(self.__pcap_handle)
            raise PcapError(_pcap_ffi.string(result_str).decode())

        return stats[0].ps_recv, stats[0].ps_drop, stats[0].ps_ifdrop

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):

        self._do_close()
        return False


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

    def __del__(self):
        """Destructor: Making sure we close our handle.
        """
        self._do_close()

    def _do_close(self):
        if self.__dumper:
            try:
                _pcap_lib.pcap_dump_close(self.__dumper)
            except:
                ## Log warning
                pass
            finally:
                self.__dumper = None


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
        dumper = _pcap_lib.pcap_dump_open(pcap_handle, filename.encode())
        return cls(dumper)

    def dump(self, hdr, data):
        """ Dumps into the file.

            Args:
                hdr: type: Pkthdr
                data: type: bytes
        """
        if not isinstance(hdr, Pkthdr):
            raise PcapError("Argument 'hdr' should be of type 'Pkthdr'")

        if not isinstance(data, bytes):
            raise PcapError("Argument 'data' shouldbe of type 'bytes'")

        pcap_pkthdr = _pcap_ffi.new('struct pcap_pkthdr *')
        pcap_pkthdr[0].ts = hdr.ts
        pcap_pkthdr[0].caplen = hdr.caplen
        pcap_pkthdr[0].len = hdr.len

        user = _pcap_ffi.cast('unsigned char *', self.__dumper)
        _pcap_lib.pcap_dump(user, pcap_pkthdr, data)

    def close(self):
        """Closes internal file object calling `pcap_dump_close`
        """
        self._do_close()


if __name__ == '__main__':

    h = _pcap_ffi.new('struct pcap_pkthdr *')
    ph = Pkthdr(h)
    print(ph.getts())
    print(ph.getlen())
    print(ph.getcaplen())

    print(lookupdev())
    print(findalldevs())
    r = open_live(lookupdev(), 0, 0, 10)
    print(r)
    print(r.set_promisc(1))
    print(r.close())
    #print(r.datalink())
