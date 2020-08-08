"""
Capture API using the libpcap.

"""
import logging

from collections import namedtuple

PCAPHeader = namedtuple('PCAPHeader', ['ts_sec', 'ts_usec', 'len', 'caplen'])

from .libpcap_ext import lib as pcap_lib
from .libpcap_ext import ffi as pcap_ffi

_logger = logging.getLogger(__name__)

class WishpyCapturerOpenError(Exception):
    pass

class WishpyCapturerCaptureError(Exception):
    pass

class WishpyCapturer:
    """ ase WishpyCapturer class.

        Following API are provided  `open`, `close`, `start`, `stop`.
    """

    def open(self):
        """open: Opens the capturer.

            Use this to perform any Capturer specific initialization. For
            instance, our API deals with Packet Capture Pipelines that can
            be connected using Python Queues. So Setting up Queues etc. can
            be performed here in this method.
        """
        raise NotImplementedError

    def start(self, **kw):
        """start: Start actual capture of packets.

           Implement in such a way tha it should be possible to start/stop
           capture multiple times for an instance of the capturer.
        """
        raise NotImplementedError

    def stop(self, **kw):
        """stop: Stop actual capture of packets.

            Implement in such a way that it should be possible to start/stop
            capture multiple times for an instance of the capturer.
        """
        raise NotImplementedError

    def close(self):
        """close: Perform any resource cleanup related to the capturer.
        """
        pass

class LibpcapCapturerIface(WishpyCapturer):
    """'libpcap' based packet capturer for an interface on the system.

        This capturer captures packet from the OS interface and posts them,
        on the Queue. Right now it is not completely abstracted out what gets
        posted on the queue. Assume they are tuples like - (header, data)
    """

    def __init__(self, iface, queue,
            snaplen=0, promisc=True, timeout=10, **kw):
        """Constructor

            Args:
                iface:   string - An Interface Name on the local OS.
                queue:   Python Queue like objects that supported Get/Put APIs
                         in a thread/process safe manner. (eg. Queue,
                         multiprocessing Queue etc.)
                snaplen: integer (optional), should be non-zero, if provided,
                         maximum capture data for packet will be capped to this
                         value. Default - Don't set Capture length (ie. if
                         input value is 0.)
                promisc: Boolean (optional). Default True To determine whether
                         to start capturing in 'promiscuous' mode.
                timeout: integer - Timeout in miliseconds to wait before next
                         'batch' of captured packets is returned (maps
                         directly to `libpcap: packet buffer timeout`.)
                         Default value is 10ms. Use lower values for more
                         'responsive' capture, higher values for larger
                         batches.
                **kw:    Possible Keyword argument's that can be supported
                         include 'maximum number of packets to capture etc.
        """

        self.__iface = iface
        self.__queue = queue
        self.__snaplen = snaplen
        self.__promisc = promisc
        self.__timeout = timeout
        self.__pcap_handle = None
        self.__pcap_activated = False

    # Property Classes: All are read-only there is little value in making
    # these, read-write. For now at-least
    @property
    def iface(self):
        return self.__iface

    @property
    def queue(self):
        return self.__queue

    @property
    def snaplen(self):
        return self.__snaplen

    @property
    def promisc(self):
        return self.__promisc

    @property
    def timeout(self):
        return self.__timeout

    def start(self, count=-1, serialize=False):
        """ Starts capturing of the packets on our Interface.

            Note: This is a blocking function and an application should
            call this function from a separate thread of execution.
            Calls internal `pcap_loop` function of libpcap.

            Args:
                count: (optional) if specified should be a positive integer
                    specifying maximum number of packets to be captured.
                serialize: bool, optional - if specified serializes the header
                    and data to `PCAPHeader` and `bytes` objects

            Returns:
                On Success Nothing

            Raises:
                On Error Condition, `WishpyCapturerCaptureError`.
        """

        _logger.debug("LibpcapCapturerIface.start")

        def capture_callback(user, hdr, data):

            if serialize:
                ## Convert this into - sensible Header, Data 'pickle'able
                hdr = hdr[0]
                caplen = hdr.caplen
                ser_header = PCAPHeader(
                        *(hdr.ts.tv_sec, hdr.ts.tv_usec,
                            caplen, hdr.len))
                ser_data = bytes(pcap_ffi.unpack(data, caplen))
                self.__queue.put((ser_header, ser_data))
            else:
                self.__queue.put((hdr, data,))

        _cb = pcap_ffi.callback(
                'void (*)(u_char *, const struct pcap_pkthdr *, const u_char *)',
                capture_callback)

        result = pcap_lib.pcap_loop(self.__pcap_handle, count,
                _cb, pcap_ffi.NULL)

    def stop(self):
        """ Stops the capture.

        Simply calls internal libpcap's `pcap_breakloop`
        """

        _logger.debug("LibpcapCapturerIface.stop")
        pcap_lib.pcap_breakloop(self.__pcap_handle)

    def open(self):
        """ Open's the Capturerer readying it for performing capture.

            Calls libpcap's `pcap_create` and depending upon requested
            parameters during the Constructor, those values are set and
            finally activates the handle.
        """

        _logger.debug("LibpcapCapturerIface.open")

        err_buff = pcap_ffi.new('char [256]')
        handle = pcap_lib.pcap_create(self.__iface.encode(), err_buff)
        if handle == pcap_ffi.NULL:
            err_str = pcap_ffi.string(err_buff)
            raise WishpyCapturerOpenError(err_str)

        if self.__snaplen:
            error = pcap_lib.pcap_set_snaplen(handle, self.__snaplen)
            if error == pcap_lib.PCAP_ERROR_ACTIVATED:
                raise WishpyCapturerOpenError("PCAP Handle already Activated.")

        if self.__promisc:
            error = pcap_lib.pcap_set_promisc(handle, 1)
            if error == pcap_lib.PCAP_ERROR_ACTIVATED:
                raise WishpyCapturerOpenError("PCAP Handle already Activated.")

        if self.__timeout:
            error = pcap_lib.pcap_set_timeout(handle, self.__timeout)
            if error == pcap_lib.PCAP_ERROR_ACTIVATED:
                raise WishpyCapturerOpenError("PCAP Handle already Activated.")

        error = pcap_lib.pcap_activate(handle)
        if error < 0:
            self.close()

            err_charptr = pcap_lib.pcap_geterr(handle)
            err_str = pcap_ffi.string(err_charptr).decode()
            raise WishpyCapturerOpenError("Failed to activate: {}".\
                    format(err_str))

        # FIXME: Warning to be reported
        self.__pcap_activated = True
        self.__pcap_handle = handle

    def close(self):
        """ Closes internal `libpcap` handle

            libpcap's `pcap_close` function is called and our activated flag
            is set to False.
        """
        if self.__pcap_handle is not None:
            pcap_lib.pcap_close(self.__pcap_handle)
        self.__pcap_activated = False
        self.__pcap_handle = None

        _logger.debug("LibpcapCapturerIface.close")

    def __repr__(self):
        return "LibpcapCapturerIface iface:{}, snaplen:{}, promisc:{}, timeout:{}".\
                format(self.__iface, self.__snaplen,
                        self.__promisc, self.__timeout)

if __name__ == '__main__':
    from queue import Queue
    c = LibpcapCapturerIface('wlp2s0', Queue())
    print(c)
    c.open()
    c.start(count=1)
    c.close()
