"""
Capture API using the libpcap.

"""
import os
import logging

from collections import namedtuple

_logger = logging.getLogger(__name__)

try:
    from .libpcap_ext import lib as pcap_lib
    from .libpcap_ext import ffi as pcap_ffi
except ImportError:
    if os.getenv('READTHEDOCS', None) is not None:
        _logger.warning("Ignoring. Import Error in RTD.")
    else:
        raise

PCAPHeader = namedtuple('PCAPHeader', ['dltype', 'ts_sec', 'ts_usec', 'len', 'caplen'])
PCAPHeader.__doc___ = """A Wrapper around PCAP Header."""
PCAPHeader.dltype.__doc__ = "Data Link Layer type as per libpcap"
PCAPHeader.ts_sec.__doc__ = "seconds part of the timestamp."
PCAPHeader.ts_usec.__doc__ = "micro-seconds part of the timestamp."
PCAPHeader.len.__doc__ = "length of the packet."
PCAPHeader.caplen.__doc__ = "captured length of the packet."


class WishpyCapturerOpenError(Exception):
    pass

class WishpyCapturerCaptureError(Exception):
    pass

class WishpyCapturer:
    """Base WishpyCapturer class.

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

    def close(self):
        """close: Perform any resource cleanup related to the capturer.
        """
        pass

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

class WishpyCapturerQueue(WishpyCapturer):
    """Base Class for Sending Packets to Python Queue like objects.

    """

    def __init__(self, queue, **kw):
        """Constructor

        Args:
            queue: Python Queue like objects that supported Get/Put APIs

                   The Get/Put APIs should be in a thread/process safe manner.
                   (eg. Queue, multiprocessing Queue etc.)

            \*\*kw: Possible keyword arguments.
        """
        self._queue = queue
        self._pcap_handle = None
        self._dltype = -1

    @property
    def queue(self):
        return self._queue

    def start(self, count=-1, serialize=True):
        """Starts capturing of the packets.

        Note: This is a blocking function.

              An application should call this function from a separate
              thread of execution.  Calls internal ``pcap_loop`` function of
              ``libpcap``.

        Args:
            count: (optional) if specified should be a positive integer
                    specifying maximum number of packets to be captured.

            serialize: (optional) bool - Serialize data
                    If specified serializes the header and data to ``PCAPHeader`` and ``bytes`` objects
                    (default ``True``)

        Returns:
            On Success Nothing.

            When ``pcap_loop`` returns, A special tuple - ``('stop', b'')``
            is placed on the queue. For the consumer of the queue, this should
            signal end of data transfer from the producer.

        Raises:
            On Error Condition `wishpy.wireshark.lib.WishpyCapturerCaptureError`.

        """

        _logger.debug("%s.start", self.__class__.__name__)

        def capture_callback(user, hdr, data):

            if serialize:
                ## Convert this into - sensible Header, Data 'pickle'able
                hdr = hdr[0]
                caplen = hdr.caplen
                ser_header = PCAPHeader(
                        *(self._dltype,
                            hdr.ts.tv_sec, hdr.ts.tv_usec,
                            caplen, hdr.len))
                ser_data = bytes(pcap_ffi.unpack(data, caplen))
                self._queue.put((ser_header, ser_data))
            else:
                self._queue.put((hdr, data,))

        #FIXME : I don't know how to do it without a 'closure'
        _cb = pcap_ffi.callback(
                'void (*)(u_char *, const struct pcap_pkthdr *, const u_char *)',
                capture_callback)

        result = pcap_lib.pcap_loop(self._pcap_handle, count,
                _cb, pcap_ffi.NULL)

        self._queue.put(('stop', result))

    def stop(self):
        """ Stops the capture.

        Simply calls internal ``libpcap``'s ``pcap_breakloop``
        """

        _logger.debug("%s.stop", self.__class__.__name__)

        if self._pcap_handle is not None:
            _logger.info("Stopping Capturer.")
            pcap_lib.pcap_breakloop(self._pcap_handle)
            self._pcap_handle = None
        else:
            _logger.info("Capturer already stopped.")



class WishpyCapturerIfaceToQueue(WishpyCapturerQueue):
    """``libpcap`` based packet capturer for an interface on the system.

        This capturer captures packet from the OS interface and posts them,
        on the Queue. Right now it is not completely abstracted out what gets
        posted on the queue. Assume they are tuples like - (header, data)
    """

    def __init__(self, iface, queue, snaplen=0,
            promisc=True, timeout=10, **kw):
        """Constructor

            Args:
                queue:   Python Queue like objects that supported Get/Put APIs.

                         Get/Put APIs should be thread/process safe.  (eg. Queue, multiprocessing Queue etc.)

                iface:   string - An Interface Name on the local OS.

                snaplen: integer (optional), Maximum Capture length of the data.

                         Default - Don't set Capture length (ie. if input value is 0.)

                promisc: Boolean (optional). Default True To determine whether to start capturing in 'promiscuous' mode.

                timeout: integer - Timeout in miliseconds to wait before next 'batch' of captured packets is returned

                        (This value maps directly to `libpcap: packet buffer timeout`.)
                        Default value is 10ms. Use lower values for more 'responsive' capture, higher values for larger
                        batches.

                \*\*kw:    Possible Keyword argument's that can be supported.

        """

        super().__init__(queue, **kw)

        self.__iface = iface
        self.__snaplen = snaplen
        self.__promisc = promisc
        self.__timeout = timeout
        self.__pcap_activated = False

    # Property Classes: All are read-only there is little value in making
    # these, read-write. For now at-least
    @property
    def iface(self):
        return self.__iface

    @property
    def snaplen(self):
        return self.__snaplen

    @property
    def promisc(self):
        return self.__promisc

    @property
    def timeout(self):
        return self.__timeout

    def open(self):
        """ Open's the Capturerer readying it for performing capture.

            Calls libpcap's `pcap_create` and depending upon requested
            parameters during the Constructor, those values are set and
            finally activates the handle.
        """

        _logger.debug("%s.open", self.__class__.__name__)

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

        dltype = pcap_lib.pcap_datalink(handle)
        if dltype < 0:
            self.close()

            err_charptr = pcap_lib.pcap_geterr(handle)
            err_str = pcap_ffi.string(err_charptr).decode()
            raise WishpyCapturerOpenError("Failed to get Datalink Layer Type: {}".\
                    format(err_str))

        # FIXME: Warning to be reported
        self._dltype = dltype
        self.__pcap_activated = True
        self._pcap_handle = handle

    def close(self):
        """ Closes internal `libpcap` handle

            libpcap's `pcap_close` function is called and our activated flag
            is set to False.
        """
        if self._pcap_handle is not None:
            pcap_lib.pcap_close(self._pcap_handle)
        self._pcap_handle = None
        self.__pcap_activated = False

        _logger.debug("%s.close", self.__class__.__name__)

    def __repr__(self):
        return "{} iface:{}, snaplen:{}, promisc:{}, timeout:{}".\
                format(self.__class__.__name__,
                        self.__iface, self.__snaplen,
                        self.__promisc, self.__timeout)


class WishpyCapturerFileToQueue(WishpyCapturerQueue):
    """A Libpcap capturer class that wraps a PCAP file.

    This class provides the `Capturer` API wrapping a PCAP file. Note: For the
    dissection part it is better to directly use
    :class:`wishpy.wireshark.lib.dissector.WishpyDissectorFile`. This class
    should be used when you want to take packets from a PCAP file and do
    something other than 'dissect'ing them.

    """

    def __init__(self, filename, queue, **kw):
        """Constructor

            Args:
                filename: PCAP file to be opened for reading.

                queue:  Queue to send packets to.
        """

        super().__init__(queue, **kw)

        self.__filename = filename
        self._dltype = -1

    @property
    def filename(self):
        return self.__filename

    def open(self):
        """Opens the filename for PCAP Capture.

        Returns: None
        Raises: WishpyCapturerOpenError: If failure to open a file.
        """
        err_buff = pcap_ffi.new('char [256]')
        handle = pcap_lib.pcap_open_offline(self.filename.encode(), err_buff)
        if handle == pcap_ffi.NULL:
            err_str = pcap_ffi.string(err_buff)
            raise WishpyCapturerOpenError(err_str)

        dltype = pcap_lib.pcap_datalink(handle)
        if dltype < 0:
            self.close()

            err_charptr = pcap_lib.pcap_geterr(handle)
            err_str = pcap_ffi.string(err_charptr).decode()
            raise WishpyCapturerOpenError("Failed to get Datalink Layer Type: {}".\
                    format(err_str))

        self._pcap_handle = handle
        self._dltype = dltype

    def close(self):
        """ Closes internal `libpcap` handle

            libpcap's `pcap_close` function is called and our activated flag
            is set to False.
        """
        if self._pcap_handle is not None:
            pcap_lib.pcap_close(self._pcap_handle)
        self._pcap_handle = None
        self._dltype = -1

        _logger.debug("%s.close", self.__class__.__name__)

    def __repr__(self):
        return "{} filename:{}".format(self.__class__.__name__, self.__filename)


if __name__ == '__main__': #pragma: no cover
    from queue import Queue
    c = LibpcapCapturerIface('wlp2s0', Queue())
    print(c)
    c.open()
    c.start(count=1)
    c.close()
