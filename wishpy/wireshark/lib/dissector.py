"""APIs for wireshark's dissectors.

This module provides consistent APIs for using wireshark's dissector in
different scenarios. viz. using with live packet capture and using with
a PCAP file. A couple of dissector classes are provided that can be directly used.

WishpyDissectorQueuePython : Can be used with `wishpy.libpcap.lib.capturer.Capturer`
WishpyDissectorFile: Can be used for printing json data from a pcap(ish) file.

Example:

>>> d = WishpyDissectorFile('file.pcap')
>>> for packet in d.run():
    print(packet)

"""
import socket
import struct
import json
import time
from datetime import datetime as dt
import unicodedata
import logging

from ._wrapper import *
from ...libpcap.lib.capturer import PCAPHeader, pcap_ffi

class WishpyErrorInitDissector(Exception):
    """Error raised during initialization of dissector and or dissector session.
    """
    pass

class WishpyEpanLibUninitializedError(Exception):
    """Error raised during initialization of EPAN library.
    """
    pass

class WishpyEpanLibAlreadyInitialized(Exception):
    """Error raised trying to initialize already initialized EPAN Library.
    """
    pass

class WishpyErrorWthOpen(Exception):
    """Error raised during opening a Pcap file.
    """
    pass

_logger = logging.getLogger(__name__)

_EPAN_LIB_INITIALIZED = False


class WishpyDissectorBase:
    """ A Class that wraps the underlying dissector from epan module of
    `libwireshark`. Right now this simply prints the dissector tree.
    """

    _pretty = False

    _test_json = False

    # We are having these definitions in the class because a lot many of them
    # are used in fast path and having them dereferenced here gives us some
    # performance, so why not?
    NULL = epan_ffi.NULL
    epan_string = epan_ffi.string
    addressof = epan_ffi.addressof

    BASE_NONE = epan_lib.BASE_NONE
    BASE_DEC = epan_lib.BASE_DEC
    BASE_HEX = epan_lib.BASE_HEX
    BASE_OCT = epan_lib.BASE_OCT
    BASE_DEC_HEX = epan_lib.BASE_DEC_HEX
    BASE_HEX_DEC = epan_lib.BASE_HEX_DEC
    BASE_PT_TCP = epan_lib.BASE_PT_TCP
    BASE_PT_UDP = epan_lib.BASE_PT_UDP
    BASE_PT_SCTP = epan_lib.BASE_PT_SCTP
    BASE_OUI = epan_lib.BASE_OUI

    BASE_RANGE_STRING = epan_lib.BASE_RANGE_STRING
    BASE_EXT_STRING = epan_lib.BASE_EXT_STRING
    BASE_VAL64_STRING = epan_lib.BASE_VAL64_STRING
    BASE_ALLOW_ZERO = epan_lib.BASE_ALLOW_ZERO
    BASE_UNIT_STRING = epan_lib.BASE_UNIT_STRING
    BASE_NO_DISPLAY_VALUE = epan_lib.BASE_NO_DISPLAY_VALUE
    BASE_PROTOCOL_INFO = epan_lib.BASE_PROTOCOL_INFO
    BASE_SPECIAL_VALS = epan_lib.BASE_SPECIAL_VALS
    BASE_CUSTOM = epan_lib.BASE_CUSTOM

    FT_ETHER = epan_lib.FT_ETHER
    FT_IPv4 = epan_lib.FT_IPv4
    FT_BOOLEAN = epan_lib.FT_BOOLEAN
    FT_STRING = epan_lib.FT_STRING
    FT_BYTES = epan_lib.FT_BYTES
    FT_RELATIVE_TIME = epan_lib.FT_RELATIVE_TIME
    FT_ABSOLUTE_TIME = epan_lib.FT_ABSOLUTE_TIME
    FT_NONE = epan_lib.FT_NONE
    FT_PROTOCOL = epan_lib.FT_PROTOCOL

    FT_INT8 = epan_lib.FT_INT8
    FT_INT16 = epan_lib.FT_INT16
    FT_INT24 = epan_lib.FT_INT24
    FT_INT32 = epan_lib.FT_INT32
    FT_INT40 = epan_lib.FT_INT40
    FT_INT48 = epan_lib.FT_INT48
    FT_INT56 = epan_lib.FT_INT56
    FT_INT64 = epan_lib.FT_INT64
    FT_CHAR = epan_lib.FT_CHAR
    FT_UINT8 = epan_lib.FT_UINT8
    FT_UINT16 = epan_lib.FT_UINT16
    FT_UINT24 = epan_lib.FT_UINT24
    FT_UINT32 = epan_lib.FT_UINT32
    FT_UINT40 = epan_lib.FT_UINT40
    FT_UINT48 = epan_lib.FT_UINT48
    FT_UINT56 = epan_lib.FT_UINT56
    FT_UINT64 = epan_lib.FT_UINT64
    FT_FRAMENUM = epan_lib.FT_FRAMENUM

    FT_FLOAT = epan_lib.FT_FLOAT
    FT_DOUBLE = epan_lib.FT_DOUBLE



    epan_int_types = [
                FT_INT8,
                FT_INT16,
                FT_INT32,
                FT_INT40,
                FT_INT48,
                FT_INT56,
                FT_INT64]

    epan_uint32_types = [
                FT_CHAR,
                FT_UINT8,
                FT_UINT16,
                FT_UINT24,
                FT_UINT32,
                FT_FRAMENUM]

    epan_uint_types = epan_uint32_types + \
            [ FT_UINT40, FT_UINT48, FT_UINT56, FT_UINT64]

    epan_all_int_types = epan_int_types + epan_uint_types

    unquoted_types = epan_all_int_types + \
            [FT_BOOLEAN, FT_RELATIVE_TIME, FT_FLOAT, FT_DOUBLE]

    # Below are some dict's required for printing few packet types
    hfbases = {
            BASE_NONE : ('{:d}', False), # Not sure how this is to be treated
            BASE_DEC : ('{:d}', False),
            BASE_HEX : ('0x{:x}', True),
            BASE_OCT : ('{:o}', True),
            BASE_DEC_HEX: ('{:d}(0x{:x})', True),
            BASE_HEX_DEC: ('0x{:x}({:d})', True),
            BASE_PT_TCP: ('{:d}', False),
            BASE_PT_UDP: ('{:d}', False),
            BASE_PT_SCTP: ('{:d}', False)

     }

    FTREPR_DISPLAY = epan_lib.FTREPR_DISPLAY
    fvalue_to_string_repr = epan_lib.fvalue_to_string_repr
    wmem_free = epan_lib.wmem_free

    @classmethod
    def enable_json_test(cls):
        cls._test_json = True

    @classmethod
    def enable_pretty_print(cls):
        self._pretty = True

    @classmethod
    def remove_ctrl_chars(cls, s):
        """Removes the Ctrl Characters from the string.
        """
        # FIXME: May be we should replace them with their unicode code points
        category_fn = unicodedata.category
        return "".join(ch for ch in s if category_fn(ch)[0] != "C")

    @classmethod
    def func_not_supported(cls, *args):
        return "Not Supported"

    @classmethod
    def epan_ether_to_str(cls, fvalue, ftype, display, abbrev):
        """ Converting Ethernet addresses to String"""

        eth_bytes = fvalue.value.bytes

        display_bytes = []
        for i in range(eth_bytes.len):
            display_byte = "{:02X}".format(eth_bytes.data[i])
            display_bytes.append(display_byte)

        return ":".join(display_bytes), True

    epan_bytes_to_str = epan_ether_to_str

    @classmethod
    def epan_str_to_str(cls, fvalue, ftype, display, abbrev):
        """Converting epan 'char *' to Python String"""

        value = fvalue.value.string

        # If display is BASE_NONE, utf-8 is fine, but for others, not always! (GSM-Unicode)
        if display == 0:
            x = cls.epan_string(value).decode().\
                    replace('\\', '\\\\').\
                    replace('"', '\\"')
            return cls.remove_ctrl_chars(x), True
        else:
            try:
                x = cls.epan_string(value).decode("utf-8").\
                        replace('\\', '\\\\').\
                        replace('"', '\\"')
                return cls.remove_ctrl_chars(x), True
            except Exception as e:
                _logger.exception("epan_str_to_str: (%s) %s", abbrev, x)
                return "Cannot Decode"

    @classmethod
    def epan_ipv4_to_str(cls, fvalue, ftype, display, abbrev):
        """Converting IP Address to Python String"""

        ipv4 = fvalue.value.ipv4

        return socket.inet_ntoa(struct.pack('!I', ipv4.addr)), True

    @classmethod
    def epan_bool_to_str(cls, fvalue, ftype, display, abbrev,
            on_off=False, json_compat=True):
        """ Converting `gboolean` to String"""

        if on_off and json_compat:
            raise ValueError("Specify Either on_off or json_compat not both.")

        value = bool(fvalue.value.uinteger)

        if value:
            if json_compat:
                return "true", False
            if on_off:
                return "ON", True
        else:
            if json_compat:
                return "false", False
            if on_off:
                return "OFF", True

        return "{}".format(value)

    @classmethod
    def epan_int_to_str(cls, fvalue, ftype, display, abbrev):
        """Converting Integer to String, using BASE_* property."""

        try:
            # FIXME: We can definitely do better than these `if`s.
            # We are ignoring all fancy display options for now
            if display & cls.BASE_RANGE_STRING:
                display ^= cls.BASE_RANGE_STRING

            if display & cls.BASE_EXT_STRING:
                display ^= cls.BASE_EXT_STRING

            if display & cls.BASE_VAL64_STRING:
                display ^= cls.BASE_VAL64_STRING

            if display & cls.BASE_ALLOW_ZERO:
                display ^= cls.BASE_ALLOW_ZERO

            if display & cls.BASE_UNIT_STRING:
                display ^= cls.BASE_UNIT_STRING

            if display & cls.BASE_NO_DISPLAY_VALUE:
                display ^= cls.BASE_NO_DISPLAY_VALUE

            if display & cls.BASE_PROTOCOL_INFO:
                display ^= cls.BASE_PROTOCOL_INFO

            if display & cls.BASE_SPECIAL_VALS:
                display ^= cls.BASE_SPECIAL_VALS

            # Change the custom display to `Decimal` for now
            if display == cls.BASE_CUSTOM:
                display = cls.BASE_DEC

            if display == cls.BASE_OUI:
                display = cls.BASE_HEX

            base_format, quote = cls.hfbases[display]

        except:
            _logger.exception("epan_int_to_str: (%s) %d %d", abbrev, ftype, display)
            return "type: {} display: {} Not Supported".format(ftype, display), True

        return base_format.format(fvalue.value.uinteger,
                fvalue.value.uinteger), quote

    @classmethod
    def epan_abstime_to_str(cls, fvalue, ftype, display, abbrev):
        timeval = fvalue.value.time
        timeval = timeval.secs + timeval.nsecs / 1000000000
        value = dt.strftime(dt.fromtimestamp(timeval), '%d-%b-%Y %H:%M:%S.%f %Z')
        return value, True


    @classmethod
    def epan_reltime_to_str(cls, fvalue, ftype, display, abbrev):
        value = fvalue.value.time
        return "{:.9f}".format(value.secs + value.nsecs / 1000000000), False

    @classmethod
    def epan_none_to_str(cls, fvalue, ftype, display, abbrev):
        return None, None

    to_str_funcs = {
            FT_ETHER : epan_ether_to_str.__func__,
            FT_IPv4 : epan_ipv4_to_str.__func__,
            FT_BOOLEAN : epan_bool_to_str.__func__,
            FT_STRING : epan_str_to_str.__func__,
            FT_BYTES : epan_bytes_to_str.__func__,
            FT_RELATIVE_TIME : epan_reltime_to_str.__func__,
            FT_ABSOLUTE_TIME : epan_abstime_to_str.__func__,
            FT_NONE : epan_none_to_str.__func__,
            FT_PROTOCOL : epan_none_to_str.__func__
    }

    all_int_to_str_funcs = [epan_int_to_str.__func__] * len(epan_all_int_types)
    to_str_funcs.update(zip(epan_all_int_types, all_int_to_str_funcs))

    @classmethod
    def value_to_str(cls, finfo):
        """
        Returns string representation of the `finfo.value`
        """

        fvalue = finfo.value
        ftype = finfo.hfinfo[0].type
        display = finfo.hfinfo[0].display
        abbrev = cls.epan_string(finfo.hfinfo[0].abbrev).decode()

        epan_int_types = cls.epan_int_types
        epan_uint32_types = cls.epan_uint32_types
        epan_uint_types = cls.epan_uint_types
        epan_all_int_types = cls.epan_all_int_types

        try:
            fn = cls.to_str_funcs[ftype]
            return fn(cls, fvalue, ftype, display, abbrev)
        except KeyError as e:
            #_logger.exception("unknown type: %d", ftype)

            return "{} {}".format(ftype, display), True

    @classmethod
    def print_dissected_tree_pretty_ftype_api(cls, node_ptr, level=1):
        """Returns a string that represents a dissected tree.
        """
        return_str = ""

        node = node_ptr[0]
        finfo = node.finfo

        finfo_display_str = None
        if finfo != cls.NULL:

            hfinfo = finfo.hfinfo[0]
            display = hfinfo.display
            abbrev = cls.epan_string(hfinfo.abbrev).decode()
            abbrev_str = '"' + abbrev + '"'
            return_str += abbrev_str + " : "
            finfo_str = cls.fvalue_to_string_repr(
                    cls.NULL,
                    cls.addressof(finfo[0].value),
                    cls.FTREPR_DISPLAY,
                    display)

            if finfo_str != cls.NULL:
                finfo_display_str = cls.epan_string(finfo_str).decode()
                if hfinfo.type not in cls.unquoted_types:
                    if hfinfo.type == cls.FT_STRING:
                        finfo_display_str = finfo_display_str.\
                                replace('\\', '\\\\').replace('"', '\\"')
                        finfo_display_str = cls.remove_ctrl_chars(finfo_display_str)
                    finfo_display_str = '"' + finfo_display_str + '"'
                else:
                    try:
                        _, quote = cls.hfbases[display]
                    except KeyError as e:
                        quote = True

                    if quote:
                        finfo_display_str = '"' + finfo_display_str + '"'

                cls.wmem_free(cls.NULL, finfo_str)

                return_str += finfo_display_str

        lspaces = " " * level
        lspaces_1 = " " * (level - 1)
        newlevel = level + 1

        child = node.first_child
        if child != cls.NULL:

            if finfo_display_str:
                return_str += ",\n"

                abbrev_tree = abbrev + "_tree"
                abbrev_tree_str = '"' + abbrev_tree + '"'

                return_str += lspaces_1
                return_str += abbrev_tree_str + " : "

            return_str += "{"
            return_str += "\n"
            while child != cls.NULL:
                return_str += lspaces
                return_str += cls.print_dissected_tree_pretty_ftype_api(child, newlevel)
                child = child.next
            return_str += lspaces

            return_str += "\n" + lspaces_1
            return_str += "}"
        else: # child is not None So we have someone who's FT_NONE, FT_PROTOCOL and no tree?
            if not finfo_display_str:
                return_str += "\"\""
        if node.next != cls.NULL:
            return_str += ",\n"

        return return_str

    @classmethod
    def print_dissected_tree(cls, node_ptr):
        """Returns a string that represents a dissected tree.
        """
        return_str = ""

        node = node_ptr[0]
        finfo = node.finfo
        if finfo != cls.NULL:

            hfinfo = finfo.hfinfo[0]
            abbrev = cls.epan_string(hfinfo.abbrev).decode()
            abbrev_str = '"' + abbrev + '"'
            return_str += abbrev_str + ":"
            finfo_display_str, quote = cls.value_to_str(finfo)
            if finfo_display_str:
                if quote:
                    finfo_display_str = '"' + finfo_display_str + '"'
        else:
            finfo_display_str = ""

        if finfo_display_str is not None:
            return_str += finfo_display_str

        child = node.first_child
        if child != cls.NULL:

            if finfo_display_str:
                return_str += ","

                abbrev_tree = abbrev + "_tree"
                abbrev_tree_str = '"' + abbrev_tree + '"'
                return_str += abbrev_tree_str + ":"

            return_str += "{"
            while child != cls.NULL:
                return_str += cls.print_dissected_tree(child)
                child = child.next

            return_str += "}"
        else: # child is not None So we have someone who's FT_NONE, FT_PROTOCOL and no tree?
            if not finfo_display_str:
                return_str += "\"\""
        if node.next != cls.NULL:
            return_str += ","

        return return_str

    @classmethod
    def print_dissected_tree_ftype_api(cls, node_ptr):
        """Returns a string representing dissected tree using the `ftypes` API.
        """
        return_str = ""

        node = node_ptr[0]
        finfo = node.finfo

        finfo_display_str = None
        if finfo != cls.NULL:

            hfinfo = finfo.hfinfo[0]
            display = hfinfo.display
            abbrev = cls.epan_string(hfinfo.abbrev).decode()
            abbrev_str = '"' + abbrev + '"'
            return_str += abbrev_str + ":"
            finfo_str = cls.fvalue_to_string_repr(
                    cls.NULL,
                    cls.addressof(finfo[0].value),
                    cls.FTREPR_DISPLAY,
                    display)

            if finfo_str != cls.NULL:
                finfo_display_str = cls.epan_string(finfo_str).decode()
                if hfinfo.type not in cls.unquoted_types:
                    if hfinfo.type == cls.FT_STRING:
                        finfo_display_str = finfo_display_str.\
                                replace('\\', '\\\\').replace('"', '\\"')
                        finfo_display_str = cls.remove_ctrl_chars(finfo_display_str)
                    finfo_display_str = '"' + finfo_display_str + '"'
                else:
                    try:
                        _, quote = cls.hfbases[display]
                    except KeyError as e:
                        quote = True

                    if quote:
                        finfo_display_str = '"' + finfo_display_str + '"'

                cls.wmem_free(cls.NULL, finfo_str)

                return_str += finfo_display_str

        child = node.first_child
        if child != cls.NULL:

            if finfo_display_str:
                return_str += ","

                abbrev_tree = abbrev + "_tree"
                abbrev_tree_str = '"' + abbrev_tree + '"'
                return_str += abbrev_tree_str + ":"

            return_str += "{"
            while child != cls.NULL:
                return_str += cls.print_dissected_tree_ftype_api(child)
                child = child.next

            return_str += "}"
        else: # child is not None So we have someone who's FT_NONE, FT_PROTOCOL and no tree?
            if not finfo_display_str:
                return_str += "\"\""
        if node.next != cls.NULL:
            return_str += ","

        return return_str

    @classmethod
    def packet_to_json(cls, handle_ptr):
        """ An example method that depicts how to use internal dissector API."""

        dissector = handle_ptr[0]

        # FIXME: following should be like json dumps
        if cls._pretty:
            s = cls.print_dissected_tree_pretty_ftype_api(dissector.tree)
        else:
            s = cls.print_dissected_tree_ftype_api(dissector.tree)
        try:
            if cls._test_json:
                _ = json.loads(s, strict=False)
        except json.decoder.JSONDecodeError as e:
            _logger.exception("packet_to_json", e.doc)
            return {}
        except Exception as e:
            _logger.exception("packet_to_json")
            # FIXME: May be we should raise, let caller take care.
            return {}

        return s

    def __init__(self, *args, **kw):
        self._epan_dissector = None
        self._elapsed_time_ptr = None
        self._ref_frame_data_ptr = None
        self._first_frame_data = None
        self._last_frame_data = None
        self._provider = None

    @property
    def last_frame_data(self):
        return self._last_frame_data

    @property
    def first_frame_data(self):
        return self._first_frame_data

    @property
    def ref_frame_data_ptr(self):
        return self._ref_frame_data_ptr

    @property
    def elapsed_time_ptr(self):
        return self._elapsed_time_ptr

    @property
    def epan_dissector(self):

        return self._epan_dissector

    @property
    def epan_session(self):
        if self._epan_dissector is None:
            return None

        return self._epan_dissector[0].session

    def init_epan_dissector(self):
        """Initializes `epan_dissect_t` and `epan_session` objects. These
        objects are passed to the `run` method.
        """
        if self._epan_dissector is not None:
            raise WishpyErrorInitDissector("Dissector already initialized?")

        self._elapsed_time_ptr = epan_ffi.new('nstime_t *')

        self._ref_frame_data_ptr = epan_ffi.new('frame_data **')
        self._ref_frame_data_ptr[0] = self.NULL

        self._first_frame_data = epan_ffi.new('frame_data *')
        self._last_frame_data = epan_ffi.new('frame_data *')

        self._provider = epan_ffi.new('struct packet_provider_data *')
        self._provider[0].ref = self._first_frame_data
        self._provider[0].prev = self._last_frame_data

        session = epan_new_session(self._provider)
        self._epan_dissector = epan_new_dissector(session)


    def cleanup_epan_dissector(self):
        """Cleans up internal dissector object.
        """
        session = self.epan_session

        epan_free_dissector(self._epan_dissector)
        self._epan_dissector = None

        epan_free_session(session)

        del self._elapsed_time_ptr
        del self._first_frame_data
        del self._last_frame_data
        del self._provider
        del self._ref_frame_data_ptr

        self._elapsed_time_ptr = None


    def run(self, *args, **kw):
        """A generator function `yield`ing at-least the dissected packets.

        Implementing this as a generator function helps one to run code
        that looks like

        >>> for dissected in dissector.run(count=1):
            # do stuff with the dissected packet

        This is particularly convenient while performing live capture on
        an interface or dissecting a huge file.

        """
        raise NotImplemented("Derived Classes need to implement this.")


class WishpyDissectorFile(WishpyDissectorBase):
    """Dissector class for PCAP Files.
    """

    def __init__(self, filename):
        super().__init__()
        self.__filename = filename

    def run(self, count=0, skip=-1):
        """
        Actual function that performs the Dissection. Right now since we are
        only supporting dissecting packets from Wiretap supported files,
        only dissects packets from a pcap(ish) file.

        """

        if not _EPAN_LIB_INITIALIZED:
            raise WishpyEpanLibUninitializedError(
                    "Epan Library Not initialized. Did you call setup_process()"
                    )

        self.init_epan_dissector()
        # FIXME: dissector.run can be run only once right now
        # FIXME: Pass errno / errstr ourselves to get the error to be passed
        # to the Exception handler

        # FIXME: Do this as a context manager
        try:
            wth, wth_filetype = wtap_open_file_offline(self.__filename)
            if wth is None:
                raise WishpyErrorWthOpen("Error Opening wiretap file: %s" % self.__filename)

            yield from epan_perform_dissection(self, wth, wth_filetype,
                    self.packet_to_json, count, skip)

        except WishpyErrorWthOpen as e:
            _logger.exception("WishpyDissectorFile.run:WishpyErrorWithOpen")
            raise

        except Exception as e:
            _logger.exception("WishpyDissectorFile.run")

        finally:
            # If we don't close `wtap` here, outer `cleanup_process` croaks
            if wth is not None:
                wtap_close(wth)

            self.cleanup_epan_dissector()

        return


class WishpyDissectorQueue(WishpyDissectorBase):
    """Dissector class for packets received from a Queue(ish) object.
    """

    def dissect_one_packet(self):
        """Dissects a single packet

        This should typically call `fetch` and the perform dissection. All
        the queue based `dissectors` will dissect one packet at a time, so
        it's better that this function is in the base class.

        """
        hdr, data = self.fetch()

        # FIXME: This might slowdown things but for now fine.
        if isinstance(hdr, PCAPHeader):
            newhdr = pcap_ffi.new('struct pcap_pkthdr *')
            newhdr[0].ts.tv_sec = hdr.ts_sec
            newhdr[0].ts.tv_usec = hdr.ts_usec
            newhdr[0].caplen = hdr.caplen
            newhdr[0].len = hdr.len

            hdr = newhdr

            if isinstance(data, bytes):
                alloc_str = 'char [%d]' % hdr.caplen
                newdata = epan_ffi.new(alloc_str)
                epan_ffi.memmove(newdata, data, hdr.caplen)

                data = newdata

        d = epan_perform_one_packet_dissection(self, self._packets_fetched,
                hdr, data, self.packet_to_json)

        return hdr, data, d

    def fetch(self):
        """Implement this function to fetch a single packet from the queue.

        Implementation of this function should return the object of the type
        `Hdr` and `PacketData`

        """
        raise NotImplemented("Derived Classes Need to implement this.")



class WishpyDissectorQueuePython(WishpyDissectorQueue):
    """Dissector class for Python Standard Library Queue.
    """

    def __init__(self, queue):

        super().__init__()

        self.__queue = queue
        self.__running = False
        self.__stop_requested = False
        self._packets_fetched = 0

    def fetch(self):
        """Blocking Fetch from a Python Queue.
        """
        hdr, data = self.__queue.get()
        self._packets_fetched += 1
        return hdr, data

    def __iter__(self):
        return self

    def __next__(self):
        """Returns next `fetch`ed packet. (Blocking)
        """
        return self.dissect_one_packet()

    def run(self, count=0):
        """yield's the packet, up to maximum of `count` packets.

        if count is <= 0, infinite iterator.

        """

        self.__running = True

        self.init_epan_dissector()

        fetched = 0
        while True:
            fetched += 1
            try:
                hdr, data, d = self.dissect_one_packet()
            except:
                _logger.exception("dissect_one_packet")
                break

            x = yield (hdr, data, d)

            if self.__stop_requested == True:
                break

            if x and x.lower() == 'stop':
                break

            if fetched == count:
                break

        self.cleanup_epan_dissector()

        self.__running = False

    def stop(self):
        """Stop's the generator by setting internal state."""
        self.__stop_requested = True


def setup_process():
    """
    This method should be called once per process (note: Not thread.) This
    will perform underlying library initialization, so that eventually
    dissectors can `run`.
    """

    global _EPAN_LIB_INITIALIZED

    if _EPAN_LIB_INITIALIZED:
        raise WishpyEpanLibAlreadyInitialized(
                "Epan Library already initialized. setup_process() "\
                        "should be called only once per process.")

    _EPAN_LIB_INITIALIZED = perform_epan_wtap_init()


def cleanup_process():
    """
    Per process cleanup. de-init of epan/wtap modules.
    """

    perform_epan_wtap_cleanup()

    global _EPAN_LIB_INITIALIZED
    _EPAN_LIB_INITIALIZED = False

