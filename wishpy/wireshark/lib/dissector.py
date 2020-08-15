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
import os
import socket
import struct
import json
import time
from datetime import datetime as dt
import unicodedata
import logging

_logger = logging.getLogger(__name__)

from ._wrapper import *
try:
    from ...libpcap.lib.capturer import PCAPHeader, pcap_ffi
except: #pragma: no cover
    if os.getenv('READTHEDOCS', None) is not None:
        _logger.warning("Import Error, but it's okay during RTD Build.")
    else:
        _logger.warning("Import Error, Ignoring for now.")
        pass #raise

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

    # Keys: BAS_XXX value `quote` (Whether returned value should be quoted.)
    hfbases = {
            BASE_NONE : False, # Not sure how this is to be treated
            BASE_DEC : False,
            BASE_HEX : True,
            BASE_OCT : True,
            BASE_DEC_HEX: True,
            BASE_HEX_DEC: True,
            BASE_PT_TCP: False,
            BASE_PT_UDP: False,
            BASE_PT_SCTP: False

     }

    FTREPR_DISPLAY = epan_lib.FTREPR_DISPLAY
    fvalue_to_string_repr = epan_lib.fvalue_to_string_repr
    wmem_free = epan_lib.wmem_free

    @classmethod
    def enable_json_test(cls):
        cls._test_json = True

    @classmethod
    def pretty_print(cls, enabled):
        cls._pretty = enabled
        if enabled:
            cls.packet_print_func = cls.print_dissected_tree_pretty_ftype_api
        else:
            cls.packet_print_func = cls.print_dissected_tree_ftype_api

    @classmethod
    def remove_ctrl_chars(cls, s):
        """Removes the Ctrl Characters from the string.
        """
        # FIXME: May be we should replace them with their unicode code points
        category_fn = unicodedata.category
        return "".join(ch for ch in s if category_fn(ch)[0] != "C")

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
                        quote = cls.hfbases[display]
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
                        quote = cls.hfbases[display]
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

    packet_print_func = print_dissected_tree_ftype_api

    @classmethod
    def packet_to_json(cls, handle_ptr):
        """ An example method that depicts how to use internal dissector API."""

        dissector = handle_ptr[0]

        s = cls.packet_print_func(dissector.tree)
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
        """A generator function ``yield``ing at\-least the dissected packets.


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

        if hdr == 'stop':
            self._stop_requested = True
            return hdr, data, None

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
        self._stop_requested = False
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

            if self._stop_requested == True:
                break

            if x and x.lower() == 'stop':
                break

            if fetched == count:
                break

        self.cleanup_epan_dissector()

        self.__running = False

    def stop(self):
        """Stop's the generator by setting internal state."""
        self._stop_requested = True


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

    global _EPAN_LIB_INITIALIZED

    if _EPAN_LIB_INITIALIZED:
        perform_epan_wtap_cleanup()
    else:
        _logger.warning("cleanup_process called without init process!")

    _EPAN_LIB_INITIALIZED = False

