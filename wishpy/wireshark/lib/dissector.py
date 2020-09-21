"""APIs for wireshark's dissectors.

This module provides consistent APIs for using wireshark's dissector in
different scenarios. viz. using with live packet capture and using with
a PCAP file. A couple of dissector classes are provided that can be directly used.

:class:`WishpyDissectorQueuePython` : Can be used with :class:`wishpy.libpcap.lib.capturer.WishpyCapturer`
:class:`WishpyDissectorFile`: Can be used for printing json data from a pcap(ish) file.

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
    ``libwireshark``. Right now this simply prints the dissector tree.
    """

    _pretty = False
    _add_proto_tree = False
    _test_json = True
    _elasticky = False

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

    libpcap_to_wtap_enctpyes = {
            1: 1, # Enctype Ethernet is same
            127: 23, # Radiotap
            113: 25
    }
    FTREPR_DISPLAY = epan_lib.FTREPR_DISPLAY
    fvalue_to_string_repr = epan_lib.fvalue_to_string_repr
    wmem_free = epan_lib.wmem_free

    @classmethod
    def set_elasticky(cls, enabled):
        """Enable Elastic Compatible Json output."""
        cls._elasticky = enabled

    @classmethod
    def enable_json_test(cls):
        """Enable ``json.loads`` test of the generated Json."""

        cls._test_json = True

    @classmethod
    def set_pretty_print_details(cls, enabled=False, add_proto_tree=False):
        """Set Pretty Printing and Details of a Packet Field."""
        cls._pretty = enabled
        if enabled:
            cls.packet_print_func = cls.print_dissected_tree_json_pretty
        else:
            cls.packet_print_func = cls.print_dissected_tree_json

        if add_proto_tree:
            cls._add_proto_tree = True

    @classmethod
    def print_dissected_tree_json_pretty(cls, dissector):
        """Pretty prints dissected tree."""
        node = dissector[0].tree
        return cls.print_dissected_tree_json_node_pretty(node)

    @classmethod
    def print_dissected_tree_json_node_pretty(cls, node_ptr, level=1):
        """Returns a string that represents a dissected tree.
        """
        return_str = ""
        tabstop = 4

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
                        finfo_display_str = cls._remove_ctrl_chars(finfo_display_str)
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

        lspaces = " " * level * tabstop
        lspaces_1 = " " * (level - 1) * tabstop
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
                return_str += cls.print_dissected_tree_json_node_pretty(child, newlevel)
                child = child.next
            return_str += lspaces

            return_str += "\n" + lspaces_1

            # details - protect by a flag
            if level == 1 and cls._add_proto_tree:
                return_str += ","
                return_str += "\"proto_tree\":"
                return_str += "\"" + cls.print_dissected_tree_details_node(node_ptr, level) + "\""

            return_str += "}"
        else: # child is not None So we have someone who's FT_NONE, FT_PROTOCOL and no tree?
            if not finfo_display_str:
                return_str += "\"\""
        if node.next != cls.NULL:
            return_str += ",\n"

        return return_str

    @classmethod
    def print_dissected_tree_json(cls, dissector):
        node = dissector[0].tree
        return cls.print_dissected_tree_json_node_simple(node)

    @classmethod
    def print_dissected_tree_json_node_simple(cls, node_ptr, level=1, add_subtrees=True):

        tabstop = 2

        if cls._elasticky:
            add_subtrees = False

        inside_subtree = False

        pretty = False
        spaces = ""
        if pretty:
            spaces = " " * tabstop * (level - 1)

        return_str = ""
        node = node_ptr[0]
        finfo = node.finfo
        hfinfo = None

        if finfo != cls.NULL:

            hfinfo = finfo.hfinfo[0]
            abbrev = cls.epan_string(hfinfo.abbrev).decode()
            display = hfinfo.display

            finfo_str = cls.fvalue_to_string_repr(
                    cls.NULL,
                    cls.addressof(finfo[0].value),
                    cls.FTREPR_DISPLAY,
                    display)
            #print(abbrev, hfinfo.type, finfo_str, level)

            abbrev_str = spaces + "\"" + abbrev + "\":"
            if hfinfo.type == 0:
                # FIXME: Properly add a tree here
                if not add_subtrees:

                    field_str = "\"\""
                    if node.first_child != cls.NULL:
                        field_str += ","
                else:

                    field_str = "{"
                    inside_subtree = True
                    if pretty:
                        field_str += "\n"

                return_str += abbrev_str + field_str
            elif hfinfo.type == 1:

                # protocol:
                field_str = "{"
                inside_subtree = True
                if pretty:
                    field_str += "\n"

                return_str += abbrev_str + field_str
            else:
                if finfo_str != cls.NULL:
                    field_str = cls.epan_string(finfo_str).decode()
                    if hfinfo.type not in cls.unquoted_types:
                        if hfinfo.type == cls.FT_STRING:
                            field_str = field_str.\
                                    replace('\\', '\\\\').replace('"', '\\"')
                            field_str = cls._remove_ctrl_chars(field_str)
                        field_str = '"' + field_str + '"'
                    else:
                        try:
                            quote = cls.hfbases[display]
                        except KeyError as e:
                            quote = True

                        if quote:
                            field_str = '"' + field_str + '"'

                else:
                    field_str = ""

                # If this field has a child, we've to add it's "," now
                if node.first_child != cls.NULL:
                    field_str += ","
                    if pretty:
                        field_str += "\n"

                return_str += abbrev_str + field_str
                    # FIXME: We are going to add tree here!!
        else:
            # Top Level
            return_str += "{"

        child = node.first_child

        while child != cls.NULL:
            child_str = cls.print_dissected_tree_json_node_simple(child, level+1)
            return_str += child_str

            child = child.next

        if finfo != cls.NULL:
            if inside_subtree:
                return_str += spaces + "}"
        else:
            # Top Level
            return_str += "}"

        if node.next != cls.NULL:
            if return_str:
                return_str += ","

        if pretty:
            return_str += "\n"

        return return_str

    @classmethod
    def print_dissected_tree_json_node(cls, node_ptr, level=1):
        """Returns a string representing dissected tree using the `ftypes` API.
        """
        return_str = ""

        node = node_ptr[0]
        finfo = node.finfo

        finfo_display_str = None
        if finfo != cls.NULL:

            hfinfo = finfo.hfinfo[0]
            abbrev = cls.epan_string(hfinfo.abbrev).decode()
            display = hfinfo.display

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
                        finfo_display_str = cls._remove_ctrl_chars(finfo_display_str)
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

        newlevel = level + 1
        child = node.first_child
        if child != cls.NULL:

            if finfo_display_str:
                return_str += ","

                abbrev_tree = abbrev + "_tree"
                abbrev_tree_str = '"' + abbrev_tree + '"'
                return_str += abbrev_tree_str + ":"

            return_str += "{"
            while child != cls.NULL:
                return_str += cls.print_dissected_tree_json_node(child, newlevel)
                child = child.next

            if level == 1 and cls._add_proto_tree:
                return_str += ","
                return_str += "\"proto_tree\":"
                return_str += "\"" + cls.print_dissected_tree_details_node(node_ptr, level) + "\""
            return_str += "}"
        else: # child is not None So we have someone who's FT_NONE, FT_PROTOCOL and no tree?
            if not finfo_display_str:
                return_str += "\"\""
        if node.next != cls.NULL:
            return_str += ","

        return return_str

    packet_print_func = print_dissected_tree_json

    @classmethod
    def print_dissected_tree_details_api(cls, dissector):
        """Print a packets Protocol tree using `proto_tree_json` API

        (Note: This method should not be used, instead use `print_dissected_tree_details`.)
        """
        ops = epan_ffi.new('print_stream_ops_t *')
        print_stream = new_wishpy_print_stream(ops)

        cls.ops = ops
        cls.print_stream = print_stream

        epan_lib.proto_tree_print(
                epan_lib.print_dissections_expanded,
                False,
                dissector,
                epan_ffi.NULL,
                print_stream)

    @classmethod
    def print_dissected_tree_details(cls, dissector):
        """Packet Details view of the Dissected Tree like Wireshark Packet Details.
        """
        node = dissector[0].tree
        level = 0
        return cls.print_dissected_tree_details_node(node, level)


    @classmethod
    def print_dissected_tree_details_node(cls, node_ptr, level):
        """Print details of a single Node.

        (Note: This method should not be called directly as yet, instead, one should call
        the `print_dissected_tree_details` method, which internally calls this.)
        """
        tabstop = 4
        label_str = epan_ffi.new('gchar [240]')
        return_str = ""
        spaces = (level - 1) * " " * tabstop

        node = node_ptr[0]
        finfo = node.finfo

        finfo_display_str = None
        if finfo != cls.NULL:

            hfinfo = finfo.hfinfo[0]
            abbrev = cls.epan_string(hfinfo.abbrev).decode()
            display = hfinfo.display
            rep = finfo.rep

            abbrev_str = '"' + abbrev + '"'
            #return_str += abbrev_str + ":"

            if rep != epan_ffi.NULL:
                finfo_str = epan_ffi.string(rep[0].representation)
            else:
                epan_lib.proto_item_fill_label(finfo, label_str)
                finfo_str = epan_ffi.string(label_str)

            finfo_display_str =finfo_str.decode()
            finfo_display_str = finfo_display_str.\
                    replace('\\', '\\\\').replace('"', '\\"')
            finfo_display_str = spaces + cls._remove_ctrl_chars(finfo_display_str)

            return_str += finfo_display_str + "\n"

        newlevel = level + 1
        child = node.first_child
        if child != cls.NULL:

            while child != cls.NULL:
                return_str += cls.print_dissected_tree_details_node(child, newlevel)
                child = child.next


        return return_str

    @classmethod
    def packet_to_json(cls, handle_ptr):
        """An example method that depicts how to use internal dissector API."""

        s = cls.packet_print_func(handle_ptr)
        try:
            if cls._elasticky:
                x = json.loads(s, strict=False, object_pairs_hook=cls._get_elasticky_json)
                s = json.dumps(x)
        except json.decoder.JSONDecodeError as e:
            _logger.exception("packet_to_json %s", e.doc)
            return {}
        except Exception as e:
            _logger.exception("packet_to_json")
            # FIXME: May be we should raise, let caller take care.
            return {}

        return s

    @classmethod
    def _get_elasticky_json(cls, values):
        """Internal method called when ``Elastic`` compatible output is desired."""
        return_dict = {}
        for k,v in values:
            dict_key = k.replace(".", "_")
            if dict_key in return_dict:
                old = return_dict.pop(dict_key)
                if isinstance(old, list):
                    new = [v] + old
                else:
                    new = [old, v]
                return_dict[dict_key] = new
            else:
                return_dict[dict_key] = v

        return dict(return_dict)


    @classmethod
    def _remove_ctrl_chars(cls, s):
        """Removes the Ctrl Characters from the string.
        """
        # FIXME: May be we should replace them with their unicode code points
        category_fn = unicodedata.category
        return "".join(ch for ch in s if category_fn(ch)[0] != "C")

    def __init__(self, *args, **kw):
        self._epan_dissector = None    #: Handle to Epan Dissector Object (``epan_dissect_t``).
        self._elapsed_time_ptr = None  #: Used for finding time relative to first frame
        self._ref_frame_data_ptr = None #: Reference Frame data pointer (points to first frame usually).
        self._first_frame_data = None #: First frame in the dissection
        self._last_frame_data = None  #: Previous frame in the dissection.
        self._provider = None         #: Dissection callback functions 'provider'.
        self._dfilter_obj_ptr = None  #: Handle to compiled filter object (``dfilter_t``).

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
    def dfilter_obj_ptr(self):
        return self._dfilter_obj_ptr

    @property
    def epan_session(self):
        if self._epan_dissector is None:
            return None

        return self._epan_dissector[0].session

    def init_epan_dissector(self):
        """Initializes ``epan_dissect_t`` and ``epan_session`` objects. These
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

        This method should be called as the last part of :func:`run` method.
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
        del self._dfilter_obj_ptr

        self._elapsed_time_ptr = None


    def run(self, *args, **kw):
        """A generator function ``yield`` ing at\-least the dissected packets.


        Implementing this as a generator function helps one to run code
        that looks like

        >>> for dissected in dissector.run(count=1):
            # do stuff with the dissected packet

        This is particularly convenient while performing live capture on
        an interface or dissecting a huge file.

        """
        raise NotImplemented("Derived Classes need to implement this.")

    def apply_filter(self, filter_str, overwrite=False):
        """
        Applies a filter given by the filter_str to the dissection.

        Args:
            filter_str: str - A string that is in a wireshark filter format.

        Returns:
            result: (int, str) - Result of application 0 success. Negative value
            suggesting error. Caller should check the error.

        Note: Right now it is recommended to run this method before `run` method
        is called on the dissector.

        """
        if self._dfilter_obj_ptr and not overwrite:
            return (-1, "Display Filter already set and 'overwrite' not set.")

        dfilter_obj_ptr = epan_ffi.new('dfilter_t **')
        err_str_ptr = epan_ffi.new('gchar **')
        result = epan_lib.dfilter_compile(
                filter_str.encode(),
                dfilter_obj_ptr,
                err_str_ptr)

        if not result:
            err_str = epan_ffi.string(err_str_ptr[0])
            return (-2, err_str.decode())

        old = None
        if self._dfilter_obj_ptr:
            old = self._dfilter_obj_ptr

        self._dfilter_obj_ptr = dfilter_obj_ptr[0]
        if old is not None:
            del old_dfilter_obj_ptr

        return (0, None)

    def clear_filter(self):
        """Clears the dfilter if any."""
        if self._dfilter_obj_ptr:
            o = self._dfilter_obj_ptr
            self._dfilter_obj_ptr = None
            del o


class WishpyDissectorFile(WishpyDissectorBase):
    """Dissector class for PCAP Files.
    """

    def __init__(self, filename):
        super().__init__()
        self.__filename = filename

    @property
    def filename(self):
        return self.__filename

    def run(self, count=0, skip=-1):
        """Actual function that performs the Dissection.

        Args:
            count (int, optional): The number of packets to run for.
            skip (int, optional): Skip the number of packets.

        Raises:
                :class:`WishpyErrorWthOpen`: If the handle cannot be opened.

        Right now since we are only supporting dissecting packets from Wiretap
        supported files, only dissects packets from a pcap(ish) file.
        """

        if not _EPAN_LIB_INITIALIZED:
            raise WishpyEpanLibUninitializedError(
                    "Epan Library Not initialized. Did you call setup_process()"
                    )

        self.init_epan_dissector()
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

        Calls the :func:`fetch` method to fetch a single packet and then performs dissection using
        the wrapped ``epan_perform_one_packet_dissection``.
        """
        hdr, data = self.fetch()

        if hdr == 'stop':
            self._stop_requested = True
            return hdr, data, None

        dltype = 1 # Default link type is Ethernet

        # FIXME: This might slowdown things but for now fine.
        if isinstance(hdr, PCAPHeader):
            newhdr = pcap_ffi.new('struct pcap_pkthdr *')
            newhdr[0].ts.tv_sec = hdr.ts_sec
            newhdr[0].ts.tv_usec = hdr.ts_usec
            newhdr[0].caplen = hdr.caplen
            newhdr[0].len = hdr.len

            dltype = self.libpcap_to_wtap_enctpyes[hdr.dltype]

            hdr = newhdr

            if isinstance(data, bytes):
                alloc_str = 'char [%d]' % hdr.caplen
                newdata = epan_ffi.new(alloc_str)
                epan_ffi.memmove(newdata, data, hdr.caplen)

                data = newdata

        d = epan_perform_one_packet_dissection(self,
                self._packets_fetched,
                hdr, data, dltype, self.packet_to_json)

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

    def __init__(self, queue, iface_name=None):
        """Constructor

        Args:
            queue: A python Queue like object

            iface\_name (str, optional): Name of the interface

        """
        super().__init__()

        self.__queue = queue
        self.__running = False
        self._stop_requested = False
        self._packets_fetched = 0
        self.__iface_name = iface_name


    @property
    def iface_name(self):
        if self.__iface_name is None:
            return "unknown"
        else:
            self.__iface_name

    def fetch(self):
        """Blocking Fetch from a Python Queue.

        Returns:
            (hdr, data): A tuple containing PCAP like header and packet data.
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
        """Runs the dissection function for the packets fetched from the queue.

        Args:
            count (int, optional): The number of packets to run dissector for.

        Yields:
            packet: A dissected json of the packet.

        if count is <= 0, infinite iterator. This iterator can be stopped by receiving
        an object of the form (stop, None) from the queue. So the write of the queue
        will have to ensure this. Or Call the `stop` method.

        """

        self.__running = True

        self.init_epan_dissector()

        fetched = 0
        while True:
            fetched += 1
            try:
                hdr, data, d = self.dissect_one_packet()

                if data and d is None:
                    # Packet was there, but filter rejected it
                    continue
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
    """Per process initialization.

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
    """Per process cleanup. de-init of epan/wtap modules.
    """

    global _EPAN_LIB_INITIALIZED

    if _EPAN_LIB_INITIALIZED:
        perform_epan_wtap_cleanup()
    else:
        _logger.warning("cleanup_process called without init process!")

    _EPAN_LIB_INITIALIZED = False
