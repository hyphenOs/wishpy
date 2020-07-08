"""
Our Dissector API.
"""
import socket
import struct
import json

from ._wrapper import *


class WishpyEpanLibUninitializedError(Exception):
    pass

class WishpyEpanLibAlreadyInitialized(Exception):
    pass

class WishpyErrorWthOpen(Exception):
    pass

_EPAN_LIB_INITIALIZED = False

class WishpyDissectorBase:
    """ A Class that wraps the underlying dissector from epan module of
    `libwireshark`. Right now this simply prints the dissector tree.
    """

    # Below are some dict's required for printing few packet types
    hfbases = {
            epan_lib.BASE_NONE : '{:d}', # Not sure how this is to be treated
            epan_lib.BASE_DEC : '{:d}',
            epan_lib.BASE_HEX : '0x{:x}',
            epan_lib.BASE_OCT : '{:o}',
            epan_lib.BASE_DEC_HEX: '{:d}(0x{:x})',
            epan_lib.BASE_HEX_DEC: '0x{:x}({:d})',
            epan_lib.BASE_PT_TCP: '{:d}',
            epan_lib.BASE_PT_UDP: '{:d}',
            epan_lib.BASE_PT_SCTP: '{:d}'

            }

    @classmethod
    def func_not_supported(cls, *args):
        return "Not Supported"

    @classmethod
    def epan_ether_to_str(cls, fvalue, ftype, display):
        """ Converting Ethernet addresses to String"""

        eth_bytes = fvalue.value.bytes

        display_bytes = []
        for i in range(eth_bytes.len):
            display_byte = "{:02X}".format(eth_bytes.data[i])
            display_bytes.append(display_byte)

        return ":".join(display_bytes)

    epan_bytes_to_str = epan_ether_to_str

    @classmethod
    def epan_str_to_str(cls, fvalue, ftype, display):
        """Converting epan 'char *' to Python String"""

        value = fvalue.value.string

        # If display is BASE_NONE, utf-8 is fine, but for others, not always! (GSM-Unicode)
        if display == 0:
            x = epan_ffi.string(value).decode("utf-8").\
                    replace('\\', '\\\\').\
                    replace('"', '\\"')
            return x
        else:
            try:
                x = epan_ffi.string(value).decode("utf-8").\
                        replace('\\', '\\\\').\
                        replace('"', '\\"')
            except:
                return "Cannot Decode"

    @classmethod
    def epan_ipv4_to_str(cls, fvalue, ftype, display):
        """Converting IP Address to Python String"""

        ipv4 = fvalue.value.ipv4

        return socket.inet_ntoa(struct.pack('!I', ipv4.addr))

    @classmethod
    def epan_bool_to_str(cls, fvalue, ftype, display, on_off=False, json_compat=True):
        """ Converting `gboolean` to String"""

        if on_off and json_compat:
            raise ValueError("Specify Either on_off or json_compat not both.")

        value = bool(fvalue.value.uinteger)

        if value:
            if json_compat:
                return "true"
            if on_off:
                return "ON"
        else:
            if json_compat:
                return "false"
            if on_off:
                return "OFF"

        return "{}".format(value)

    @classmethod
    def epan_int_to_str(cls, fvalue, ftype, display):
        """Converting Integer to String, using BASE_* property."""

        try:
            # We are not displaying 'Extended string for the value
            if display & epan_lib.BASE_EXT_STRING:
                display ^= epan_lib.BASE_EXT_STRING

            base_format = cls.hfbases[display]
        except:
            return "type: {} display: {} Not Supported".format(ftype, display)

        return base_format.format(fvalue.value.uinteger,
                fvalue.value.uinteger)

    @classmethod
    def value_to_str(cls, finfo):
        """
        Returns string representation of the `finfo.value`
        """

        fvalue = finfo.value
        ftype = finfo.hfinfo[0].type
        display = finfo.hfinfo[0].display

        epan_int_types = [
                epan_lib.FT_INT8,
                epan_lib.FT_INT16,
                epan_lib.FT_INT32,
                epan_lib.FT_INT40,
                epan_lib.FT_INT48,
                epan_lib.FT_INT56,
                epan_lib.FT_INT64]

        epan_uint32_types = [
                epan_lib.FT_CHAR,
                epan_lib.FT_UINT8,
                epan_lib.FT_UINT16,
                epan_lib.FT_UINT32,
                epan_lib.FT_FRAMENUM]

        epan_uint_types = epan_uint32_types + \
                [ epan_lib.FT_UINT40, epan_lib.FT_UINT48,
                epan_lib.FT_UINT56, epan_lib.FT_UINT64]

        epan_all_int_types = epan_int_types + epan_uint_types

        if ftype in epan_all_int_types:
            return cls.epan_int_to_str(fvalue, ftype, display)

        if ftype == epan_lib.FT_ETHER:
            return cls.epan_ether_to_str(fvalue, ftype, display)

        if ftype == epan_lib.FT_IPv4:
            return cls.epan_ipv4_to_str(fvalue, ftype, display)

        if ftype == epan_lib.FT_BOOLEAN:
            return cls.epan_bool_to_str(fvalue, ftype, display)

        if ftype == epan_lib.FT_STRING:
            return cls.epan_str_to_str(fvalue, ftype, display)

        if ftype == epan_lib.FT_BYTES:
            return cls.epan_bytes_to_str(fvalue, ftype, display)

        if ftype in [epan_lib.FT_NONE, epan_lib.FT_PROTOCOL]:
            return "null"

        return "{} {}".format(ftype, display)

    @classmethod
    def print_dissected_tree(cls, node_ptr, data_ptr):
        """
        Returns a string that represents a dissected tree."""

        return_str = ""

        if data_ptr == epan_ffi.NULL:
            level = 1
        else:
            level = epan_ffi.cast('int *', data_ptr)[0]

        return_str = ""
        node = node_ptr[0]
        finfo = node.finfo
        if finfo != epan_ffi.NULL:

            hfinfo = finfo.hfinfo[0]
            abbrev = epan_ffi.string(hfinfo.abbrev).decode()
            abbrev_str = "\"{!s}\"".format(abbrev)
            return_str += abbrev_str + ": "
            finfo_display_str = cls.value_to_str(finfo)
            if finfo_display_str:
                finfo_display_str = "\"{!s}\"".format(finfo_display_str)
            else:
                finfo_display_str = "\"\""
        else:
            finfo_display_str = ""

        return_str += finfo_display_str

        data_ptr_new = epan_ffi.new('int *')
        data_ptr_new[0] = level + 1
        child = node.first_child
        if child != epan_ffi.NULL:

            if finfo_display_str:
                return_str += ",\n"

                abbrev_tree = abbrev + "_tree"
                abbrev_tree_str = "\"{!s}\"".format(abbrev_tree)
                return_str += "  " * (level -1)
                return_str += abbrev_tree_str + " : "

            return_str += "{ "
            return_str += "\n"
            while child != epan_ffi.NULL:
                return_str += "  " * level
                return_str += cls.print_dissected_tree(child, data_ptr_new)
                child = child.next
            return_str += "  " * level

            return_str += "\n"
            return_str += "  " * (level-1)
            return_str += "}"
        if node.next != epan_ffi.NULL:
            return_str += ",\n"

        return return_str

    @classmethod
    def packet_to_json(cls, handle_ptr):
        """ An example method that depicts how to use internal dissector API."""

        dissector = handle_ptr[0]

        # FIXME: following should be like json dumps
        json.loads(cls.print_dissected_tree(dissector.tree, epan_ffi.NULL))
        s = cls.print_dissected_tree(dissector.tree, epan_ffi.NULL)
        try:
            x = json.loads(s, strict=False)
        except Exception as e:
            print(s)
            print((e.doc, e.msg))
            raise

    def run(self, *args, **kw):
        raise NotImplemented("Derived Classes need to implement this.")

class WishpyDissectorFile(WishpyDissectorBase):
    """Dissector class for PCAP Files.
    """

    def __init__(self, filename):
        self.__filename = filename

    def run(self, count=0):
        """
        Actual function that performs the Dissection. Right now since we are
        only supporting dissecting packets from Wiretap supported files,
        only dissects packets from a pcap(ish) file.
        """

        if not _EPAN_LIB_INITIALIZED:
            raise WishpyEpanLibUninitializedError(
                    "Epan Library Not initialized. Did you call setup_process()"
                    )
        # FIXME: dissector.run can be run only once right now
        # FIXME: Pass errno / errstr ourselves to get the error to be passed
        # to the Exception handler

        # FIXME: Do this as a context manager
        print ("before wtap_open_file_offline")
        wth, wth_filetype = wtap_open_file_offline(self.__filename)
        if wth is None:
            raise WishpyErrorWthOpen()


        processed = epan_perform_dissection(wth, wth_filetype,
                self.packet_to_json, count)

        wtap_close(wth)

        return processed

class WishpyDissectorQueue(WishpyDissectorBase):
    """Dissector class for packets received from a Queue(ish) object.
    """

    def fetch(self):
        """Implement this function to fetch a single packet from the queue.

        Implementation of this function should return the object of the type
        `Hdr` and PacketData`
        """
        raise NotImplemented("Derived Classes Need to implement this.")



class WishpyDissectorQueuePython(WishpyDissectorQueue):

    def __init__(self, queue):
        self.__queue = queue

    def fetch(self):
        """Blocking Fetch from a Python Queue.
        """
        hdr, data = self.__queue.get()
        return hdr, data

    def __iter__(self):
        return self

    def __next__(self):
        """Returns next `fetch`ed packet. (Blocking)
        """
        # TODO : perform actual dissection
        return self.fetch()

    def run(self, count=0):
        """yield's the packet, up to maximum of `count` packets.

        if count is <= 0, infinite iterator.
        """

        fetched = 0
        while True:
            hdr, data = self.__next__()

            fetched += 1
            x = yield (hdr, data)

            if x and x.lower() == 'stop':
                return

            if fetched == count:
                return


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


__all__ = ['WishpyDissectorFile']
