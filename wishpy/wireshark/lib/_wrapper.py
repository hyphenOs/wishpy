"""
wrapper library to actual wireshark bindings. Should not be used directly.

As support for more 'wireshark' features gets added, the support will be added
in the _wrapper and other APIs (like WishpyDissector) will make use of that
support. This abstracts out Wireshark 2.6 and Wireshark 3.2 specific
API calls.
"""

import os
import binascii
import warnings
import logging

try:
    from .epan2_ext import lib as epan_lib
    from .epan2_ext import ffi as epan_ffi
    _epan_version = (2, 6)
except ImportError:
    try:
        from .epan3_ext import lib as epan_lib
        from .epan3_ext import ffi as epan_ffi
        _epan_version = (3, 2)
    except ImportError:
        warnings.warn("Epan Library Extensions Not Found.")
        raise EpanLoadError

_logger = logging.getLogger(__name__)

class EpanLoadError(Exception):
    pass

_nstime_empty = epan_ffi.new('nstime_t *');
@epan_ffi.callback('const nstime_t *(*)(struct packet_provider_data *prov, guint32 frame_num)')
def _wishpy_get_ts(prov, frame_num):

    if prov[0].ref[0].num == frame_num:
        return epan_ffi.addressof(prov[0].ref[0], 'abs_ts')

    if prov[0].prev[0].num == frame_num:
        return epan_ffi.addressof(prov[0].prev[0], 'abs_ts')

    return _nstime_empty


def _epan_init_v2():

    epan_lib.init_process_policies()
    null_register_cb = epan_ffi.cast('register_cb', epan_ffi.NULL)
    register_protocols_handle = epan_ffi.callback('void (*)(register_cb, gpointer)',
            epan_lib.register_all_protocols)
    register_handoffs_handle = epan_ffi.callback('void (*)(register_cb, gpointer)',
            epan_lib.register_all_protocol_handoffs)
    result = epan_lib.epan_init(
            register_protocols_handle,
            register_handoffs_handle,
            null_register_cb, epan_ffi.NULL)
    if result:
        epan_lib.epan_load_settings()

    return result

def _epan_init_v3():
    """
    Performs initialzation of the `epan` library. Calls
    1. `init_process_policies` (Required)
    2. `epan_init` (Required)
    3. `epan_load_settings` (Required)

    Returns True/False based upon result of operation.
    """

    epan_lib.init_process_policies()
    null_register_cb = epan_ffi.cast('register_cb', epan_ffi.NULL)
    result = epan_lib.epan_init(
            null_register_cb, epan_ffi.NULL, True)
    if result:
        epan_lib.epan_load_settings()

    return result

def _epan_perform_one_packet_dissection_v2(wishpy_dissector, frames, hdr, packet_data, cb_func):
    """Performs dissection of a single packet using v2.6
    """

    # FIXME : hardcoded
    wth_file_type = 1
    total_bytes = 0

    epan_session = wishpy_dissector.epan_session
    epan_dissect_obj = wishpy_dissector.epan_dissector
    elapsed_time_ptr = wishpy_dissector.elapsed_time_ptr
    ref_frame_data_ptr = wishpy_dissector.ref_frame_data_ptr
    last_frame_data = wishpy_dissector.last_frame_data

    if ref_frame_data_ptr[0] == epan_ffi.NULL:
        curr_frame_data = wishpy_dissector.first_frame_data
    else:
        curr_frame_data = epan_ffi.new('frame_data *')

    # Read stuff from `hdr` for us
    # TODO: Timestamps
    packet_len = hdr[0].len
    packet_capture_len = hdr[0].caplen

    # Allocate enough space to 'copy'
    count = packet_capture_len
    if packet_capture_len > 1024:
        count = 4096
    if packet_capture_len > 4096:
        _logger.debug("Big Packet: Length: %d", packet_capture_len)
        count = 16384
    if packet_capture_len > 16384:
        _logger.debug("Huge Packet: Length: %d", packet_capture_len)
        count = 65536
    alloc_str = 'guint8[{:d}]'.format(count)

    buf_ptr = epan_ffi.new(alloc_str)
    # Copy from the data `pakcet_data` to us
    epan_ffi.memmove(buf_ptr, packet_data, packet_capture_len)

    offset = epan_ffi.new('gint64 *')
    cum_bytes = epan_ffi.new('guint32 *')

    # Go ahead fill-up the `rec`
    rec = epan_ffi.new('wtap_rec *')
    epan_lib.wtap_rec_init(rec)
    rec[0].rec_header.packet_header.len = packet_len
    rec[0].rec_header.packet_header.caplen = packet_capture_len
    rec[0].rec_header.packet_header.pkt_encap = 1 # FIXME: Hard coded
    rec[0].ts.secs = hdr[0].ts.tv_sec
    rec[0].ts.nsecs = hdr[0].ts.tv_usec * 1000 # Asumes usec precision FIXME
    rec[0].presence_flags = epan_lib.WTAP_HAS_TS | epan_lib.WTAP_HAS_CAP_LEN

    epan_lib.frame_data_init(curr_frame_data, frames, rec,
            offset[0], cum_bytes[0])

    epan_lib.frame_data_set_before_dissect(curr_frame_data,
            elapsed_time_ptr, ref_frame_data_ptr, last_frame_data)

    # Not sure what this is - Just copied from `tshark` sources
    epan_lib.prime_epan_dissect_with_postdissector_wanted_hfids(epan_dissect_obj)

    ## Do actual dissection here.
    # Get buffer and tvbuff first and then run dissector
    tvb_ptr = epan_lib.tvb_new_real_data(buf_ptr, packet_len, packet_capture_len)
    epan_lib.epan_dissect_run(epan_dissect_obj, wth_file_type, rec,
            tvb_ptr, curr_frame_data, epan_ffi.NULL)

    dissected = cb_func(epan_dissect_obj)

    # Get into last data - useful for relative analysis
    epan_ffi.memmove(last_frame_data,
            curr_frame_data, epan_ffi.sizeof('frame_data'))

    # Reset the frame data and dissector object
    epan_lib.frame_data_set_after_dissect(curr_frame_data, cum_bytes)
    epan_lib.epan_dissect_reset(epan_dissect_obj)

    return dissected

def _epan_perform_dissection_v2(wishpy_dissector, wth, wth_file_type, cb_func, count=0, skip=-1):
    """
    Performs dissection of the file bound to `wth`
    """

    epan_session = wishpy_dissector.epan_session
    epan_dissect_obj = wishpy_dissector.epan_dissector
    elapsed_time_ptr = wishpy_dissector.elapsed_time_ptr
    ref_frame_data_ptr = wishpy_dissector.ref_frame_data_ptr
    last_frame_data = wishpy_dissector.last_frame_data

    offset = epan_ffi.new('gint64 *')

    err = epan_ffi.new('int *')
    err_str = epan_ffi.new("gchar **")

    cum_bytes = epan_ffi.new('guint32 *')
    processed = 1
    skipped = 0
    total_bytes = 0
    while True:

        if ref_frame_data_ptr[0] == epan_ffi.NULL:
            curr_frame_data = wishpy_dissector.first_frame_data
        else:
            curr_frame_data = epan_ffi.new('frame_data *')

        result = epan_lib.wtap_read(wth, err, err_str, offset)

        if result == True:

            rec = epan_lib.wtap_get_rec(wth)
            buf_ptr = epan_lib.wtap_get_buf_ptr(wth)

            pkt_len = rec.rec_header.packet_header.len
            pkt_reported_len = rec.rec_header.packet_header.caplen

            epan_lib.frame_data_init(curr_frame_data, processed, rec,
                    offset[0], cum_bytes[0])

            total_bytes += pkt_reported_len
            cum_bytes[0] = total_bytes

            # FIXME: Look at properly using `frame_data_ref`
            epan_lib.frame_data_set_before_dissect(curr_frame_data,
                    elapsed_time_ptr, ref_frame_data_ptr, last_frame_data)

            # Not sure what this is - Just copied from `tshark` sources
            epan_lib.prime_epan_dissect_with_postdissector_wanted_hfids(
                    epan_dissect_obj)

            ## Do actual dissection here.
            # Get buffer and tvbuff first and then run dissector
            tvb_ptr = epan_lib.tvb_new_real_data(buf_ptr, pkt_len,
                    pkt_reported_len)

            epan_lib.epan_dissect_run(epan_dissect_obj, wth_file_type,
                    rec, tvb_ptr, curr_frame_data, epan_ffi.NULL)

            if skipped < skip:
                skipped += 1
                continue

            dissected = cb_func(epan_dissect_obj)

            # Get into last data - useful for relative analysis
            epan_ffi.memmove(last_frame_data,
                curr_frame_data, epan_ffi.sizeof('frame_data'))

            # Reset the frame data and dissector object
            epan_lib.frame_data_set_after_dissect(curr_frame_data, cum_bytes)
            epan_lib.epan_dissect_reset(epan_dissect_obj)

            processed += 1

            yield dissected

            if processed == count + 1:
                break

        else:
            break

def _epan_perform_one_packet_dissection_v3(wishpy_dissector, frames, hdr, packet_data, cb_func):
    """Performs a single packet dissection.
    """

    # FIXME : hardcoded
    wth_file_type = 1
    total_bytes = 0

    epan_session = wishpy_dissector.epan_session
    epan_dissect_obj = wishpy_dissector.epan_dissector
    elapsed_time_ptr = wishpy_dissector.elapsed_time_ptr
    ref_frame_data_ptr = wishpy_dissector.ref_frame_data_ptr
    last_frame_data = wishpy_dissector.last_frame_data

    if ref_frame_data_ptr[0] == epan_ffi.NULL:
        curr_frame_data = wishpy_dissector.first_frame_data
    else:
        curr_frame_data = epan_ffi.new('frame_data *')
    # Read stuff from `hdr` for us
    packet_len = hdr[0].len
    packet_capture_len = hdr[0].caplen

    # Allocate enough space to 'copy'
    count = packet_capture_len
    if packet_capture_len > 1024:
        count = 4096
    if packet_capture_len > 4096:
        _logger.debug("Big Packet: Length: %d", packet_capture_len)
        count = 16384
    if packet_capture_len > 16384:
        _logger.debug("Huge Packet: Length: %d", packet_capture_len)
        count = 65536
    count = packet_capture_len

    # Copy from the data `packet_data` to us
    # We've to oblige to `wireshark` way of doing it hence the heavy lifting
    buf = epan_ffi.new('Buffer *')
    epan_lib.ws_buffer_init(buf, count)
    start_ptr = buf[0].data + buf[0].start
    epan_ffi.memmove(start_ptr, packet_data, packet_capture_len)


    rec = epan_ffi.new('wtap_rec *')
    epan_lib.wtap_rec_init(rec)
    rec[0].rec_header.packet_header.len = packet_len
    rec[0].rec_header.packet_header.caplen = packet_capture_len
    rec[0].rec_header.packet_header.pkt_encap = 1 # FIXME: Hard coded
    rec[0].ts.secs = hdr[0].ts.tv_sec
    rec[0].ts.nsecs = hdr[0].ts.tv_usec * 1000 # Asumes usec precision FIXME
    rec[0].presence_flags = epan_lib.WTAP_HAS_TS | epan_lib.WTAP_HAS_CAP_LEN

    offset = epan_ffi.new('gint64 *')
    cum_bytes = epan_ffi.new('guint32 *')
    epan_lib.frame_data_init(curr_frame_data, frames, rec, offset[0], cum_bytes[0])

    total_bytes += packet_capture_len
    cum_bytes[0] = total_bytes

    epan_lib.frame_data_set_before_dissect(curr_frame_data,
            elapsed_time_ptr, ref_frame_data_ptr, last_frame_data)

    # Not sure what this is - Just copied from `tshark` sources
    epan_lib.prime_epan_dissect_with_postdissector_wanted_hfids(
            epan_dissect_obj)

    ## Ready to do `dissection` here.
    # Get buffer and tvbuff first and then run dissector
    tvb_ptr = epan_lib.tvb_new_real_data(buf[0].data, packet_len,
            packet_capture_len)

    epan_lib.epan_dissect_run(epan_dissect_obj, wth_file_type,
            rec, tvb_ptr, curr_frame_data, epan_ffi.NULL)

    dissected = cb_func(epan_dissect_obj)

    # Get into last data - useful for relative analysis
    epan_ffi.memmove(last_frame_data,
            curr_frame_data, epan_ffi.sizeof('frame_data'))
    # Reset the frame data and dissector object
    epan_lib.frame_data_set_after_dissect(curr_frame_data, cum_bytes)
    epan_lib.epan_dissect_reset(epan_dissect_obj)

    return dissected


def _epan_perform_dissection_v3(wishpy_dissector, wth, wth_file_type, cb_func, count=0, skip=-1):
    """
    Performs dissection of the file bound to `wth`. If Non-zero positive count
    is specified, performs dissection of up to `count` packets
    """

    epan_session = wishpy_dissector.epan_session
    epan_dissect_obj = wishpy_dissector.epan_dissector
    elapsed_time_ptr = wishpy_dissector.elapsed_time_ptr
    ref_frame_data_ptr = wishpy_dissector.ref_frame_data_ptr
    last_frame_data = wishpy_dissector.last_frame_data

    offset = epan_ffi.new('gint64 *')

    buf = epan_ffi.new('Buffer *')
    epan_lib.ws_buffer_init(buf, 1514) # FIXME : Should do with proper length
    rec = epan_ffi.new('wtap_rec *')
    epan_lib.wtap_rec_init(rec)
    err = epan_ffi.new('int *')
    err_str = epan_ffi.new("gchar **")

    cum_bytes = epan_ffi.new('guint32 *')
    processed = 1
    total_bytes = 0
    skipped = 0
    while True:

        if ref_frame_data_ptr[0] == epan_ffi.NULL:
            curr_frame_data = wishpy_dissector.first_frame_data
        else:
            curr_frame_data = epan_ffi.new('frame_data *')

        result = epan_lib.wtap_read(wth, rec, buf, err, err_str, offset)

        if result == True:

            pkt_len = rec[0].rec_header.packet_header.len
            pkt_reported_len = rec[0].rec_header.packet_header.caplen

            epan_lib.frame_data_init(curr_frame_data, processed, rec,
                    offset[0], cum_bytes[0])

            total_bytes += pkt_reported_len
            cum_bytes[0] = total_bytes

            epan_lib.frame_data_set_before_dissect(curr_frame_data,
                    elapsed_time_ptr, ref_frame_data_ptr, last_frame_data)

            # Not sure what this is - Just copied from `tshark` sources
            epan_lib.prime_epan_dissect_with_postdissector_wanted_hfids(
                    epan_dissect_obj)

            ## Do actual dissection here.
            # Get buffer and tvbuff first and then run dissector
            tvb_ptr = epan_lib.tvb_new_real_data(buf[0].data, pkt_len,
                    pkt_reported_len)

            epan_lib.epan_dissect_run(epan_dissect_obj, wth_file_type,
                    rec, tvb_ptr, curr_frame_data, epan_ffi.NULL)

            if skipped < skip:
                skipped += 1
                continue

            dissected = cb_func(epan_dissect_obj)

            # Get into last data - useful for relative analysis
            epan_ffi.memmove(last_frame_data,
                    curr_frame_data, epan_ffi.sizeof('frame_data'))

            # Reset the frame data and dissector object
            epan_lib.frame_data_set_after_dissect(curr_frame_data, cum_bytes)
            epan_lib.epan_dissect_reset(epan_dissect_obj)

            processed += 1

            yield dissected

            if processed == count + 1:
                break

        else:
            break

    return processed

def wtap_open_file_offline(filepath):
    """
    Opens a file given by filepath  using `wtap_open_offline` and returns a tuple containing
    Handle and file type.
    """

    if filepath is None:
        _logger.error("File Path None.")
        return None, None

    if not os.path.exists(filepath):
        _logger.error("File not found: %s", filepath)
        return None, None

    # Open a wtap file
    err = epan_ffi.new('int *')
    err_str = epan_ffi.new("gchar *[256]")
    filename = filepath
    open_type = epan_lib.WTAP_TYPE_AUTO
    c_filename = epan_ffi.new('const char []', filename.encode())
    wth = epan_lib.wtap_open_offline(c_filename, open_type, err, err_str, False)
    if wth == epan_ffi.NULL:
        if err_str[0] != epan_ffi.NULL:
            err_display_str = epan_ffi.string(err_str[0]).decode()
        else:
            err_display_str = "Unknown Error"
        _logger.error("Error creating wiretap handle: %s (%d)", err_display_str, err[0])
        return None, None

    wtap_file_type = epan_lib.wtap_file_type_subtype(wth)
    return wth, wtap_file_type

wtap_close = epan_lib.wtap_close
epan_cleanup = epan_lib.epan_cleanup

_wishpy_provider_funcs = epan_ffi.new('struct packet_provider_funcs *',
        [_wishpy_get_ts, epan_ffi.NULL, epan_ffi.NULL, epan_ffi.NULL])


def epan_new_session(provider=epan_ffi.NULL):
    """Get new `epan_session`

    Calls the wrapped `epan_new` and returns the handler.
    """
    return epan_lib.epan_new(provider, _wishpy_provider_funcs)

def epan_free_session(session):
    """Calls `epan_free` on the given `session` object.
    """
    epan_lib.epan_free(session)

def epan_new_dissector(session):
    """Get new `epan_dissect_t`

    Calls the wrapped `epan_dissect_new` and returns the handler.
    Params:
        session: `epan_session` object returned by `epan_new_session`(ish).
    """
    return epan_lib.epan_dissect_new(session, True, True)

def epan_free_dissector(epan_dissector_obj):
    """Calls internal `epan_dissect_free` on the `epan_dissector_obj`
    """
    epan_lib.epan_dissect_free(epan_dissector_obj)

if _epan_version == (2,6):
    epan_lib_init = _epan_init_v2
    epan_perform_dissection = _epan_perform_dissection_v2
    epan_perform_one_packet_dissection = _epan_perform_one_packet_dissection_v2
else:
    epan_lib_init = _epan_init_v3
    epan_perform_dissection = _epan_perform_dissection_v3
    epan_perform_one_packet_dissection = _epan_perform_one_packet_dissection_v3

def perform_epan_wtap_init():

    _logger.info("Found Wireshark Epan Version %d.%d", _epan_version[0], _epan_version[1])

    # FIXME: True / False to be decided
    epan_lib.wtap_init(False)

    return epan_lib_init()

def perform_epan_wtap_cleanup():

    epan_lib.epan_cleanup()
    epan_lib.wtap_cleanup()
