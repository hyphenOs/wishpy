"""
wrapper library to actual wireshark bindings. Should not be used directly.

As support for more 'wireshark' features gets added, the support will be added
in the _wrapper and other APIs (like WishpyDissector) will make use of that
support. This abstracts out Wireshark 2.6 and Wireshark 3.2 specific
API calls.
"""

import os
import binascii

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

class EpanLoadError(Exception):
    pass

_nstime_empty = epan_ffi.new('nstime_t *');
@epan_ffi.callback('const nstime_t *(*)(struct packet_provider_data *prov, guint32 frame_num)')
def _wishpy_get_ts(prov, frame_num):
    return _nstime_empty


_wishpy_provider_funcs = epan_ffi.new('struct packet_provider_funcs *',
        [_wishpy_get_ts, epan_ffi.NULL, epan_ffi.NULL, epan_ffi.NULL])

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

def _epan_perform_one_packet_dissection_v2(epan_session, hdr, packet_data, cb_func):
    raise NotImplemented

def _epan_perform_dissection_v2(wth, wth_file_type, cb_func, count=0):
    """
    Performs dissection of the file bound to `wth`
    """
    #empty_packet_provider_funcs = epan_ffi.new('struct packet_provider_funcs *')
    epan_session = epan_lib.epan_new(epan_ffi.NULL, _wishpy_provider_funcs)

    # TODO: make proper `epan_session` for us
    epan_dissect_obj = epan_lib.epan_dissect_new(epan_session, True, True)

    offset = epan_ffi.new('gint64 *')
    frame_data_ref = epan_ffi.new('frame_data **')
    elapsed_time_ptr = epan_ffi.new('nstime_t *')

    err = epan_ffi.new('int *')
    err_str = epan_ffi.new("gchar **")

    frame_data_ref[0] = epan_ffi.NULL
    frame_data_ptr = epan_ffi.new('frame_data *')
    cum_bytes = epan_ffi.new('guint32 *')
    processed = 0
    total_bytes = 0
    while True:
        result = epan_lib.wtap_read(wth, err, err_str, offset)

        if result == True:
            processed += 1
            rec = epan_lib.wtap_get_rec(wth)
            buf_ptr = epan_lib.wtap_get_buf_ptr(wth)

            epan_rec = epan_ffi.cast('wtap_rec *', rec)
            pkt_len = rec.rec_header.packet_header.len
            pkt_reported_len = rec.rec_header.packet_header.caplen


            epan_lib.frame_data_init(frame_data_ptr, processed, epan_rec,
                    offset[0], cum_bytes[0])

            total_bytes += pkt_reported_len
            cum_bytes[0] = total_bytes
            # FIXME: Look at properly using `frame_data_ref`
            epan_lib.frame_data_set_before_dissect(frame_data_ptr,
                    elapsed_time_ptr, frame_data_ref, epan_ffi.NULL)

            # Not sure what this is - Just copied from `tshark` sources
            epan_lib.prime_epan_dissect_with_postdissector_wanted_hfids(
                    epan_dissect_obj)

            ## Do actual dissection here.
            # Get buffer and tvbuff first and then run dissector
            tvb_ptr = epan_lib.tvb_new_real_data(buf_ptr, pkt_len,
                    pkt_reported_len)

            epan_lib.epan_dissect_run(epan_dissect_obj, wth_file_type,
                    epan_rec, tvb_ptr, frame_data_ptr, epan_ffi.NULL)

            dissected = cb_func(epan_dissect_obj)

            # Reset the frame data and dissector object
            epan_lib.frame_data_set_after_dissect(frame_data_ptr, cum_bytes)
            epan_lib.epan_dissect_reset(epan_dissect_obj)

            processed += 1

            yield dissected

            if processed == count:
                break

        else:
            break

    epan_lib.epan_dissect_free(epan_dissect_obj)
    epan_lib.epan_free(epan_session)

def _epan_perform_one_packet_dissection_v3(hdr, packet_data, cb_func):
    """Performs a single packet dissection.
    """

    # FIXME : hardcoded
    wth_file_type = 1
    total_bytes = 0
    # FIXME: epan_session and epan_dissect_obj to be set by caller? So that
    # We don't free on every data.
    epan_session = epan_lib.epan_new(epan_ffi.NULL, _wishpy_provider_funcs)

    epan_dissect_obj = epan_lib.epan_dissect_new(epan_session, True, True)

    offset = epan_ffi.new('gint64 *')
    frame_data_ref = epan_ffi.new('frame_data **')
    elapsed_time_ptr = epan_ffi.new('nstime_t *')

    buf = epan_ffi.new('Buffer *')
    epan_lib.ws_buffer_init(buf, 1514) # FIXME : Should do with proper length
    start_ptr = buf[0].data + buf[0].start

    rec = epan_ffi.new('wtap_rec *')
    epan_lib.wtap_rec_init(rec)

    err = epan_ffi.new('int *')
    err_str = epan_ffi.new("gchar **")

    frame_data_ref[0] = epan_ffi.NULL
    frame_data_ptr = epan_ffi.new('frame_data *')
    cum_bytes = epan_ffi.new('guint32 *')

    packet_len = hdr[0].len
    packet_capture_len = hdr[0].caplen

    rec[0].rec_header.packet_header.len = packet_len
    rec[0].rec_header.packet_header.caplen = packet_capture_len
    rec[0].rec_header.packet_header.pkt_encap = 1 # FIXME: Hard coded

    epan_lib.frame_data_init(frame_data_ptr, 0, rec, offset[0], cum_bytes[0])

    total_bytes += packet_capture_len
    cum_bytes[0] = total_bytes

    # Copy from the data to us
    epan_ffi.memmove(start_ptr, packet_data, packet_capture_len)

    # FIXME: Look at properly using `frame_data_ref`
    epan_lib.frame_data_set_before_dissect(frame_data_ptr,
            elapsed_time_ptr, frame_data_ref, epan_ffi.NULL)

    # Not sure what this is - Just copied from `tshark` sources
    epan_lib.prime_epan_dissect_with_postdissector_wanted_hfids(
            epan_dissect_obj)

    ## Do actual dissection here.
    # Get buffer and tvbuff first and then run dissector
    tvb_ptr = epan_lib.tvb_new_real_data(buf[0].data, packet_len,
            packet_capture_len)

    epan_lib.epan_dissect_run(epan_dissect_obj, wth_file_type,
            rec, tvb_ptr, frame_data_ptr, epan_ffi.NULL)

    dissected = cb_func(epan_dissect_obj)

    # Reset the frame data and dissector object
    epan_lib.frame_data_set_after_dissect(frame_data_ptr, cum_bytes)
    epan_lib.epan_dissect_reset(epan_dissect_obj)

    epan_lib.epan_dissect_free(epan_dissect_obj)
    epan_lib.epan_free(epan_session)

    return dissected


def _epan_perform_dissection_v3(wth, wth_file_type, cb_func, count=0, skip=-1):
    """
    Performs dissection of the file bound to `wth`. If Non-zero positive count
    is specified, performs dissection of up to `count` packets
    """
    #empty_packet_provider_funcs = epan_ffi.new('struct packet_provider_funcs *')
    epan_session = epan_lib.epan_new(epan_ffi.NULL, _wishpy_provider_funcs)

    # TODO: make proper `epan_session` for us
    epan_dissect_obj = epan_lib.epan_dissect_new(epan_session, True, True)

    offset = epan_ffi.new('gint64 *')
    frame_data_ref = epan_ffi.new('frame_data **')
    elapsed_time_ptr = epan_ffi.new('nstime_t *')

    buf = epan_ffi.new('Buffer *')
    epan_lib.ws_buffer_init(buf, 1514) # FIXME : Should do with proper length
    rec = epan_ffi.new('wtap_rec *')
    epan_lib.wtap_rec_init(rec)
    err = epan_ffi.new('int *')
    err_str = epan_ffi.new("gchar **")

    frame_data_ref[0] = epan_ffi.NULL
    frame_data_ptr = epan_ffi.new('frame_data *')
    cum_bytes = epan_ffi.new('guint32 *')
    processed = 0
    total_bytes = 0
    skipped = 0
    while True:
        result = epan_lib.wtap_read(wth, rec, buf, err, err_str, offset)

        if result == True:

            pkt_len = rec[0].rec_header.packet_header.len
            pkt_reported_len = rec[0].rec_header.packet_header.caplen

            epan_lib.frame_data_init(frame_data_ptr, processed, rec,
                    offset[0], cum_bytes[0])

            total_bytes += pkt_reported_len
            cum_bytes[0] = total_bytes

            # FIXME: Look at properly using `frame_data_ref`
            epan_lib.frame_data_set_before_dissect(frame_data_ptr,
                    elapsed_time_ptr, frame_data_ref, epan_ffi.NULL)

            # Not sure what this is - Just copied from `tshark` sources
            epan_lib.prime_epan_dissect_with_postdissector_wanted_hfids(
                    epan_dissect_obj)

            ## Do actual dissection here.
            # Get buffer and tvbuff first and then run dissector
            tvb_ptr = epan_lib.tvb_new_real_data(buf[0].data, pkt_len,
                    pkt_reported_len)

            epan_lib.epan_dissect_run(epan_dissect_obj, wth_file_type,
                    rec, tvb_ptr, frame_data_ptr, epan_ffi.NULL)

            if skipped < skip:
                skipped += 1
                continue

            dissected = cb_func(epan_dissect_obj)

            # Reset the frame data and dissector object
            epan_lib.frame_data_set_after_dissect(frame_data_ptr, cum_bytes)
            epan_lib.epan_dissect_reset(epan_dissect_obj)

            processed += 1

            yield dissected

            if processed == count:
                break

        else:
            break

    epan_lib.epan_dissect_free(epan_dissect_obj)
    epan_lib.epan_free(epan_session)

    return processed

def wtap_open_file_offline(filepath):
    """
    Opens a file given by filepath  using `wtap_open_offline` and returns a tuple containing
    Handle and file type.
    """

    if not os.path.exists(filepath):
        return None, None

    # Open a wtap file
    err = epan_ffi.new('int *')
    err_str = epan_ffi.new("gchar *[256]")
    filename = filepath
    open_type = epan_lib.WTAP_TYPE_AUTO
    wth = epan_lib.wtap_open_offline(filename.encode(), open_type, err, err_str, False)
    if wth is epan_ffi.NULL:
        return None, None

    wtap_file_type = epan_lib.wtap_file_type_subtype(wth)
    return wth, wtap_file_type

wtap_close = epan_lib.wtap_close
epan_cleanup = epan_lib.epan_cleanup


if _epan_version == (2,6):
    epan_lib_init = _epan_init_v2
    epan_perform_dissection = _epan_perform_dissection_v2
    epan_perform_one_packet_dissection = _epan_perform_one_packet_dissection_v2
else:
    epan_lib_init = _epan_init_v3
    epan_perform_dissection = _epan_perform_dissection_v3
    epan_perform_one_packet_dissection = _epan_perform_one_packet_dissection_v3

def perform_epan_wtap_init():

    # FIXME: True / False to be decided
    epan_lib.wtap_init(False)

    return epan_lib_init()

def perform_epan_wtap_cleanup():

    epan_lib.epan_cleanup()
    epan_lib.wtap_cleanup()
