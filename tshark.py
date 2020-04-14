import sys
import time
from datetime import datetime as dt

from wireshark.wtap.wtap import wtap_ffi, wtap_lib
from wireshark.epan.epan import epan_ffi, epan_lib

wtap_lib.wtap_init(False)

# Open a wtap file
err = wtap_ffi.new('int *')
err_str = wtap_ffi.new("gchar *[256]")
filename = "/home/gabhijit/Work/MatrixShell/April-10_00001_20180410194045.pcap" #"port8080.pcap"
open_type = wtap_lib.WTAP_TYPE_AUTO
open_random = wtap_ffi.cast("gboolean", False)
wth = wtap_lib.wtap_open_offline(filename.encode(), open_type, err, err_str, open_random)
wtap_file_type = wtap_lib.wtap_file_type_subtype(wth)

# Open `epan_lib`
epan_lib.init_process_policies()
null_register_cb = epan_ffi.cast('register_cb', epan_ffi.NULL)
register_protocols_handle = epan_ffi.callback('void (*)(register_cb, gpointer)', epan_lib.register_all_protocols)
register_handoffs_handle = epan_ffi.callback('void (*)(register_cb, gpointer)', epan_lib.register_all_protocol_handoffs)
epan_init_result = epan_lib.epan_init(
        register_protocols_handle,
        register_handoffs_handle,
        null_register_cb, epan_ffi.NULL)
epan_lib.epan_load_settings()

empty_packet_provider_funcs = epan_ffi.new('struct packet_provider_funcs *')
epan_session = epan_lib.epan_new(epan_ffi.NULL, empty_packet_provider_funcs)
epan_dissect_obj = epan_lib.epan_dissect_new(epan_session, True, True)

offset = wtap_ffi.new('gint64 *')
frame_data_ref = epan_ffi.new('frame_data **')
elapsed_time_ptr = epan_ffi.new('nstime_t *')

frame_data_ref[0] = epan_ffi.NULL
frame_data_ptr = epan_ffi.new('frame_data *')
cum_bytes = epan_ffi.new('guint32 *')
then = dt.now()
while True:
    result = wtap_lib.wtap_read(wth, err, err_str, offset)

    if result == True:
        rec = wtap_lib.wtap_get_rec(wth)
        buf_ptr = wtap_lib.wtap_get_buf_ptr(wth)

        epan_rec = epan_ffi.cast('wtap_rec *', rec)
        #print(rec.rec_type, rec.rec_header.packet_header.len, rec.rec_header.packet_header.caplen)
        pkt_len = rec.rec_header.packet_header.len
        pkt_reported_len = rec.rec_header.packet_header.caplen


        epan_lib.frame_data_init(frame_data_ptr, 0, epan_rec, offset[0], cum_bytes[0])

        epan_lib.frame_data_set_before_dissect(frame_data_ptr, elapsed_time_ptr, frame_data_ref, epan_ffi.NULL)


        epan_lib.prime_epan_dissect_with_postdissector_wanted_hfids(epan_dissect_obj)
        ## Do actuaa dissection here.
        # Get buffer and tvbuff first and then run dissector
        tvb_ptr = epan_lib.tvb_new_real_data(buf_ptr, pkt_len, pkt_reported_len)
        epan_lib.epan_dissect_run(epan_dissect_obj, wtap_file_type, epan_rec, tvb_ptr, frame_data_ptr, epan_ffi.NULL)

        print(epan_dissect_obj.tree)

        epan_lib.frame_data_set_after_dissect(frame_data_ptr, cum_bytes)

        # epan_dissect_rest calls `tvb_free`, no need to call it ourselves
        epan_lib.epan_dissect_reset(epan_dissect_obj)

    else:
        break

now = dt.now()

print(now - then)
