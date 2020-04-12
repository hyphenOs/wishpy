from wireshark.wtap.wtap import wtap_ffi, wtap_lib
from wireshark.epan.epan import epan_ffi, epan_lib

wtap_lib.wtap_init(False)

# Open a wtap file
err = wtap_ffi.new('int *')
err_str = wtap_ffi.new("gchar *[256]")
filename = "port8080.pcap"
open_type = wtap_lib.WTAP_TYPE_AUTO
open_random = wtap_ffi.cast("gboolean", False)
wth = wtap_lib.wtap_open_offline(filename.encode(), open_type, err, err_str, open_random)

# Open `epan_lib`
epan_lib.init_process_policies()
null_register_cb = epan_ffi.cast('register_cb', epan_ffi.NULL)
register_protocols_handle = epan_ffi.callback('void (*)(register_cb, gpointer)', epan_lib.register_all_protocols)
register_handoffs_handle = epan_ffi.callback('void (*)(register_cb, gpointer)', epan_lib.register_all_protocol_handoffs)
epan_init_result = epan_lib.epan_init(
        register_protocols_handle,
        register_handoffs_handle,
        null_register_cb, epan_ffi.NULL)

empty_packet_provider_funcs = epan_ffi.new('struct packet_provider_funcs *')
epan_session = epan_lib.epan_new(epan_ffi.NULL, empty_packet_provider_funcs)
print(epan_session)
epan_dissect_obj = epan_lib.epan_dissect_new(epan_session, True, True)
print(epan_dissect_obj)

offset = wtap_ffi.new('gint64 *')
while True:
    result = wtap_lib.wtap_read(wth, err, err_str, offset)

    if result == True:
        rec = wtap_lib.wtap_get_rec(wth)
        print(rec.rec_type, rec.rec_header.packet_header.len, rec.rec_header.packet_header.caplen)

        ## Do actuaa dissection here.
        # Get buffer and tvbuff first and then run dissector

        epan_lib.epan_dissect_reset(epan_dissect_obj)

    else:
        break
