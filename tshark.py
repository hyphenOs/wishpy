from wireshark.wtap.wtap import wtap_ffi, wtap_lib

err = wtap_ffi.new('int *')
err_str = wtap_ffi.new("gchar *[256]")
filename = "port8080.pcap"
open_type = wtap_lib.WTAP_TYPE_AUTO

open_random = wtap_ffi.cast("gboolean", False)

print(filename, open_type, err, err_str)

wtap_lib.wtap_init(False)

wth = wtap_lib.wtap_open_offline(filename.encode(), open_type, err, err_str, open_random)

print(wth)

offset = wtap_ffi.new('gint64 *')
while True:
    result = wtap_lib.wtap_read(wth, err, err_str, offset)

    if result == True:
        rec = wtap_lib.wtap_get_rec(wth)
        print(rec.rec_type, rec.rec_header.packet_header.len, rec.rec_header.packet_header.caplen)

    else:
        break


