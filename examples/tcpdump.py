import sys
import time

MAX_COUNT = 100

from wishpy.libpcap.lib.libpcap_ext import lib as libpcap_lib
from wishpy.libpcap.lib.libpcap_ext import ffi as libpcap_ffi

pcap_version = libpcap_lib.pcap_lib_version()
print(libpcap_ffi.string(pcap_version))


@libpcap_ffi.callback('void (*)(u_char *, const struct pcap_pkthdr *, const u_char *)')
def wishpy_libpcap_handler(user, hdr, data):
    print(hdr[0].ts.tv_sec, hdr[0].ts.tv_usec, hdr[0].len, hdr[0].caplen)
    print(data)
    #print(user)

err_buffer = libpcap_ffi.new('char [256]')
print(err_buffer)

pcap_handle = libpcap_lib.pcap_create('wlp2s0'.encode(), err_buffer)

#error = libpcap_lib.pcap_set_promisc(pcap_handle, 1)

error = libpcap_lib.pcap_set_timeout(pcap_handle, 1)
if error != 0 :
    errstr = libpcap_lib.pcap_geterr(pcap_handle)
    print(libpcap_ffi.string(errstr))
    sys.exit(1)

error = libpcap_lib.pcap_activate(pcap_handle)
if error != 0 :
    errstr = libpcap_lib.pcap_geterr(pcap_handle)
    print(libpcap_ffi.string(errstr))
    sys.exit(1)

then = time.time()
result = libpcap_lib.pcap_loop( pcap_handle, MAX_COUNT,
        wishpy_libpcap_handler, libpcap_ffi.NULL)

print(result)
now = time.time()

print(now - then)

