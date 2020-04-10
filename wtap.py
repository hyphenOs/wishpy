from cffi import FFI
from glib import glib_cdef
from garray_h import garray_h_cdef
from glist_h import glist_h_cdef
from nstime_h import nstime_h_cdef
from wtap_h import wtap_h_cdef
from wtap_opttypes_h import wtap_opttypes_h_cdef

from wsutil_buffer_h import wsutil_buffer_h_cdef
from wsutil_inet_ipv6_h import wsutil_inet_ipv6_h_cdef

# from ws_symbols_h import ws_symbols_h_cdef

wtap_ffi = FFI()

# Get the definitions from glib
wtap_ffi.cdef(glib_cdef)
wtap_ffi.cdef(garray_h_cdef)
wtap_ffi.cdef(glist_h_cdef)

wtap_ffi.cdef(nstime_h_cdef)

wtap_ffi.cdef(wsutil_buffer_h_cdef)
wtap_ffi.cdef(wsutil_inet_ipv6_h_cdef)
wtap_ffi.cdef(wtap_opttypes_h_cdef)

# Get the definitions from our on library
wtap_ffi.cdef(wtap_h_cdef)


if __name__ == '__main__':
    wtap_lib = wtap_ffi.verify('''
            #include <wireshark/wiretap/wtap.h>

        ''',
        libraries=['glib-2.0', 'wireshark', 'wsutil'],
        extra_compile_args=['-I/usr/include/wireshark',
            '-I/usr/include/glib-2.0',
            '-I/usr/lib/x86_64-linux-gnu/glib-2.0/include'])

