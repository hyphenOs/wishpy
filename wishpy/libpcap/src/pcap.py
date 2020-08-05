from cffi import FFI
from cffi import PkgConfigError


from .typedefs_h import libc_typedefs_h_cdef

from .bpf_h import libpcap_bpf_h_cdef
from .dlt_h import libpcap_dlt_h_cdef

from .pcap_h import (
        libpcap_pcap_h_all_cdef,
        libpcap_pcap_h_nowin_cdef,
        )

libpcap_ffi = FFI()

libpcap_ffi.cdef(libc_typedefs_h_cdef)
libpcap_ffi.cdef(libpcap_bpf_h_cdef)
libpcap_ffi.cdef(libpcap_dlt_h_cdef)

libpcap_ffi.cdef(libpcap_pcap_h_all_cdef)
libpcap_ffi.cdef(libpcap_pcap_h_nowin_cdef)

_pkg_name = 'wishpy.libpcap.lib.libpcap_ext'
_pkgconfig_libs = ['libpcap']

_sources = '''
    #include <pcap/pcap.h>
    '''

_extra_compile_args = ['-I/usr/local/include']
_extra_link_args = ['-L/usr/local/lib', '-lpcap']

try:
    libpcap_ffi.set_source_pkgconfig(_pkg_name, _pkgconfig_libs, _sources)
except PkgConfigError:
    libpcap_ffi.set_source(
            _pkg_name,
            _sources,
            extra_compile_args=_extra_compile_args,
            extra_link_args=_extra_link_args)

