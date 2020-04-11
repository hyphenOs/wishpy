from cffi import FFI

epan_ffi = FFI()

from ..glib.glib_h import glib_h_cdef
from ..glib.garray_h import garray_h_cdef
from ..glib.glist_h import glist_h_cdef
from ..glib.gstring_h import glib_gstring_h_types_cdef

from ..wsutil.nstime_h import wsutil_nstime_h_cdef
from ..wsutil.buffer_h import wsutil_buffer_h_cdef
from ..wsutil.inet_ipv4_h import wsutil_inet_ipv4_h_cdef
from ..wsutil.inet_ipv6_h import wsutil_inet_ipv6_h_cdef
from ..wsutil.inet_addr_h import wsutil_inet_addr_h_cdef
from ..wsutil.plugins_h import wsutil_plugins_h_cdef
from ..wsutil.colors_h import wsutil_colors_h_cdef

from ..wtap.wtap_h import wtap_h_types_cdef
from ..wtap.wtap_opttypes_h import wtap_opttypes_h_types_cdef

from .epan_h import epan_h_cdef
from .register_h import epan_register_h_cdef
from .framedata_h import framedata_h_cdef
from .prefs_h import epan_prefs_h_cdef
from .params_h import epan_params_h_cdef
from .range_h import epan_range_h_types_cdef
from .tvbuff_h import epan_tvbuff_h_types_cdef

epan_ffi.cdef(glib_h_cdef)
epan_ffi.cdef(garray_h_cdef)
epan_ffi.cdef(glist_h_cdef)
epan_ffi.cdef(glib_gstring_h_types_cdef)

epan_ffi.cdef(wsutil_nstime_h_cdef)
epan_ffi.cdef(wsutil_buffer_h_cdef)
epan_ffi.cdef(wsutil_inet_ipv4_h_cdef)
epan_ffi.cdef(wsutil_inet_ipv6_h_cdef)
epan_ffi.cdef(wsutil_inet_addr_h_cdef)
epan_ffi.cdef(wsutil_plugins_h_cdef)
epan_ffi.cdef(wsutil_colors_h_cdef)

epan_ffi.cdef(wtap_opttypes_h_types_cdef)
epan_ffi.cdef(wtap_h_types_cdef)

epan_ffi.cdef(framedata_h_cdef)
epan_ffi.cdef(epan_register_h_cdef)
epan_ffi.cdef(epan_params_h_cdef)
epan_ffi.cdef(epan_range_h_types_cdef)
epan_ffi.cdef(epan_prefs_h_cdef)

epan_ffi.cdef(epan_tvbuff_h_types_cdef)
epan_ffi.cdef(epan_h_cdef)

