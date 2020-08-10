
def _fake_func(*args, **kw):
    pass

def _fake_wrapper(*args, **kw):

    def wrapped(*a, **k):
        pass

    return wrapped

class ffi:
    new = _fake_func
    callback = _fake_wrapper
    NULL = None
    string = _fake_func
    addressof = _fake_func

class lib:
    wtap_close = None
    epan_cleanup = None

    BASE_NONE = 0
    BASE_DEC = 0
    BASE_HEX = 0
    BASE_OCT = 0
    BASE_DEC_HEX = 0
    BASE_HEX_DEC = 0
    BASE_PT_TCP = 0
    BASE_PT_UDP = 0
    BASE_PT_SCTP = 0
    BASE_OUI = 0

    BASE_RANGE_STRING = 0
    BASE_EXT_STRING = 0
    BASE_VAL64_STRING = 0
    BASE_ALLOW_ZERO = 0
    BASE_UNIT_STRING = 0
    BASE_NO_DISPLAY_VALUE = 0
    BASE_PROTOCOL_INFO = 0
    BASE_SPECIAL_VALS = 0
    BASE_CUSTOM = 0

    FT_ETHER = 0
    FT_IPv4 = 0
    FT_BOOLEAN = 0
    FT_STRING = 0
    FT_BYTES = 0
    FT_RELATIVE_TIME = 0
    FT_ABSOLUTE_TIME = 0
    FT_NONE = 0
    FT_PROTOCOL = 0

    FT_INT8 = 0
    FT_INT16 = 0
    FT_INT24 = 0
    FT_INT32 = 0
    FT_INT40 = 0
    FT_INT48 = 0
    FT_INT56 = 0
    FT_INT64 = 0
    FT_CHAR = 0
    FT_UINT8 = 0
    FT_UINT16 = 0
    FT_UINT24 = 0
    FT_UINT32 = 0
    FT_UINT40 = 0
    FT_UINT48 = 0
    FT_UINT56 = 0
    FT_UINT64 = 0
    FT_FRAMENUM = 0

    FT_FLOAT = 0
    FT_DOUBLE = 0

    FTREPR_DISPLAY = 0

    fvalue_to_string_repr = _fake_func
    wmem_free = _fake_func
