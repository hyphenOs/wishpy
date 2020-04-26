from wishpy.wireshark.src.wireshark3.epan.epan import (
        epan_ffi,
        _sources,
        _libraries,
        _extra_compile_args,
        _extra_link_args)

if __name__ == '__main__':
    epan_lib = epan_ffi.verify(_sources,
            libraries=_libraries,
            extra_compile_args=_extra_compile_args,
            extra_link_args=_extra_link_args)

    print(epan_lib)
