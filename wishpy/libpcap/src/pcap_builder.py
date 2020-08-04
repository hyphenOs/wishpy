from wishpy.libpcap.src.pcap import (
        libpcap_ffi,
        _sources,
        _extra_link_args,
        _extra_compile_args)



if __name__ == '__main__':

    libpcap_lib = libpcap_ffi.verify(_sources,
            extra_link_args=_extra_link_args,
            extra_compile_args=_extra_compile_args)

    print(libpcap_lib)
    print(dir(libpcap_lib))
