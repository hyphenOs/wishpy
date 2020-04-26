# Driver for our wtap


from wishpy.wireshark.src.wireshark2.wtap.wtap import wtap_ffi as wtap2_ffi
from wishpy.wireshark.src.wireshark2.epan.epan import epan_ffi as epan2_ffi



if __name__ == '__main__':
    wtap2_lib = wtap2_ffi.verify('''
            #include <config.h>
            #include <wiretap/wtap.h>

        ''',
        libraries=['glib-2.0', 'wireshark', 'wsutil', 'wiretap'],
        extra_compile_args=[
            '-I/usr/include/glib-2.0',
            '-I/usr/lib/x86_64-linux-gnu/glib-2.0/include',
            '-I/usr/include/wireshark/',
            ],
        extra_link_args=[
            #'-L/usr/lib',
            #'-L/usr/local/lib'
            ])
    print(dir(wtap2_lib))

    epan_lib = epan2_ffi.verify('''
            #include <config.h>
            #include <epan/address.h>
            #include <epan/proto.h>
            #include <epan/epan_dissect.h>
            #include <epan/epan.h>
            #include <epan/packet.h>
            #include <wsutil/privileges.h>

        ''',
        libraries=['glib-2.0', 'wireshark', 'wsutil', 'wiretap'],
        extra_compile_args=[
            '-I/usr/include/glib-2.0',
            '-I/usr/lib/x86_64-linux-gnu/glib-2.0/include',
            '-I/usr/include/wireshark/',
            ],
        extra_link_args=[
            #'-L/usr/lib',
            #'-L/usr/local/lib'
            ])

    print(dir(epan_lib))
