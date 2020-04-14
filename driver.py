# Driver for our wtap


from wireshark.wtap.wtap import wtap_ffi
from wireshark.epan.epan import epan_ffi

if __name__ == '__main__':
    wtap_lib = wtap_ffi.verify('''
            #include <wireshark/config.h>
            #include <wireshark/wiretap/wtap.h>

        ''',
        libraries=['glib-2.0', 'wireshark', 'wsutil', 'wiretap'],
        extra_compile_args=['-g', '-I/usr/local/include/wireshark',
            '-I/usr/include/glib-2.0',
            '-I/usr/lib/x86_64-linux-gnu/glib-2.0/include',
            '-L/usr/local/lib'])

    print(dir(wtap_lib))
    epan_lib = epan_ffi.verify('''
            #include <wireshark/config.h>
            #include <wireshark/epan/epan.h>

        ''',
        libraries=['glib-2.0', 'wireshark', 'wsutil'],
        extra_compile_args=['-g', '-I/usr/local/include/wireshark',
            '-I/usr/include/glib-2.0',
            '-I/usr/lib/x86_64-linux-gnu/glib-2.0/include',
            '-L/usr/local/lib'])

    print(dir(epan_lib))
