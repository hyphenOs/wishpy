# Driver for our wtap

from wireshark.wtap.wtap import wtap_ffi


if __name__ == '__main__':
    wtap_lib = wtap_ffi.verify('''
            #include <wireshark/config.h>
            #include <wireshark/wiretap/wtap.h>

        ''',
        libraries=['glib-2.0', 'wireshark', 'wsutil', 'wiretap'],
        extra_compile_args=['-I/usr/include/wireshark',
            '-I/usr/include/glib-2.0',
            '-I/usr/lib/x86_64-linux-gnu/glib-2.0/include'])

    print(dir(wtap_lib))
