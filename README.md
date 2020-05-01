Python Bindings for Wireshark and libpcap

- Uses CFFI to generate Python bindings for wireshark and libpcap
- You can write applications like `tshark` in Python
- Makes wireshark's dissectors available in Python and makes libpcap
  easily available in Python for packet capture

- Very very early still

# Getting Started

This packages right now is tested only on Linux (specifically Ubuntu 16.04)
that based laptop that I have. To be able to get started, following
development environment is required -

1. `gcc` and it's toolset
2. Python 3.5 or higher and Python development environment.

It is highly recommended to start with a virtual environment, something like
`virtualenv venv`

Typically simply doing a `python setup.py install` should be enough to get
you started. If everything goes well, one will have the modules installed
in the `site-packages`.

Once the packages are installed, you can run `python examples/tshark.py <pcap-filename>`

Alternatively, if you just want to use wrapped APIs, they are used in -
1. examples/tshark2.py (For wireshark 2.6)
2. examples/tshark3.py (For wireshark 3.2)

Unfortunately there's not much you can do besides running it against some pcaps
and see the json dump of the packets.

# Wireshark support

Right now both Wireshark 2.6.x and wireshark 3.2.x are supporte.

The best way to make sure this works is through `pkg-config`. If both versions
of the library are present, we'll try to install both bindings. Right now,
default support is for wireshark 2.6 that ships with Ubuntu.
If you have both the versions installed, it's a little bit tricky. If building
`wireshark` from source, If you perform a `make install` (or `sudo make install`),
the right `wireshark.pc` file is created and will be used during build.

# Directory structure

The directory structure of the code is as follows -

```
wishpy/
  wireshark/
    src/
      glib/
      wsutil/
      wireshark2/
        epan/
        wtap/
      wireshark3/
        epan/
        wtap/
      ...
    lib/
      ...
```
The `src` directory above is essentially, a source code for generating the
`lib` directory during run-time. In future, we'll have `sdist` only package
the sources and `bdist`/`install` to only populate the `lib` directory. For
now everything is packaged together.

Right now we have only 'wrapped extensions' available.
We have started with some very 'basic' Dissector API. See `examples/tshark.py` to see how it can be used.
This API is very early (in fact this is not really an API, but just a hint about what API might look like.)
and definitely is going to change.

