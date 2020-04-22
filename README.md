Python Bindings for Wireshark

- Uses CFFI to generate Python bindings for wireshark
- You can write applications like `tshark` in Python
- Makes wireshark's dissectors available in Python

- Very early still

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
in the `site-packages`

and then one can run `python tshark.py <pcap-filename>` to see this in action.

# Directory structure

The directory structure of the code is as follows -

```
wishpy/
  wireshark/
    src/
      epan/
      wtap/
      wsutil/
      glib/
      ...
    lib/
      ...
```
The `src` directory above is essentially, a source code for generating the
`lib` directory during run-time. (In future, we'll have `sdist` only package
the sources and `bdist`/`install` to only populate the `lib` directory. For
now everything is packaged together.

Right now we have only 'wrapped extensions' available, eventually more Pythonic
API will be provided (That will be dependent upon the extension library)
