Python Bindings for ``Wireshark`` and ``libpcap``

.. image:: https://travis-ci.com/hyphenOs/wishpy.svg?branch-master
    :target: https://travis-ci.com/hyphenOs/wishpy
    :alt: Build Status
.. image:: https://readthedocs.org/projects/wishpy/badge/?version-latest
   :target: https://wishpy.readthedocs.io/en/latest/?badge-latest
   :alt: Documentation Status
.. image:: https://coveralls.io/repos/github/hyphenOs/wishpy/badge.svg?branch-master
    :target: https://coveralls.io/github/hyphenOs/wishpy?branch-master
    :alt: Coverage Status

What ``wishpy`` is?
-------------------

- Uses ``cffi`` to generate Python bindings for ``wireshark`` and ``libpcap``
- You can write applications like ``tshark`` in Python
- Makes wireshark's dissectors available in Python and makes ``libpcap``
  easily available in Python for packet capture
- This is in active development, but should work on common Linux distributions,
  if it doesn't please file an issue.
- Also,a drop-in replacement for `pcapy <https://github.com/helpsystems/pcapy>`_. Supports all the major ``pcapy`` APIs.
- Early Windows support. Please check `README-windows <https://github.com/hyphenOs/wishpy/blob/master/README-windows.rst>`_ .

Getting Started
---------------

This packages right now is tested only on Linux (specifically Ubuntu 16.04)
To be able to get started, following development environment is required -

1. ``gcc`` and it's toolset
2. Python 3.5 or higher and Python development environment.
3. Supports PyPy 7.3 or higher (compatible with Python 3.6)

It is highly recommended to start with a virtual environment, something like
``virtualenv venv``

Typically simply doing a ``python setup.py install`` should be enough to get
you started. If everything goes well, one will have the modules installed
in the ``site-packages``.

Once the packages are installed, you can run the example code -

Alternatively, if you just want to use wrapped APIs, they are used in -
1. ``wishpy/scripts/tcpdump.py <interface_name>`` (For live capturing the packets and dumping ``json``, **NOTE:** Requires ``sudo`` permissions.)
2. ``wishpy/scripts/tshark.py <pcap-file-path>`` (For dumping packets from a ``pcap``ish file as ``json``)

Wireshark support
-----------------

Right now both Wireshark 2.6.x and wireshark 3.2.x are supported.

The best way to make sure this works is through ``pkg-config``. Right now,
default support is for ``wireshark`` 2.6 that ships with Ubuntu.
If you have both the versions installed, it's a little bit tricky. If building
``wireshark`` from source, If you perform a ``make install`` (or ``sudo make install``),
the right ``wireshark.pc`` file is created and will be used during build.

``libpcap`` support
-------------------

`libpcap <https://tcpdump.org>`_ library \> 1.7 is supported. Also, there is a ``pcapy`` module, that can be used as a drop in replacement for `pcapy <https://github.com/helpsystems/pcapy>`_. Similar APIs as ``pcapy`` are supported. We have performed quick testing with following versions of ``libpcap`` on Ubuntu (based on git tag) - ``libpcap-1.7.4``, ``libpcap-1.8.1``, ``libpcap-1.9.1``.

Documentation
-------------

We have started with some very 'basic' Dissector/Capturer API. See ``wishpy/scripts/tshark.py`` to see how it can be used.
This API is very early (in fact this is not really an API, but just a hint about what API might look like.)
and very likely to change going forward. A very early version of the `API Documentation is available <https://wishpy.readthedocs.io/en/latest/api.html>`_.

Examples
--------

See the code in ``wishpy/scripts/`` directory for how to use wishpy API.

A More detailed example using ``wishpy`` for publishing to Redis is available at the following repo -

* `wishpy-examples <https://github.com/hyphenOs/wishpy-examples>`_

