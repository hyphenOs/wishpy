import os
import sys
import subprocess
import warnings
from setuptools import setup, find_packages

def find_libwireshark_version():

    # First try using pkg-config
    major, minor, patch = None, None, None
    try:
        output = subprocess.run(["pkg-config", "--modversion", "wireshark"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        major, minor, _ = output.stdout.decode().strip().split(".")
        major, minor = int(major), int(minor)
        return major, minor, True
    except subprocess.CalledProcessError:
        pass


    if os.path.exists("wireshark-version"):
        with open("wireshark-version", "r") as f:
            for line in f:
                if line.lower().startswith("version:"):
                    version_str = line.split(":")[1].strip()
                    major, minor, _ = version_str.split(".")
                    major, minor = int(major), int(minor)
                    return major, minor, False

    return None, None, None

major, minor, is_pkgconfig = find_libwireshark_version()

if major is None or minor is None:
    major = 2
    minor = 6

version_str = "{}.{}".format(major, minor)

if not is_pkgconfig:
    warning_msg = "Heuristically determined version of Wireshark is {}.{} .".\
            format(major, minor)
    warning_msg += " Trying to find libs/includes in the prefix '/usr/local/"
    warnings.warn(warning_msg)

if major == 2:
    if minor != 6:
        print("Supported version is 2.6. Determined version is ", version_str)
        sys.exit(-1)

    epan_ffi_module = 'wishpy/wireshark/src/wireshark2/epan/epan_builder.py:epan_ffi'

elif major == 3:
    if minor != 2:
        print("Supported version is 3.2. Determined version is ", version_str)
        sys.exit(-1)

    epan_ffi_module = 'wishpy/wireshark/src/wireshark3/epan/epan_builder.py:epan_ffi'

libpcap_ffi_module = 'wishpy/libpcap/src/pcap_builder.py:libpcap_ffi'

setup(name='wishpy',
        version='0.0.5',
        description='Python Bindings for Wireshark using CFFI',
        author='Abhijit Gadgil',
        author_email='gabhijit@iitbombay.org',
        license_files=['LICENSE', 'COPYING', 'COPYING-Wireshark', 'LICENSE-libpcap'],
        setup_requires=['cffi>=1.14.0'],
        cffi_modules=[
            epan_ffi_module,
            libpcap_ffi_module
            ],
        packages=find_packages(), #exclude=('wishpy.wireshark.lib',)),
        scripts=['examples/tshark3.py',
            'examples/tshark2.py',
            'examples/tshark.py',
            'examples/tcpdump.py'],
        zip_safe=False)
