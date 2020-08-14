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
    except FileNotFoundError:
        pass

    if sys.platform.startswith('win'):
        # On windows the version is always 3.2 (One we are building)
        return 3, 2, False

    if os.path.exists("wireshark-version"):
        with open("wireshark-version", "r") as f:
            for line in f:
                if line.lower().startswith("version:"):
                    ws_version_str = line.split(":")[1].strip()
                    major, minor, _ = ws_version_str.split(".")
                    major, minor = int(major), int(minor)
                    return major, minor, False

    return None, None, None

major, minor, is_pkgconfig = find_libwireshark_version()

if major is None or minor is None:
    major = 3
    minor = 2

ws_version_str = "{}.{}".format(major, minor)

if not is_pkgconfig:
    warning_msg = "Heuristically determined version of Wireshark is {}.{} .".\
            format(major, minor)
    warning_msg += " Trying to find libs/includes in the prefix '/usr/local/"
    warnings.warn(warning_msg)

if major == 2:
    if minor != 6:
        print("Supported version is 2.6. Determined version is ", ws_version_str)
        sys.exit(-1)

    epan_ffi_module = 'wishpy/wireshark/src/wireshark2/epan/epan_builder.py:epan_ffi'

elif major == 3:
    if minor != 2:
        print("Supported version is 3.2. Determined version is ", ws_version_str)
        sys.exit(-1)

    epan_ffi_module = 'wishpy/wireshark/src/wireshark3/epan/epan_builder.py:epan_ffi'

libpcap_ffi_module = 'wishpy/libpcap/src/pcap_builder.py:libpcap_ffi'

all_cffi_modules = [epan_ffi_module]
if sys.platform != 'win32':
    all_cffi_modules.append(libpcap_ffi_module)

setup(name='wishpy',
        version='0.1.0',
        description='Python Bindings for Wireshark and libpcap using cffi',
        long_description=open('README.md').read(),
        long_description_content_type="text/markdown",
        author='hyphenOs Software Labs',
        author_email='gabhijit@hyphenos.io',
        license_files=['LICENSE', 'COPYING', 'COPYING-Wireshark', 'LICENSE-libpcap'],
        setup_requires=['cffi>=1.14.0'],
        install_requires=['cffi>=1.14.0', 'click'],
        cffi_modules=all_cffi_modules,
        packages=find_packages(),
        url='https://github.com/hyphenOs/wishpy/',
        keywords=['Python', 'Wireshark', 'Networking', 'libpcap'],
        license='GPLv3',
        classifiers=[
            "Development Status :: 2 - Pre-Alpha",
            "Environment :: Console",
            "Intended Audience :: Developers",
            "Intended Audience :: System Administrators",
            "Intended Audience :: Telecommunications Industry",
            "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.5",
            "Programming Language :: Python :: 3.6",
            "Programming Language :: Python :: 3.7",
            "Programming Language :: Python :: 3.8",
            "Topic :: System :: Networking",
            "Topic :: System :: Networking :: Monitoring",
        ],
        entry_points="""
        [console_scripts]
        tshark=wishpy.scripts.tshark:dissect
        tcpdump=wishpy.scripts.tcpdump:dump
        pcap_pickler=wishpy.scripts.pcap_to_pickle:pickler
        """,
        zip_safe=False)
