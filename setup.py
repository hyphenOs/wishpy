from setuptools import setup, find_packages

import wspy.wireshark.src.epan.epan as epan_src
import wspy.wireshark.src.wtap.wtap as wtap_src

setup(name='wspy',
        version='0.0.1',
        description='Python Bindings for Wireshark using CFFI',
        author='Abhijit Gadgil',
        author_email='gabhijit@iitbombay.org',
        license_files=['LICENSE', 'COPYING', 'COPYING-wireshark'],
        ext_modules=[
            epan_src.epan_ffi.distutils_extension(),
            wtap_src.wtap_ffi.distutils_extension(),
            ],
        packages=find_packages())

