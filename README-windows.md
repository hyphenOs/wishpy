# 'wishpy' on Windows 

**NOTE: This is Very Very Experimental, even for a project this early.** 

# Getting Started 

Unfortunately until such time we figure out how to generated `bdist_wheel` for windows, this document is the only
hope of getting this working on Windows - Windows 10 specifically. 

Specifically, only `examples/tshark.py` which dissects `PCAP`ish files, works. The Capturing part does not work yet, and is a WIP. 

## Building Wireshark and 'wishpy' 

To get started, one has to start building wireshark from the sources first. This is required because there is no equivalent of `-dev` packages on Windows that I know of. If that exists, may be things will be slightly better. 

To get started, one can follow the instructions [here](https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html). Most of the instructions work just fine. There are a few changes we have done. 

1. Follow all steps up to section 2.2.10 - you should have got everything required to build wireshark sources instaled.
2. Ignore step 2.2.3 and 2.2.8. No need to install Qt and Doctools, we are not going to be building that. What we really need is - to be able to build libraries. 
3. `chocolaty` installation of `visualstudio2019-workload-nativedesktop` will crib. This is because somehow the final `restart` doesn't work. Just restart the machine. 
4. Note: by default `chocolaty` installs Python3.8 and the support does not work with Python 3.8. My suspicion is there is some issue with setuptools and Python 3.8 as it is not able to properly determine 64 bits windows to start with. So instead of Python 3.8 installed by Chocolaty, one should install Python 3.7.8 from [python.org](https://www.python.org). Python3.8 is per se not a problem with building wireshark, but will annoy when building the bindings, so it's just best to get a working Python installed.
5. Instead of Using "Developer Command Prompt", we are using "Developer Power Shell", it's slightly easier to work with.
6. In Power shell, setup following envirnoment variables. 
   - `$env:WIRESHARK_BASE_DIR = "C:\wireshark-dev"`
   - `$env:PLATFORM = "x64"`
   - `$env:WIRESHARK_TARGET_PLATFORM="win64"`
7. Edit the `CMakeOptions.txt` file to change `BUILD_wireshark` to `OFF`.
8. Make the following directory - 
  - `c:\wsbuild64` 
9. Right now following directories should be present - 
  - `c:\wireshark` - git clone of the wireshark repo.
  - `c:\wsbuild64` - build directory - All the subsequent commands are run in this directory.
  - `c:\wireshark-dev` - Set above as `WIRESHARK_BASE_DIR`. Wireshark downloads all the required tools and libraries inside this path. 
10. All subsequent commands are to be run into - `c:\wsbuild64` directory
11. Generate the wireshark solution file using - 
    - `cmake -G "Visual Studio 16 2019" -A x64 ..\wireshark` 
    - `cmake --build . --config Release --target INSTALL`
12. Last command might need administrative privilages, so can be re-run again by opening Administrator `Developer powershell for visual studio 2019`

13. This should install wireshark libraries and some console tools inside `C:\program files (86)\wireshark`.
14. Th required `glib-2` dev files are under - `C:\wireshark-dev\wireshark-win64-libs-3.2\vcpkg-export-20190318-win64ws\installed\x64-windows\include` and `C:\wireshark-dev\wireshark-win64-libs-3.2\vcpkg-export-20190318-win64ws\installed\x64-windows\lib` (Required in next step in `wishpy`.) 

15. Now we can simply perform `python setup.py install` inside wishpy. Note: the paths above are right now hard-coded inside the `wishpy/wireshark/src/wireshark3/epan/epan.py` to get them to build. If you deviate from these paths, this file needs to be changed. (This is ugly right now agreed, we'll need to make it better). 

16. If installation succeeds - one can now run `venv\scripts\tshark.py <pcap-file>`.

17. `PATH` environment variable needs to be updated to point to the wireshark and glib-2 libraries. They are the following respectively - 
    - Wireshark DLL's Path `c:\Program Files (x86)\Wireshark`
    - glib-2 DLL's Path `C:\wireshark-dev\wireshark-win64-libs-3.2\vcpkg-export-20190318-win64ws\installed\x64-windows\bin`


