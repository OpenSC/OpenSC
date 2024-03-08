# OpenSC documentation

Manual pages for the
[OpenSC command line tools](https://htmlpreview.github.io/?https://github.com/OpenSC/OpenSC/blob/master/doc/tools/tools.html)
as well as for the
[OpenSC configuration files](https://htmlpreview.github.io/?https://github.com/OpenSC/OpenSC/blob/master/doc/files/files.html)
are available online and typically distributed along with your installation.

The [OpenSC Wiki](https://github.com/OpenSC/OpenSC/wiki) includes, among others, information for:
 * [Windows Quick Start](https://github.com/OpenSC/OpenSC/wiki/Windows-Quick-Start)
 * [macOS Quick Start](https://github.com/OpenSC/OpenSC/wiki/macOS-Quick-Start)
 * [Compiling and Installing on Unix flavors](https://github.com/OpenSC/OpenSC/wiki/Compiling-and-Installing-on-Unix-flavors)
 * [Frequently Asked Questions](https://github.com/OpenSC/OpenSC/wiki/Frequently-Asked-Questions)
 * More user and developer provided documentation

# Downloads

## Latest release

The [latest stable version of OpenSC](https://github.com/OpenSC/OpenSC/releases/latest) is available on Github.  It is available as

 * Windows installer for 64 bit and 32 bit programs (`OpenSC*_win64.msi` and `OpenSC*_win32.msi`)
 * macOS installer (`OpenSC*.dmg`)
 * Source code distribution (`opensc*.tar.gz`)

## Nightly build

The latest source code is available through [GitHub](https://github.com/OpenSC/OpenSC/archive/master.zip).
Nightly builds are available by their git hash in branches of [OpenSC/Nightly](https://github.com/OpenSC/Nightly).


# Build and testing status

[![Linux build](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml/badge.svg)](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml)
[![OSX build](https://github.com/OpenSC/OpenSC/actions/workflows/macos.yml/badge.svg)](https://github.com/OpenSC/OpenSC/actions/workflows/macos.yml)
[![AppVeyor CI Build Status](https://ci.appveyor.com/api/projects/status/github/OpenSC/OpenSC?branch=master&svg=true)](https://ci.appveyor.com/project/frankmorgner/opensc/branch/master)
[![Coverity Scan Status](https://scan.coverity.com/projects/4026/badge.svg)](https://scan.coverity.com/projects/4026)
[![CodeQL](https://github.com/OpenSC/OpenSC/actions/workflows/codeql.yml/badge.svg?event=push)](https://github.com/OpenSC/OpenSC/actions/workflows/codeql.yml)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/opensc.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:opensc)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3908/badge)](https://bestpractices.coreinfrastructure.org/projects/3908)

Build and test status of specific cards:

| Cards                                                               | Status                                                                                                                            |
|----------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| CAC                                                                 | [![CAC](https://gitlab.com/redhat-crypto/OpenSC/badges/cac/pipeline.svg)](https://gitlab.com/redhat-crypto/OpenSC/pipelines)      |
| [virt_CACard](https://github.com/Jakuje/virt_cacard)                | [![virt_CACard](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml/badge.svg)](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml) |
| [Coolkey](https://github.com/dogtagpki/coolkey/tree/master/applet)  | [![Coolkey](https://gitlab.com/redhat-crypto/OpenSC/badges/coolkey/pipeline.svg)](https://gitlab.com/redhat-crypto/OpenSC/pipelines) |
| [PivApplet](https://github.com/arekinath/PivApplet)                 | [![PIV](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml/badge.svg)](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml) |
| [OpenPGP Applet](https://github.com/Yubico/ykneo-openpgp/)          | [![OpenPGP](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml/badge.svg)](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml) |
| [GidsApplet](https://github.com/vletoux/GidsApplet/)                | [![GIDS](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml/badge.svg)](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml) |
| [IsoApplet](https://github.com/philipWendland/IsoApplet/)           | [![IsoApplet](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml/badge.svg)](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml) |
| [OsEID (MyEID)](https://sourceforge.net/projects/oseid/)            | [![OsEID (MyEID)](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml/badge.svg)](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml) |
| SmartCardHSM                                                        | [![SmartCardHSM](https://gitlab.com/redhat-crypto/OpenSC/badges/sc-hsm/pipeline.svg)](https://gitlab.com/redhat-crypto/OpenSC/pipelines) |
| ePass2003                                                           | [![ePass2003](https://gitlab.com/redhat-crypto/OpenSC/badges/epass2003/pipeline.svg)](https://gitlab.com/redhat-crypto/OpenSC/pipelines) |
