# OpenSC documentation


Wiki is [available online](https://github.com/OpenSC/OpenSC/wiki)

Please take a look at the documentation before trying to use OpenSC.

Do NOT use any links from wiki to download the OpenSC because wiki can be modified by anybody, see
[#2554](https://github.com/OpenSC/OpenSC/issues/2554). For downloading OpenSC, use the links here in README.

# Downloads

[OpenSC 0.24.0](https://github.com/OpenSC/OpenSC/releases/tag/0.24.0) is the latest stable version released on
13.12.2023. It is available as

 * Windows installer
   * [OpenSC-0.24.0_win64.msi](https://github.com/OpenSC/OpenSC/releases/download/0.24.0/OpenSC-0.24.0_win64.msi) for 64 bit programs
   * [OpenSC-0.24.0_win32.msi](https://github.com/OpenSC/OpenSC/releases/download/0.24.0/OpenSC-0.24.0_win32.msi) for 32 bit programs
 * [OpenSC-0.24.0.dmg](https://github.com/OpenSC/OpenSC/releases/download/0.24.0/OpenSC-0.24.0.dmg): macOS installer
 * [opensc-0.24.0.tar.gz](https://github.com/OpenSC/OpenSC/releases/download/0.24.0/opensc-0.24.0.tar.gz): Source code distribution

## Nightly build

The latest source code is available through [GitHub](https://github.com/OpenSC/OpenSC/archive/master.zip).
Nightly builds are available by their git hash in branches of [OpenSC/Nightly](https://github.com/OpenSC/Nightly).


# Build and testing status

[![Linux build](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml/badge.svg)](https://github.com/OpenSC/OpenSC/actions/workflows/linux.yml)
[![OSX build](https://github.com/OpenSC/OpenSC/actions/workflows/macos.yml/badge.svg)](https://github.com/OpenSC/OpenSC/actions/workflows/macos.yml)
[![AppVeyor CI Build Status](https://ci.appveyor.com/api/projects/status/github/OpenSC/OpenSC?branch=master&svg=true)](https://ci.appveyor.com/project/LudovicRousseau/OpenSC/branch/master)
[![Coverity Scan Status](https://scan.coverity.com/projects/4026/badge.svg)](https://scan.coverity.com/projects/4026)
[![CodeQL](https://github.com/OpenSC/OpenSC/actions/workflows/codeql.yml/badge.svg?event=push)](https://github.com/OpenSC/OpenSC/actions/workflows/codeql.yml)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/opensc.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:opensc)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3908/badge)](https://bestpractices.coreinfrastructure.org/projects/3908)

Build and test status of specific cards:

| Cards                                                               | Status                                                                                                                            |
|---------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
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
