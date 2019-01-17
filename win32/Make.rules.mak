OPENSC_FEATURES = pcsc

#Include support for minidriver
MINIDRIVER_DEF = /DENABLE_MINIDRIVER

#Build MSI with the Windows Installer XML (WIX) toolkit, requires WIX >= 3.9
!IF "$(WIX)" == ""
# at least WiX 3.11 sets the WIX environment variable to its path
WIX = C:\Program Files\WiX Toolset v3.10
!ENDIF
!IF "$(DEVENVDIR)" == "C:\Program Files (x86)\Microsoft Visual Studio 10.0\Common7\IDE\" || "$(DEVENVDIR)" == "C:\Program Files\Microsoft Visual Studio 10.0\Common7\IDE\"
WIXVSVER = VS2010
!ENDIF
!IF "$(VISUALSTUDIOVERSION)" == "12.0"
WIXVSVER = VS2013
!ENDIF
!IF "$(VISUALSTUDIOVERSION)" == "14.0"
WIXVSVER = VS2015
!ENDIF
WIX_INCL_DIR = "/I$(WIX)\SDK\$(WIXVSVER)\inc"
WIX_LIBS = "$(WIX)\SDK\$(WIXVSVER)\lib\$(PLATFORM)\dutil.lib" "$(WIX)\SDK\$(WIXVSVER)\lib\$(PLATFORM)\wcautil.lib"

# We do not build tests on windows
#TESTS_DEF = /DENABLE_TESTS

#Include support for Secure Messaging
SM_DEF = /DENABLE_SM

#Build with debugging support
#DEBUG_DEF = /DDEBUG

# If you want support for OpenSSL (needed for pkcs15-init tool, software hashing in PKCS#11 library and verification):
# - download and build OpenSSL
# - uncomment the line starting with OPENSSL_DEF
# - set the OPENSSL_INCL_DIR below to your openssl include directory, preceded by "/I"
# - set the OPENSSL_LIB below to your openssl lib file
#OPENSSL_DEF= /DENABLE_OPENSSL
!IF "$(OPENSSL_DEF)" == "/DENABLE_OPENSSL"
!IF "$(PLATFORM)" == "x86"
OPENSSL_DIR = C:\OpenSSL-Win32
!ELSE
OPENSSL_DIR = C:\OpenSSL-Win64
!ENDIF
OPENSSL_INCL_DIR = /I$(OPENSSL_DIR)\include

#define OPENSSL_STATIC if you have visual studio compatible with OpenSSL's static binaries
OPENSSL_STATIC_DIR = static

!IF "$(DEBUG_DEF)" == "/DDEBUG"
!IF "$(PLATFORM)" == "x86"
# OpenSSL 1.0.2
OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\$(OPENSSL_STATIC_DIR)\libeay32MTd.lib user32.lib advapi32.lib crypt32.lib ws2_32.lib
# OpenSSL 1.1.0
#OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\$(OPENSSL_STATIC_DIR)\libcrypto32MTd.lib user32.lib advapi32.lib crypt32.lib ws2_32.lib
!ELSE
# OpenSSL 1.0.2
OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\$(OPENSSL_STATIC_DIR)\libeay32MTd.lib user32.lib advapi32.lib crypt32.lib ws2_32.lib
# OpenSSL 1.1.0
#OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\$(OPENSSL_STATIC_DIR)\libcrypto64MTd.lib user32.lib advapi32.lib crypt32.lib ws2_32.lib
!ENDIF
!ELSE
!IF "$(PLATFORM)" == "x86"
# OpenSSL 1.0.2
OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\$(OPENSSL_STATIC_DIR)\libeay32MT.lib user32.lib advapi32.lib crypt32.lib ws2_32.lib
# OpenSSL 1.1.0
#OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\$(OPENSSL_STATIC_DIR)\libcrypto32MT.lib user32.lib advapi32.lib crypt32.lib ws2_32.lib
!ELSE
# OpenSSL 1.0.2
OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\$(OPENSSL_STATIC_DIR)\libeay32MT.lib user32.lib advapi32.lib crypt32.lib ws2_32.lib
# OpenSSL 1.1.0
#OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\$(OPENSSL_STATIC_DIR)\libcrypto64MT.lib user32.lib advapi32.lib crypt32.lib ws2_32.lib
!ENDIF
!ENDIF

PROGRAMS_OPENSSL = cryptoflex-tool.exe pkcs15-init.exe netkey-tool.exe piv-tool.exe \
	westcos-tool.exe sc-hsm-tool.exe dnie-tool.exe gids-tool.exe npa-tool.exe
OPENSC_FEATURES = $(OPENSC_FEATURES) openssl
CANDLEFLAGS = -dOpenSSL="$(OPENSSL_DIR)" $(CANDLEFLAGS)
!ENDIF


# If you want support for zlib (Used for PIV and actalis):
# - Download zlib-dll and
# - uncomment the line starting with ZLIB_DEF 
# - set the ZLIB_INCL_DIR below to the zlib include lib proceeded by "/I"
# - set the ZLIB_LIB  below to your zlib lib file
#ZLIB_DEF = /DENABLE_ZLIB
!IF "$(ZLIBSTATIC_DEF)" == "/DENABLE_ZLIB_STATIC"
ZLIB_DEF = /DENABLE_ZLIB
!IF "$(ZLIB_INCL_DIR)" == ""
ZLIB_INCL_DIR = /IC:\zlib
!ENDIF
!IF "$(ZLIB_LIB)" == ""
ZLIB_LIB = C:\zlib\zlib.lib
!ENDIF
OPENSC_FEATURES = $(OPENSC_FEATURES) zlib
!ELSEIF "$(ZLIB_DEF)" == "/DENABLE_ZLIB"
!IF "$(ZLIB_INCL_DIR)" == ""
ZLIB_INCL_DIR = /IC:\zlib-dll\include
!ENDIF
!IF "$(ZLIB_LIB)" == ""
ZLIB_LIB = C:\zlib-dll\lib\zdll.lib
!ENDIF
OPENSC_FEATURES = $(OPENSC_FEATURES) zlib
CANDLEFLAGS = -dzlib="C:\zlib-dll" $(CANDLEFLAGS)
!ENDIF


# If you want support for EAC:
# - Download OpenPACE and
# - uncomment the line starting with OPENPACE_DEF 
# - set the OPENPACE_INCL_DIR below to the OpenPACE include directory preceded by "/I"
# - set the OPENPACE_LIB  below to your OpenPACE lib file
#OPENPACE_DEF= /DENABLE_OPENPACE
!IF "$(OPENPACE_DEF)" == "/DENABLE_OPENPACE"
!IF "$(OPENPACE_DIR)" == ""
OPENPACE_DIR = C:\openpace
!ENDIF
OPENPACE_INCL_DIR = /I$(OPENPACE_DIR)\src
OPENPACE_LIB = $(OPENPACE_DIR)\src\libeac.lib
CANDLEFLAGS = -dOpenPACE="$(OPENPACE_DIR)" $(CANDLEFLAGS)
!ENDIF


# Used for MiniDriver
CNGSDK_INCL_DIR = "/IC:\Program Files (x86)\Microsoft CNG Development Kit\Include"
!IF "$(PROCESSOR_ARCHITECTURE)" == "x86" && "$(PROCESSOR_ARCHITEW6432)" == ""
CNGSDK_INCL_DIR = "/IC:\Program Files\Microsoft CNG Development Kit\Include"
!ENDIF
# Mandatory path to 'ISO C9x compliant stdint.h and inttypes.h for Microsoft Visual Studio'
# http://msinttypes.googlecode.com/files/msinttypes-r26.zip
# INTTYPES_INCL_DIR =  /IC:\opensc\dependencies\msys\local

# Code optimisation
#  O1 - minimal code size
CODE_OPTIMIZATION = /O1

ALL_INCLUDES = /I$(TOPDIR)\win32 /I$(TOPDIR)\src $(OPENPACE_INCL_DIR) $(OPENSSL_INCL_DIR) $(OPENSSL_EXTRA_CFLAGS) $(ZLIB_INCL_DIR) $(LIBLTDL_INCL) $(INTTYPES_INCL_DIR) $(CNGSDK_INCL_DIR) $(WIX_INCL_DIR)

!IF "$(DEBUG_DEF)" == "/DDEBUG"
LINKDEBUGFLAGS = /NODEFAULTLIB:LIBCMT /DEBUG
CODE_OPTIMIZATION =
COPTS =  /GS /W3 /WX /D_CRT_SECURE_NO_DEPRECATE /D_CRT_NONSTDC_NO_WARNINGS /MTd /nologo /DHAVE_CONFIG_H $(ALL_INCLUDES) /DWINVER=0x0601 /D_WIN32_WINNT=0x0601 /DWIN32_LEAN_AND_MEAN $(OPENPACE_DEF) $(OPENSSL_DEF) $(ZLIB_DEF) $(MINIDRIVER_DEF) $(SM_DEF) $(TESTS_DEF) /DOPENSC_FEATURES="\"$(OPENSC_FEATURES)\"" /DDEBUG /Zi /Od
!ELSE
LINKDEBUGFLAGS = /NODEFAULTLIB:LIBCMTD /DEBUG /OPT:REF /OPT:ICF
COPTS =  /GS /W3 /WX /D_CRT_SECURE_NO_DEPRECATE /D_CRT_NONSTDC_NO_WARNINGS /MT /nologo /DHAVE_CONFIG_H $(ALL_INCLUDES) /DWINVER=0x0601 /D_WIN32_WINNT=0x0601 /DWIN32_LEAN_AND_MEAN $(OPENPACE_DEF) $(OPENSSL_DEF) $(ZLIB_DEF) $(MINIDRIVER_DEF) $(SM_DEF) $(TESTS_DEF) /DOPENSC_FEATURES="\"$(OPENSC_FEATURES)\"" /Zi
!ENDIF


LINKFLAGS = /NOLOGO /INCREMENTAL:NO /MACHINE:$(PLATFORM) /NODEFAULTLIB:MSVCRTD  /NODEFAULTLIB:MSVCRT /NXCOMPAT /DYNAMICBASE $(LINKDEBUGFLAGS)
LIBFLAGS =  /nologo /machine:$(PLATFORM)
!IF "$(PLATFORM)" == "x86"
CANDLEFLAGS = -dPlatform=x86 $(CANDLEFLAGS)
!ELSE
CANDLEFLAGS = -dPlatform=x64 $(CANDLEFLAGS)
!ENDIF

.c.obj::
	cl $(CODE_OPTIMIZATION) $(COPTS) /c $<

.cpp.obj::
	cl $(CODE_OPTIMIZATION) $(COPTS) /c $<

.rc.res::
	rc /l 0x0409 $<

clean::
	del /Q *.obj *.dll *.exe *.pdb *.lib *.def *.res
