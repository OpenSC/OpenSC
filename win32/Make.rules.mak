OPENSC_FEATURES = pcsc

!IF "$(BUILD_ON)" == "WIN32"
PROGRAMFILES_PATH = C:\Program Files
!ELSE
PROGRAMFILES_PATH = C:\Program Files (x86)
!ENDIF

#Include support for minidriver
MINIDRIVER_DEF = /DENABLE_MINIDRIVER

#Build MSI with the Windows Installer XML (WIX) toolkit, requires WIX >= 3.9
WIX_PATH = $(PROGRAMFILES_PATH)\WiX Toolset v3.10
WIX_INCL_DIR = "/I$(WIX_PATH)\SDK\VS2010\inc"
!IF "$(BUILD_FOR)" == "WIN64"
WIX_LIBS = "$(WIX_PATH)\SDK\VS2010\lib\x64\dutil.lib" "$(WIX_PATH)\SDK\VS2010\lib\x64\wcautil.lib"
!ELSE
WIX_LIBS = "$(WIX_PATH)\SDK\VS2010\lib\x86\dutil.lib" "$(WIX_PATH)\SDK\VS2010\lib\x86\wcautil.lib"
!ENDIF

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
!IF "$(BUILD_FOR)" == "WIN64"
OPENSSL_DIR = C:\OpenSSL-Win64
!ELSE
OPENSSL_DIR = C:\OpenSSL-Win32
!ENDIF
OPENSSL_INCL_DIR = /I$(OPENSSL_DIR)\include

#define OPENSSL_STATIC if you have visual studio compatible with OpenSSL's static binaries
OPENSSL_STATIC_DIR = static

!IF "$(DEBUG_DEF)" == "/DDEBUG"
OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\$(OPENSSL_STATIC_DIR)\libeay32MTd.lib user32.lib advapi32.lib crypt32.lib
!ELSE
OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\$(OPENSSL_STATIC_DIR)\libeay32MT.lib user32.lib advapi32.lib crypt32.lib
!ENDIF

PROGRAMS_OPENSSL = cryptoflex-tool.exe pkcs15-init.exe netkey-tool.exe piv-tool.exe \
	westcos-tool.exe sc-hsm-tool.exe dnie-tool.exe gids-tool.exe
OPENSC_FEATURES = $(OPENSC_FEATURES) openssl
CANDLEFLAGS = -dOpenSSL="$(OPENSSL_DIR)" $(CANDLEFLAGS)
!ENDIF


# If you want support for zlib (Used for PIV, infocamere and actalis):
# - Download zlib-dll and
# - uncomment the line starting with ZLIB_DEF 
# - set the ZLIB_INCL_DIR below to the zlib include lib proceeded by "/I"
# - set the ZLIB_LIB  below to your zlib lib file
#ZLIB_DEF = /DENABLE_ZLIB
!IF "$(ZLIBSTATIC_DEF)" == "/DENABLE_ZLIB_STATIC"
ZLIB_DEF = /DENABLE_ZLIB
ZLIB_INCL_DIR = /IC:\zlib
ZLIB_LIB = C:\zlib\zlib.lib
OPENSC_FEATURES = $(OPENSC_FEATURES) zlib
!ELSE IF "$(ZLIB_DEF)" == "/DENABLE_ZLIB"
ZLIB_INCL_DIR = /IC:\zlib-dll\include
ZLIB_LIB = C:\zlib-dll\lib\zdll.lib
OPENSC_FEATURES = $(OPENSC_FEATURES) zlib
CANDLEFLAGS = -dzlib="C:\zlib-dll" $(CANDLEFLAGS)
!ENDIF


# Used for MiniDriver
CNGSDK_INCL_DIR = "/I$(PROGRAMFILES_PATH)\Microsoft CNG Development Kit\Include"
# Mandatory path to 'ISO C9x compliant stdint.h and inttypes.h for Microsoft Visual Studio'
# http://msinttypes.googlecode.com/files/msinttypes-r26.zip
# INTTYPES_INCL_DIR =  /IC:\opensc\dependencies\msys\local

# Code optimisation
#  O1 - minimal code size
CODE_OPTIMIZATION = /O1

ALL_INCLUDES = /I$(TOPDIR)\win32 /I$(TOPDIR)\src $(OPENSSL_INCL_DIR) $(OPENSSL_EXTRA_CFLAGS) $(ZLIB_INCL_DIR) $(LIBLTDL_INCL) $(INTTYPES_INCL_DIR) $(CNGSDK_INCL_DIR) $(WIX_INCL_DIR)

!IF "$(DEBUG_DEF)" == "/DDEBUG"
LINKDEBUGFLAGS = /NODEFAULTLIB:LIBCMT /DEBUG
CODE_OPTIMIZATION =
COPTS =  /GS /W3 /D_CRT_SECURE_NO_DEPRECATE /MTd /nologo /DHAVE_CONFIG_H $(ALL_INCLUDES) /D_WIN32_WINNT=0x0502 /DWIN32_LEAN_AND_MEAN $(OPENSSL_DEF) $(ZLIB_DEF) $(MINIDRIVER_DEF) $(SM_DEF) /DOPENSC_FEATURES="\"$(OPENSC_FEATURES)\"" /DDEBUG /Zi /Od
!ELSE
LINKDEBUGFLAGS = /NODEFAULTLIB:LIBCMTD
COPTS =  /GS /W3 /D_CRT_SECURE_NO_DEPRECATE /MT /nologo /DHAVE_CONFIG_H $(ALL_INCLUDES) /D_WIN32_WINNT=0x0502 /DWIN32_LEAN_AND_MEAN $(OPENSSL_DEF) $(ZLIB_DEF) $(MINIDRIVER_DEF) $(SM_DEF) /DOPENSC_FEATURES="\"$(OPENSC_FEATURES)\""
!ENDIF


!IF "$(BUILD_FOR)" == "WIN64"
LINKFLAGS = /NOLOGO /INCREMENTAL:NO /MACHINE:X64 /MANIFEST:NO /NODEFAULTLIB:MSVCRTD  /NODEFAULTLIB:MSVCRT /NXCOMPAT /DYNAMICBASE $(LINKDEBUGFLAGS)
LIBFLAGS =  /nologo /machine:x64
CANDLEFLAGS = -dPlatform=x64 $(CANDLEFLAGS)
!ELSE
LINKFLAGS = /NOLOGO /INCREMENTAL:NO /MACHINE:X86 /MANIFEST:NO /NODEFAULTLIB:MSVCRTD  /NODEFAULTLIB:MSVCRT /NXCOMPAT /DYNAMICBASE /SAFESH $(LINKDEBUGFLAGS)
LIBFLAGS =  /nologo /machine:x86
CANDLEFLAGS = -dPlatform=x86 $(CANDLEFLAGS)
!ENDIF

.c.obj::
	cl $(CODE_OPTIMIZATION) $(COPTS) /c $<

.cpp.obj::
	cl $(CODE_OPTIMIZATION) $(COPTS) /c $<

.rc.res::
	rc /l 0x0409 $<

clean::
	del /Q *.obj *.dll *.exe *.pdb *.lib *.def *.manifest *.res
