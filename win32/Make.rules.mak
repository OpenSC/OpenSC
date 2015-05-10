OPENSC_FEATURES = pcsc

#Include support for minidriver
MINIDRIVER_DEF = /DENABLE_MINIDRIVER

#Build MSI with the Windows Installer XML (WIX) toolkit, requires WIX >= 3.6
!IF "$(BUILD_ON)" == "WIN64"
WIX_PATH = "C:\Program Files (x86)\Windows Installer XML v3.6"
WIX_INCL_DIR = "/IC:\Program Files (x86)\Windows Installer XML v3.6\SDK\inc"
!IF "$(BUILD_FOR)" == "WIN64"
WIX_LIBS = "C:\Program Files (x86)\Windows Installer XML v3.6\SDK\lib\dutil_2010_x64.lib" "C:\Program Files (x86)\Windows Installer XML v3.6\SDK\lib\wcautil_2010_x64.lib"
!ELSE
WIX_LIBS = "C:\Program Files (x86)\Windows Installer XML v3.6\SDK\lib\dutil_2010.lib" "C:\Program Files (x86)\Windows Installer XML v3.6\SDK\lib\wcautil_2010.lib"
!ENDIF

!ELSE
WIX_PATH = "C:\Program Files\Windows Installer XML v3.6"
WIX_INCL_DIR = "/IC:\Program Files\Windows Installer XML v3.6\SDK\inc"
!IF "$(BUILD_FOR)" == "WIN64"
WIX_LIBS = "C:\Program Files\Windows Installer XML v3.6\SDK\lib\dutil_2010_x64.lib" "C:\Program Files\Windows Installer XML v3.6\SDK\lib\wcautil_2010_x64.lib"
!ELSE
WIX_LIBS = "C:\Program Files\Windows Installer XML v3.6\SDK\lib\dutil_2010.lib" "C:\Program Files\Windows Installer XML v3.6\SDK\lib\wcautil_2010.lib"
!ENDIF

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
OPENSSL_DEF = /DENABLE_OPENSSL
!IF "$(OPENSSL_DEF)" == "/DENABLE_OPENSSL"
!IF "$(BUILD_FOR)" == "WIN64"
OPENSSL_DIR = C:\OpenSSL-Win64
!ELSE
OPENSSL_DIR = C:\OpenSSL-Win32
!ENDIF
OPENSSL_INCL_DIR = /I$(OPENSSL_DIR)\include

!IF "$(DEBUG_DEF)" == "/DDEBUG"
OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\static\libeay32MTd.lib $(OPENSSL_DIR)\lib\VC\static\ssleay32MTd.lib user32.lib advapi32.lib crypt32.lib
!ELSE
OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\static\libeay32MT.lib $(OPENSSL_DIR)\lib\VC\static\ssleay32MT.lib user32.lib advapi32.lib crypt32.lib
!ENDIF

PROGRAMS_OPENSSL = pkcs15-init.exe cryptoflex-tool.exe netkey-tool.exe piv-tool.exe westcos-tool.exe
OPENSC_FEATURES = $(OPENSC_FEATURES) openssl
!ENDIF


# If you want support for zlib (Used for PIV, infocamere and actalis):
# - Download zlib and build with "nmake /f win32\Makefile.msc zlib.lib"
# - uncomment the line starting with ZLIB_DEF 
# - set the ZLIB_INCL_DIR below to the zlib include lib proceeded by "/I"
# - set the ZLIB_LIB  below to your zlib lib file
ZLIB_DEF = /DENABLE_ZLIB
!IF "$(ZLIB_DEF)" == "/DENABLE_ZLIB"
ZLIB_INCL_DIR = /IC:\zlib-1.2.5
ZLIB_LIB = C:\zlib-1.2.5\zlib.lib
OPENSC_FEATURES = $(OPENSC_FEATURES) zlib
!ENDIF

# Used for MiniDriver
!IF "$(BUILD_ON)" == "WIN64"
CNGSDK_INCL_DIR = "/IC:\Program Files (x86)\Microsoft CNG Development Kit\Include"
!ELSE
CNGSDK_INCL_DIR = "/IC:\Program Files\Microsoft CNG Development Kit\Include"
!ENDIF
# Mandatory path to 'ISO C9x compliant stdint.h and inttypes.h for Microsoft Visual Studio'
# http://msinttypes.googlecode.com/files/msinttypes-r26.zip
# INTTYPES_INCL_DIR =  /IC:\opensc\dependencies\msys\local

# Code optimisation
#  O1 - minimal code size
CODE_OPTIMIZATION = /O1

ALL_INCLUDES = /I$(TOPDIR)\win32 /I$(TOPDIR)\src $(OPENSSL_INCL_DIR) $(ZLIB_INCL_DIR) $(LIBLTDL_INCL) $(INTTYPES_INCL_DIR) $(CNGSDK_INCL_DIR) $(WIX_INCL_DIR)

!IF "$(DEBUG_DEF)" == "/DDEBUG"
LINKDEBUGFLAGS = /NODEFAULTLIB:LIBCMT /DEBUG
CODE_OPTIMIZATION =
COPTS =  /W3 /D_CRT_SECURE_NO_DEPRECATE /MTd /nologo /DHAVE_CONFIG_H $(ALL_INCLUDES) /D_WIN32_WINNT=0x0502 /DWIN32_LEAN_AND_MEAN $(OPENSSL_DEF) $(ZLIB_DEF) $(MINIDRIVER_DEF) $(SM_DEF) /DOPENSC_FEATURES="\"$(OPENSC_FEATURES)\"" /DDEBUG /Zi /Od
!ELSE
LINKDEBUGFLAGS = /NODEFAULTLIB:LIBCMTD
COPTS =  /W3 /D_CRT_SECURE_NO_DEPRECATE /MT /nologo /DHAVE_CONFIG_H $(ALL_INCLUDES) /D_WIN32_WINNT=0x0502 /DWIN32_LEAN_AND_MEAN $(OPENSSL_DEF) $(ZLIB_DEF) $(MINIDRIVER_DEF) $(SM_DEF) /DOPENSC_FEATURES="\"$(OPENSC_FEATURES)\""
!ENDIF


!IF "$(BUILD_FOR)" == "WIN64"
LINKFLAGS = /NOLOGO /INCREMENTAL:NO /MACHINE:X64 /MANIFEST:NO /NODEFAULTLIB:MSVCRTD  /NODEFAULTLIB:MSVCRT $(LINKDEBUGFLAGS)
LIBFLAGS =  /nologo /machine:x64
CANDLEFLAGS = -dPlatform=x64
!ELSE
LINKFLAGS = /NOLOGO /INCREMENTAL:NO /MACHINE:X86 /MANIFEST:NO /NODEFAULTLIB:MSVCRTD  /NODEFAULTLIB:MSVCRT $(LINKDEBUGFLAGS)
LIBFLAGS =  /nologo /machine:x86
CANDLEFLAGS = -dPlatform=x86
!ENDIF
.c.obj::
	cl $(CODE_OPTIMIZATION) $(COPTS) /c $<

.cpp.obj::
	cl $(CODE_OPTIMIZATION) $(COPTS) /c $<

.rc.res::
	rc /l 0x0409 $<

clean::
	del /Q *.obj *.dll *.exe *.pdb *.lib *.def *.manifest *.res
