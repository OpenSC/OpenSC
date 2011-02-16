
OPENSC_FEATURES = pcsc

#Uncomment to use 'static' linking mode
LINK_MODE = STATIC

#Include support of minidriver 'cardmon'
MINIDRIVER_DEF = /DENABLE_MINIDRIVER


#Build MSI with the Windows Installer XML (WIX), minimal WIX version 3.6
#Static link mode should be used.
#WIX_MSI_DEF = /DBUILD_MSI
!IF "$(WIX_MSI_DEF)" == "/DBUILD_MSI"
WIX_INSTALLED_PATH = c:\download\wix36-binaries
LINK_MODE = STATIC
!ENDIF


# If you want support for OpenSSL (needed for pkcs15-init tool, software hashing in PKCS#11 library and verification):
# - download and build OpenSSL
# - uncomment the line starting with OPENSSL_DEF
# - set the OPENSSL_INCL_DIR below to your openssl include directory, preceded by "/I"
# - set the OPENSSL_LIB below to your openssl lib file
#OPENSSL_DEF = /DENABLE_OPENSSL
!IF "$(OPENSSL_DEF)" == "/DENABLE_OPENSSL"
OPENSSL_INCL_DIR = /IC:\openssl\include

!IF "$(LINK_MODE)" != "STATIC"
OPENSSL_LIB = C:\openssl\out32dll\libeay32.lib
#OPENSSL_LIB = C:\openssl\lib\VC\libeay32MD.lib C:\openssl\lib\VC\ssleay32MD.lib user32.lib advapi32.lib
!ENDIF
!IF "$(LINK_MODE)" == "STATIC"
#OPENSSL_LIB = C:\openssl\lib\VC\static\libeay32MT.lib C:\openssl\lib\VC\static\ssleay32MT.lib user32.lib advapi32.lib
!ENDIF

PROGRAMS_OPENSSL = pkcs15-init.exe cryptoflex-tool.exe netkey-tool.exe piv-tool.exe westcos-tool.exe
OPENSC_FEATURES = $(OPENSC_FEATURES) openssl
!ENDIF


# If you want support for zlib (Used for PIV, infocamere and actalis):
# - Download zlib and build
# - uncomment the line starting with ZLIB_DEF 
# - set the ZLIB_INCL_DIR below to the zlib include lib proceeded by "/I"
# - set the ZLIB_LIB  below to your zlib lib file
#ZLIB_DEF = /DENABLE_ZLIB
!IF "$(ZLIB_DEF)" == "/DENABLE_ZLIB"
ZLIB_INCL_DIR = /IC:\ZLIB\INCLUDE
ZLIB_LIB = C:\ZLIB\LIB\zlib.lib 
OPENSC_FEATURES = $(OPENSC_FEATURES) zlib
!ENDIF

# Used for MiniDriver
CNGSDK_INCL_DIR = "/IC:\Program Files\Microsoft CNG Development Kit\Include"

# Mandatory path to 'ISO C9x compliant stdint.h and inttypes.h for Microsoft Visual Studio'
# http://msinttypes.googlecode.com/files/msinttypes-r26.zip
# INTTYPES_INCL_DIR =  /IC:\opensc\dependencies\msys\local

ALL_INCLUDES = /I$(TOPDIR)\win32 /I$(TOPDIR)\src $(OPENSSL_INCL_DIR) $(ZLIB_INCL_DIR) $(LIBLTDL_INCL) $(INTTYPES_INCL_DIR) $(CNGSDK_INCL_DIR)
!IF "$(LINK_MODE)" != "STATIC"
COPTS = /D_CRT_SECURE_NO_DEPRECATE /Zi /MD /nologo /DHAVE_CONFIG_H $(ALL_INCLUDES) /D_WIN32_WINNT=0x0400 /DWIN32_LEAN_AND_MEAN $(OPENSSL_DEF) $(ZLIB_DEF) /DOPENSC_FEATURES="\"$(OPENSC_FEATURES)\""
LINKFLAGS = /DEBUG /NOLOGO /INCREMENTAL:NO /MACHINE:IX86
!ENDIF

!IF "$(LINK_MODE)" == "STATIC"
COPTS =  /D_CRT_SECURE_NO_DEPRECATE /MT /nologo /DHAVE_CONFIG_H $(ALL_INCLUDES) /D_WIN32_WINNT=0x0400 /DWIN32_LEAN_AND_MEAN $(OPENSSL_DEF) $(ZLIB_DEF) /DOPENSC_FEATURES="\"$(OPENSC_FEATURES)\""
LINKFLAGS =  /NOLOGO /INCREMENTAL:NO /MACHINE:IX86 /MANIFEST:NO /NODEFAULTLIB:MSVCRTD  /NODEFAULTLIB:MSVCRT /NODEFAULTLIB:LIBCMTD
!ENDIF

.c.obj::
	cl $(COPTS) /c $<

.rc.res::
	rc /l 0x0409 /r $<

clean::
	del /Q *.obj *.dll *.exe *.pdb *.lib *.def *.manifest
