OPENSC_FEATURES = pcsc

#Include support for minidriver
MINIDRIVER_DEF = /DENABLE_MINIDRIVER

#Build MSI with the Windows Installer XML (WIX) toolkit, requires WIX >= 3.14
WIX_INCL_DIR = "/I$(WIX)\SDK\VS2017\inc"
WIX_LIBS = "$(WIX)\SDK\VS2017\lib\$(PLATFORM)\dutil.lib" "$(WIX)\SDK\VS2017\lib\$(PLATFORM)\wcautil.lib"

# We do not build tests on windows
#TESTS_DEF = /DENABLE_TESTS

#Include support for Secure Messaging
SM_DEF = /DENABLE_SM

#Build with debugging support
#DEBUG_DEF = /DDEBUG

!IF "$(BUILD_TYPE)" == ""
!IF "$(DEBUG_DEF)" == "/DDEBUG"
BUILD_TYPE = MTd
!ELSE
BUILD_TYPE = MT
!ENDIF
!ENDIF

# If you want support for OpenSSL (needed for pkcs15-init tool, software hashing in PKCS#11 library and verification):
# - download and build OpenSSL
# - uncomment the line starting with OPENSSL_DEF
# - set the OPENSSL_INCL_DIR below to your openssl include directory, preceded by "/I"
# - set the OPENSSL_LIB below to your openssl lib file
#OPENSSL_DEF= /DENABLE_OPENSSL
!IF "$(OPENSSL_DEF)" == "/DENABLE_OPENSSL"
!IF "$(OPENSSL_DIR)" == ""
!IF "$(PLATFORM)" == "x86"
OPENSSL_DIR = C:\OpenSSL-Win32
!ELSE
OPENSSL_DIR = C:\OpenSSL-Win64
!ENDIF
!ENDIF
OPENSSL_INCL_DIR = /I$(OPENSSL_DIR)\include

!IF "$(OPENSSL_LIB)" == ""
!IF "$(OPENSSL_VER)" == "1.1.1"
!IF "$(PLATFORM)" == "x86"
OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\static\libcrypto32$(BUILD_TYPE).lib
!ELSE
OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\static\libcrypto64$(BUILD_TYPE).lib
!ENDIF
!ELSE
OPENSSL_LIB = $(OPENSSL_DIR)\lib\VC\$(PLATFORM)\$(BUILD_TYPE)\libcrypto_static.lib
!ENDIF
!ENDIF
OPENSSL_LIB = $(OPENSSL_LIB) user32.lib advapi32.lib crypt32.lib ws2_32.lib

PROGRAMS_OPENSSL = cryptoflex-tool.exe pkcs15-init.exe netkey-tool.exe piv-tool.exe \
	westcos-tool.exe sc-hsm-tool.exe dnie-tool.exe gids-tool.exe
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
!IF "$(OPENSSL_DEF)" == "/DENABLE_OPENSSL"
# Build only when OpenPACE and OpenSSL are available
PROGRAMS_OPENPACE = npa-tool.exe
!ENDIF
CANDLEFLAGS = -dOpenPACE="$(OPENPACE_DIR)" $(CANDLEFLAGS)
!ENDIF


# Used for MiniDriver
CPDK_INCL_DIR = "/IC:\Program Files (x86)\Windows Kits\10\Cryptographic Provider Development Kit\Include"

COPTS = /nologo /Zi /GS /W3 /WX /D_CRT_SECURE_NO_DEPRECATE /D_CRT_NONSTDC_NO_WARNINGS /DHAVE_CONFIG_H \
	/DWINVER=0x0601 /D_WIN32_WINNT=0x0601 /DWIN32_LEAN_AND_MEAN /DOPENSC_FEATURES="\"$(OPENSC_FEATURES)\"" \
	$(DEBUG_DEF) $(OPENPACE_DEF) $(OPENSSL_DEF) $(ZLIB_DEF) $(MINIDRIVER_DEF) $(SM_DEF) $(TESTS_DEF) $(OPENSSL_EXTRA_CFLAGS) \
	/I$(TOPDIR)\win32 /I$(TOPDIR)\src $(OPENPACE_INCL_DIR) $(OPENSSL_INCL_DIR) $(ZLIB_INCL_DIR) $(CPDK_INCL_DIR) $(WIX_INCL_DIR)
LINKFLAGS = /nologo /machine:$(PLATFORM) /INCREMENTAL:NO /NXCOMPAT /DYNAMICBASE /DEBUG /NODEFAULTLIB:MSVCRT /NODEFAULTLIB:MSVCRTD
LIBFLAGS =  /nologo /machine:$(PLATFORM)
CANDLEFLAGS = -arch $(PLATFORM) $(CANDLEFLAGS)

!IF "$(DEBUG_DEF)" == "/DDEBUG"
LINKFLAGS = $(LINKFLAGS) /NODEFAULTLIB:LIBCMT
COPTS = /Od /$(BUILD_TYPE) $(COPTS)
!ELSE
LINKFLAGS = $(LINKFLAGS) /NODEFAULTLIB:LIBCMTD /OPT:REF /OPT:ICF
COPTS = /O1 /$(BUILD_TYPE) $(COPTS)
!ENDIF

.c.obj::
	cl $(COPTS) /c $<

.cpp.obj::
	cl $(COPTS) /c $<

.rc.res::
	rc /l 0x0409 $<

clean::
	del /Q *.obj *.dll *.exe *.pdb *.lib *.def *.res
