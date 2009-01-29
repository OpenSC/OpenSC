# Note: these instructions obsolete the instructions in opensc.html

# You first need to download the gnuwin32 libtool (e.g. the "Binaries" and "Developer
# files" from http://gnuwin32.sourceforge.net/packages/libtool.htm)
# Then fill in the directory path to ltdl.h on the LIBLTDL_INCL line below, preceeded
# by an "/I"; and fill in the path to the libltdl.lib on the LIBLTDL_LIB line below.
# Then you can build this OpenSC package; and afterwards you'll need to copy the
# libltdl3.dll somewhere on your execution path.
LIBLTDL_INCL =    # E.g. /IC:\libtool-1.5.8-lib\include
LIBLTDL_LIB =     # E.g. C:\libtool-1.5.8-lib\lib\libltdl.lib

OPENSC_FEATURES = pcsc

# If you want support for OpenSSL (needed for a.o. pkcs15-init tool and openssl engine):
# - download and build OpenSSL
# - uncomment the line starting with OPENSSL_DEF
# - set the OPENSSL_INCL_DIR below to your openssl include directory, preceded by "/I"
# - set the OPENSSL_LIB below to your openssl lib file
#OPENSSL_DEF = /DENABLE_OPENSSL
!IF "$(OPENSSL_DEF)" == "/DENABLE_OPENSSL"
OPENSSL_INCL_DIR = /IC:\openssl\include
OPENSSL_LIB = C:\openssl\out32dll\libeay32.lib
PROGRAMS_OPENSSL = pkcs15-init.exe cryptoflex-tool.exe netkey-tool.exe piv-tool.exe
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

# If you want support for iconv (Used for EstEID):
# - Download iconv and build
# - uncomment the line starting with ICONV_DEF 
# - set the ICONV_INCL_DIR below to the iconv include lib proceeded by "/I"
# - set the ICONV_LIB  below to your iconv lib file
#ICONV_DEF = /DENABLE_ICONV
!IF "$(ICONV_DEF)" == "/DENABLE_ICONV"
ICONV_INCL_DIR = /IC:\build\iconv\include
ICONV_LIB = C:\build\iconv\lib\iconv.lib
OPENSC_FEATURES = $(OPENSC_FEATURES) iconv
!ENDIF

COPTS = /D_CRT_SECURE_NO_DEPRECATE /Zi /MD /nologo /DHAVE_CONFIG_H /I$(TOPDIR)\src\include /I$(TOPDIR)\src\include\opensc /I$(TOPDIR)\src\common $(OPENSSL_INCL_DIR) $(ZLIB_INCL_DIR) $(LIBLTDL_INCL) $(ICONV_INCL_DIR) /D_WIN32_WINNT=0x0400 /DWIN32_LEAN_AND_MEAN $(OPENSSL_DEF) $(ZLIB_DEF) $(ICONV_DEF) /DOPENSC_FEATURES="\"$(OPENSC_FEATURES)\""
LINKFLAGS = /DEBUG /NOLOGO /INCREMENTAL:NO /MACHINE:IX86


install-headers:
	@for %i in ( $(HEADERS) ) do \
		@xcopy /d /q /y %i $(HEADERSDIR) > nul

install-headers-dir:
	@for %i in ( $(HEADERSDIRFROM2) ) do \
		@xcopy /d /q /y %i\*.h $(HEADERSDIR2)\*.h > nul

.c.obj::
	cl $(COPTS) /c $<

.rc.res::
	rc /l 0x0409 /r $<

clean::
	del /Q *.obj *.dll *.exe *.pdb *.lib *.def
