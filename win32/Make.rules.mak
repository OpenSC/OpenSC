# Note: these instructions obsolete the instructions in opensc.html

# You first need to download the gnuwin32 libtool (e.g. the "Binaries" and "Developer
# files" from http://gnuwin32.sourceforge.net/packages/libtool.htm)
# Then fill in the directory path to ltdl.h on the LIBLTDL_INCL line below, preceeded
# by an "/I"; and fill in the path to the libltdl.lib on the LIBLTDL_LIB line below.
# Then you can build this OpenSC package; and afterwards you'll need to copy the
# libltdl3.dll somewhere on your execution path.
LIBLTDL_INCL =    # E.g. /IC:\libtool-1.5.8-lib\include
LIBLTDL_LIB =     # E.g. C:\libtool-1.5.8-lib\lib\libltdl.lib

# If you want support for OpenSSL (needed for a.o. pkcs15-init tool and openssl engine):
# - download and build OpenSSL
# - uncomment the line starting with OPENSSL_DEF
# - set the OPENSSL_INCL_DIR below to your openssl include directory, preceded by "/I"
# - set the OPENSSL_LIB below to your openssl lib file
#OPENSSL_DEF = /DHAVE_OPENSSL
!IF "$(OPENSSL_DEF)" == "/DHAVE_OPENSSL"
OPENSSL_INCL_DIR = /IC:\openssl\include
OPENSSL_LIB = C:\openssl\out32dll\libeay32.lib
PKCS15_INIT = pkcs15-init.exe
!ENDIF

COPTS = /Zi /MD /nologo /DHAVE_CONFIG_H /I$(TOPDIR)\src\include /I$(TOPDIR)\src\include\opensc $(OPENSSL_INCL_DIR) $(LIBLTDL_INCL) /D_WIN32_WINNT=0x0400 $(OPENSSL_DEF)
LINKFLAGS = /DEBUG /NOLOGO /INCREMENTAL:NO /MACHINE:IX86


install-headers:
	@for %i in ( $(HEADERS) ) do \
		@xcopy /d /q /y %i $(HEADERSDIR) > nul

install-headers-dir:
	@for %i in ( $(HEADERSDIRFROM2) ) do \
		@xcopy /d /q /y %i\*.h $(HEADERSDIR2)\*.h > nul

.c.obj::
	cl $(COPTS) /c $<

clean::
	del /Q *.obj *.dll *.exe

