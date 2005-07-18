# If you want support for OpenSSL (needed for a.o. pkcs15-init tool and openssl engine):
# - download and build OpenSSL
# - uncomment the line starting with OPENSSL_DEF
# - set the OPENSSL_INCL_DIR below to your openssl include directory, preceded by "/I"
# - set the OPENSSL_LIB below to your openssl lib file
# Note: these instructions obsolete the instructions in opensc.html

#OPENSSL_DEF = /DHAVE_OPENSSL
!IF "$(OPENSSL_DEF)" == "/DHAVE_OPENSSL"
OPENSSL_INCL_DIR = /IC:\openssl\include
OPENSSL_LIB = C:\openssl\out32dll\libeay32.lib
LIBP11_DIR = libp11
OPENSSL_ENGINES_DIR = sslengines
PKCS15_INIT = pkcs15-init.exe
!ENDIF

COPTS = /Zi /MD /nologo /DHAVE_CONFIG_H /I$(TOPDIR)\src\include /I$(TOPDIR)\src\include\opensc $(OPENSSL_INCL_DIR) /D_WIN32_WINNT=0x0400 $(OPENSSL_DEF)
LINKFLAGS = /DEBUG /NOLOGO /INCREMENTAL:NO /MACHINE:IX86


install-headers:
	@for %i in ( $(HEADERS) ) do \
		@xcopy /d /q /y %i $(HEADERSDIR) > nul

install-headers-dir:
	@for %i in ( $(HEADERSDIRFROM2) ) do \
		@xcopy /d /q /y %i\*.h $(HEADERSDIR2)\*.h > nul

.c.obj::
	cl $(COPTS) /c $<

