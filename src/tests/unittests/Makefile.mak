TOPDIR = ..\..\..

default: all

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

TARGETS = asn1.exe base64.exe check_macro_reference_loop.exe decode_ecdsa_signature.exe \
	hextobin.exe openpgp-tool.exe parse_pkcs11_uri.exe pkcs15-emulator-filter.exe \
	simpletlv.exe strip_pkcs1_2_padding.exe pkcs15-tlv-record.exe

!IF "$(ZLIB_DEF)" == "/DENABLE_ZLIB"
TARGETS = $(TARGETS) compression.exe
!ENDIF

!IF "$(OPENSSL_DEF)" == "/DENABLE_OPENSSL"
TARGETS = $(TARGETS) sm.exe
!ENDIF

LIBS = $(TOPDIR)\src\libopensc\opensc_a.lib \
	   $(TOPDIR)\src\pkcs15init\pkcs15init.lib \
	   $(TOPDIR)\src\scconf\scconf.lib \
	   $(TOPDIR)\src\common\common.lib \
	   $(TOPDIR)\src\common\libscdl.lib \
	   $(TOPDIR)\src\ui\strings.lib \
	   $(TOPDIR)\src\ui\notify.lib \
	   $(TOPDIR)\src\sm\libsmiso.lib \
	   $(TOPDIR)\src\sm\libsmeac.lib
EXTRA_LIBS = $(CMOCKA_LIB) $(OPENPACE_LIB) $(OPENSSL_LIB) $(ZLIB_LIB) \
	gdi32.lib Shell32.lib user32.lib advapi32.lib ws2_32.lib shlwapi.lib

all: $(TARGETS)

$(TARGETS): $(LIBS)

openpgp-tool.exe: $(TOPDIR)\src\tools\openpgp-tool-helpers.obj
	cl $(COPTS) $(CMOCKA_CFLAGS) /c $*.c
	link $(LINKFLAGS) /out:$@ $*.obj $(TOPDIR)\src\tools\openpgp-tool-helpers.obj $(LIBS) $(EXTRA_LIBS)

sm.exe: $(TOPDIR)\src\sm\libsm.lib
	cl $(COPTS) $(CMOCKA_CFLAGS) /c $*.c
	link $(LINKFLAGS) /out:$@ $*.obj $(TOPDIR)\src\sm\libsm.lib $(LIBS) $(EXTRA_LIBS)

.c.exe:
	cl $(COPTS) $(CMOCKA_CFLAGS) /c $<
	link $(LINKFLAGS) /out:$@ $*.obj $(LIBS) $(EXTRA_LIBS)

check: all
	@for %i in ( $(TARGETS) ) do @( echo Running %i && %i || exit 1 )
