TOPDIR = ..\..\..

TARGETS = asn1 compression pkcs15filter check_macro_reference_loop \
	strip_pkcs1_2_padding base64 parse_pkcs11_uri

OBJECTS = asn1.obj \
	compression.obj \
	pkcs15-emulator-filter.obj \
	check_macro_reference_loop.obj \
	strip_pkcs1_2_padding.obj \
	parse_pkcs11_uri.obj \
	$(TOPDIR)\win32\versioninfo.res

all: $(TARGETS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

# cmocka is available with the optional vcpkg "tests" feature.
CMOCKA_INCL_DIR = /I"$(VCPKG_DIR)\include"
!IF "$(BUILD_TYPE)" == "MTd"
CMOCKA_LIB = "$(VCPKG_DIR)\debug\lib\cmocka.lib"
!ELSE
CMOCKA_LIB = "$(VCPKG_DIR)\lib\cmocka.lib"
!ENDIF

OPENSC_LIB = $(TOPDIR)\src\libopensc\opensc.lib

# This header-only test does not need the legacy test objects or OpenSC libs.
check-pss: pkcs11-pss-params.exe
	.\pkcs11-pss-params.exe

pkcs11-pss-params.exe: pkcs11-pss-params.c torture.h \
	$(TOPDIR)\src\pkcs11\pkcs11-pss-params.h \
	$(TOPDIR)\src\pkcs11\pkcs11.h $(TOPDIR)\src\pkcs11\pd-pkcs11.h \
	$(TOPDIR)\win32\config.h $(CMOCKA_LIB)
	cl $(COPTS) /std:c11 $(CMOCKA_INCL_DIR) /c pkcs11-pss-params.c
	link $(LINKFLAGS) /out:$@ pkcs11-pss-params.obj $(CMOCKA_LIB)

check-tlv-record: pkcs15-tlv-record.exe
	.\pkcs15-tlv-record.exe

pkcs15-tlv-record.exe: pkcs15-tlv-record.c torture.h $(TOPDIR)\win32\config.h $(CMOCKA_LIB) $(OPENSC_LIB)
	cl $(COPTS) /std:c11 $(CMOCKA_INCL_DIR) /c pkcs15-tlv-record.c
	link $(LINKFLAGS) /out:$@ pkcs15-tlv-record.obj $(CMOCKA_LIB) $(OPENSC_LIB)

$(TARGETS): $(OBJECTS) $(LIBS)

.c.exe:
	cl $(COPTS) /c $<
	link $(LINKFLAGS) /out:$@ $*.obj $(OBJECTS) $(LIBS)
