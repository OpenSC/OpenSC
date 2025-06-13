TOPDIR = ..\..

default: all

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

TARGETS = opensc-tool.exe opensc-explorer.exe pkcs15-tool.exe pkcs15-crypt.exe \
		pkcs11-tool.exe cardos-tool.exe eidenv.exe openpgp-tool.exe iasecc-tool.exe \
		opensc-notify.exe egk-tool.exe goid-tool.exe dtrust-tool.exe \
		opensc-asn1.exe pkcs11-register.exe $(PROGRAMS_OPENSSL) $(PROGRAMS_OPENPACE)

OBJECTS = util.obj versioninfo-tools.res

LIBS = $(TOPDIR)\src\common\common.lib \
	   $(TOPDIR)\src\scconf\scconf.lib \
	   $(TOPDIR)\src\libopensc\opensc.lib \
	   $(TOPDIR)\src\pkcs15init\pkcs15init.lib \
	   $(TOPDIR)\src\common\libpkcs11.lib \
	   $(TOPDIR)\src\common\libscdl.lib

all: $(TARGETS)

$(TARGETS): $(OBJECTS) $(LIBS)

opensc-notify.exe: opensc-notify-cmdline.obj versioninfo-opensc-notify.res $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /out:$@ $*.obj opensc-notify-cmdline.obj versioninfo-opensc-notify.res $(LIBS) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

npa-tool.exe: npa-tool-cmdline.obj fread_to_eof.obj $(OBJECTS) $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /out:$@ $*.obj npa-tool-cmdline.obj fread_to_eof.obj $(OBJECTS) $(LIBS) $(OPENPACE_LIB) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

egk-tool.exe: egk-tool-cmdline.obj $(OBJECTS) $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /out:$@ $*.obj egk-tool-cmdline.obj $(OBJECTS) $(LIBS) $(ZLIB_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

goid-tool.exe: goid-tool-cmdline.obj fread_to_eof.obj $(OBJECTS) $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /out:$@ $*.obj goid-tool-cmdline.obj fread_to_eof.obj $(OBJECTS) $(LIBS) $(OPENPACE_LIB) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

opensc-asn1.exe: opensc-asn1-cmdline.obj fread_to_eof.obj versioninfo-tools.res $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /out:$@ $*.obj opensc-asn1-cmdline.obj fread_to_eof.obj versioninfo-tools.res $(LIBS) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

pkcs11-register.exe: pkcs11-register-cmdline.obj fread_to_eof.obj $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /out:$@ $*.obj pkcs11-register-cmdline.obj fread_to_eof.obj versioninfo-tools.res $(LIBS) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

pkcs15-tool.exe: pkcs15-tool.obj $(TOPDIR)\src\pkcs11\pkcs11-display.obj
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /out:$@ $*.obj $(TOPDIR)\src\pkcs11\pkcs11-display.obj $(OBJECTS) $(LIBS) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

openpgp-tool.exe: openpgp-tool-helpers.obj $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /out:$@ $*.obj openpgp-tool-helpers.obj $(OBJECTS) $(LIBS) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

sc-hsm-tool.exe: sc-hsm-tool.obj fread_to_eof.obj $(OBJECTS) $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /out:$@ $*.obj sc-hsm-tool.obj fread_to_eof.obj $(OBJECTS) $(LIBS) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib

pkcs11-tool.exe: pkcs11-tool.obj pkcs11_uri.obj $(OBJECTS) $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj pkcs11-tool.obj pkcs11_uri.obj $(OBJECTS) $(LIBS) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

.c.exe:
	cl $(COPTS) /c $<
	link $(LINKFLAGS) /out:$@ $*.obj $(OBJECTS) $(LIBS) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib
