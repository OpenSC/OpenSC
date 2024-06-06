TOPDIR = ..\..

default: all

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

TARGETS = opensc-tool.exe opensc-explorer.exe pkcs15-tool.exe pkcs15-crypt.exe \
		pkcs11-tool.exe cardos-tool.exe eidenv.exe openpgp-tool.exe iasecc-tool.exe \
		opensc-notify.exe egk-tool.exe goid-tool.exe dtrust-tool paccess-tool.exe \
		opensc-asn1.exe pkcs11-register.exe $(PROGRAMS_OPENSSL) $(PROGRAMS_OPENPACE)

OBJECTS = util.obj tools.res

LIBS = $(TOPDIR)\src\common\common.lib \
	   $(TOPDIR)\src\scconf\scconf.lib \
	   $(TOPDIR)\src\libopensc\opensc.lib \
	   $(TOPDIR)\src\pkcs15init\pkcs15init.lib \
	   $(TOPDIR)\src\common\libpkcs11.lib \
	   $(TOPDIR)\src\common\libscdl.lib

all: $(TARGETS)

$(TARGETS): $(OBJECTS) $(LIBS)

opensc-notify.exe: opensc-notify-cmdline.obj opensc-notify-x.res $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj opensc-notify-cmdline.obj opensc-notify-x.res $(LIBS) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

npa-tool.exe: npa-tool-cmdline.obj fread_to_eof.obj $(OBJECTS) $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj npa-tool-cmdline.obj fread_to_eof.obj $(OBJECTS) $(LIBS) $(OPENPACE_LIB) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

egk-tool.exe: egk-tool-cmdline.obj $(OBJECTS) $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj egk-tool-cmdline.obj $(OBJECTS) $(LIBS) $(ZLIB_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

goid-tool.exe: goid-tool-cmdline.obj fread_to_eof.obj $(OBJECTS) $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj goid-tool-cmdline.obj fread_to_eof.obj $(OBJECTS) $(LIBS) $(OPENPACE_LIB) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

opensc-asn1.exe: opensc-asn1-cmdline.obj fread_to_eof.obj tools.res $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj opensc-asn1-cmdline.obj fread_to_eof.obj tools.res $(LIBS) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

pkcs11-register.exe: pkcs11-register-cmdline.obj fread_to_eof.obj tools.res $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj pkcs11-register-cmdline.obj fread_to_eof.obj tools.res $(LIBS) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

pkcs15-tool.exe: pkcs15-tool.obj tools.res $(TOPDIR)\src\pkcs11\pkcs11-display.obj
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj $(TOPDIR)\src\pkcs11\pkcs11-display.obj $(OBJECTS) $(LIBS) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

openpgp-tool.exe: openpgp-tool-helpers.obj tools.res $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj openpgp-tool-helpers.obj $(OBJECTS) $(LIBS) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib

sc-hsm-tool.exe: sc-hsm-tool.obj fread_to_eof.obj $(OBJECTS) $(LIBS)
	cl $(COPTS) /c $*.c
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj sc-hsm-tool.obj fread_to_eof.obj $(OBJECTS) $(LIBS) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib

.c.exe:
	cl $(COPTS) /c $<
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj $(OBJECTS) $(LIBS) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib shlwapi.lib
