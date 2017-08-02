TOPDIR = ..\..

default: all

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

TARGETS = opensc-tool.exe opensc-explorer.exe pkcs15-tool.exe pkcs15-crypt.exe \
		pkcs11-tool.exe cardos-tool.exe eidenv.exe openpgp-tool.exe iasecc-tool.exe \
		opensc-notify.exe \
		$(PROGRAMS_OPENSSL)

OBJECTS = util.obj npa-tool-cmdline.obj fread_to_eof.obj versioninfo-tools.res

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
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj opensc-notify-cmdline.obj versioninfo-opensc-notify.res $(LIBS) $(OPENPACE_LIB) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib
	mt -manifest exe.manifest -outputresource:$@;1

.c.exe:
	cl $(COPTS) /c $<
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj $(OBJECTS) $(LIBS) $(OPENPACE_LIB) $(OPENSSL_LIB) gdi32.lib shell32.lib User32.lib ws2_32.lib
	mt -manifest exe.manifest -outputresource:$@;1
