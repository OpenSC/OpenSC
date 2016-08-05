TOPDIR = ..\..

default: all

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

TARGETS = opensc-tool.exe opensc-explorer.exe pkcs15-tool.exe pkcs15-crypt.exe \
		pkcs11-tool.exe cardos-tool.exe eidenv.exe openpgp-tool.exe iasecc-tool.exe \
		$(PROGRAMS_OPENSSL)

OBJECTS = util.obj versioninfo-tools.res
LIBS = $(TOPDIR)\src\common\common.lib \
	   $(TOPDIR)\src\scconf\scconf.lib \
	   $(TOPDIR)\src\libopensc\opensc.lib \
	   $(TOPDIR)\src\pkcs15init\pkcs15init.lib \
	   $(TOPDIR)\src\common\libpkcs11.lib \
	   $(TOPDIR)\src\common\libscdl.lib

all: $(TARGETS)

$(TARGETS): $(OBJECTS) $(LIBS)

.c.exe:
	cl $(COPTS) /c $<
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj $(OBJECTS) $(LIBS) $(OPENSSL_LIB) gdi32.lib shell32.lib
	if EXIST $@.manifest mt -manifest $@.manifest -outputresource:$@;1
