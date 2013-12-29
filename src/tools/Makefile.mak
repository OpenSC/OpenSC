TOPDIR = ..\..

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

TARGETS = opensc-tool.exe opensc-explorer.exe pkcs15-tool.exe pkcs15-crypt.exe \
		pkcs11-tool.exe cardos-tool.exe eidenv.exe sc-hsm-tool.exe openpgp-tool.exe dnie-tool.exe \
		$(PROGRAMS_OPENSSL)

$(TARGETS): versioninfo-tools.res util.obj

all: $(TARGETS)

.c.obj:
	cl $(COPTS) /c $<

.c.exe:
	cl $(COPTS) /c $<
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj util.obj ..\common\common.lib \
	..\scconf\scconf.lib ..\libopensc\opensc.lib ..\pkcs15init\pkcs15init.lib \
	..\common\libpkcs11.lib ..\common\libscdl.lib versioninfo-tools.res $(OPENSSL_LIB) gdi32.lib
		if EXIST $@.manifest mt -manifest $@.manifest -outputresource:$@;1
