
TOPDIR = ..\..

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

TARGETS = opensc-tool.exe opensc-explorer.exe pkcs15-tool.exe pkcs15-crypt.exe \
		pkcs11-tool.exe cardos-info.exe eidenv.exe rutoken-tool.exe \
		netkey-tool.exe westcos-tool.exe \
		$(PROGRAMS_OPENSSL)

all: $(TARGETS)

$(TARGETS):  versioninfo.res util.obj 

.c.obj:
	cl $(COPTS) /c $<

.c.exe:
	cl $(COPTS) /c $<
        link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj util.obj \
        ..\common\common.lib ..\scconf\scconf.lib ..\libopensc\opensc.lib \
        ..\pkcs15init\pkcs15init.lib ..\pkcs11\libpkcs11.lib \
        versioninfo.res $(OPENSSL_LIB) $(LIBLTDL) gdi32.lib
		if EXIST $@.manifest mt -manifest $@.manifest -outputresource:$@;1
