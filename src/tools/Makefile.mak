
TOPDIR = ..\..

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

TARGETS = opensc-explorer.exe opensc-tool.exe \
	  piv-tool.exe \
	  pkcs15-tool.exe pkcs15-crypt.exe pkcs11-tool.exe cardos-info.exe eidenv.exe $(PKCS15_INIT) 

all: util.obj $(TARGETS)

.c.obj:
	cl $(COPTS) /c $<

.c.exe:
	cl $(COPTS) /c $<
        link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj util.obj \
        ..\common\common.lib ..\scconf\scconf.lib ..\libopensc\opensc.lib \
        ..\pkcs15init\pkcs15init.lib ..\pkcs11\libpkcs11.lib \
        $(TOPDIR)\win32\version.res $(OPENSSL_LIB) $(LIBLTDL) gdi32.lib
