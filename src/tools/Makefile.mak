
TOPDIR = ..\..

TARGETS = opensc-explorer.exe opensc-tool.exe \
	  pkcs15-tool.exe pkcs15-crypt.exe #pkcs15-init.exe 

all: util.obj $(TARGETS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

.c.obj:
	cl $(COPTS) /c $<

.c.exe:
	cl $(COPTS) /c $<
        link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj util.obj ..\common\common.lib ..\libopensc\opensc.lib

