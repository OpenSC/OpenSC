TOPDIR = ..\..

TARGETS = base64.exe p15dump.exe \
	  p15dump.exe pintest.exe # prngtest.exe lottery.exe

OBJECTS = print.obj sc-test.obj $(TOPDIR)\win32\versioninfo.res
LIBS = $(TOPDIR)\src\common\common.lib $(TOPDIR)\src\libopensc\opensc.lib

all: $(TARGETS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGETS): $(OBJECTS) $(LIBS)

.c.exe:
	cl $(COPTS) /c $<
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj $(OBJECTS) $(LIBS)
	if EXIST $@.manifest mt -manifest $@.manifest -outputresource:$@;1
