TOPDIR = ..\..\..

TARGETS = asn1 compression pkcs15filter check_macro_reference_loop

OBJECTS = asn1.obj \
	compression.obj \
	pkcs15-emulator-filter.obj \
	check_macro_reference_loop.obj
	$(TOPDIR)\win32\versioninfo.res

all: $(TARGETS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGETS): $(OBJECTS) $(LIBS)

.c.exe:
	cl $(COPTS) /c $<
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj $(OBJECTS) $(LIBS)
	if EXIST $@.manifest mt -manifest $@.manifest -outputresource:$@;1
