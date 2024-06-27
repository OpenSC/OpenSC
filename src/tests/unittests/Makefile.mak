TOPDIR = ..\..\..

TARGETS = asn1 compression pkcs15filter check_macro_reference_loop strip_pkcs1_2_padding

OBJECTS = asn1.obj \
	compression.obj \
	pkcs15-emulator-filter.obj \
	check_macro_reference_loop.obj \
	strip_pkcs1_2_padding.obj \
	$(TOPDIR)\src\tests\tests.res

all: $(TARGETS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGETS): $(OBJECTS) $(LIBS)

.c.exe:
	cl $(COPTS) /c $<
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj $(OBJECTS) $(LIBS)
