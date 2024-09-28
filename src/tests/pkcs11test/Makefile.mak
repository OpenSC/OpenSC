TOPDIR = ..\..\..

TARGETS = pkcs11test

OBJECTS = pkcs11test.obj \
	pkcs11test_common.obj \
	pkcs11test_func.obj \
	pkcs11test_params_check.obj \
	pkcs11test_params_parse.obj \
	pkcs11test_process.obj \
	pkcs11test_prop_check.obj \
	pkcs11test_prop_parse.obj \
	pkcs11test_str.obj \
	pkcs11test_value_check.obj \
	pkcs11test_value_getter.obj \
	$(TOPDIR)\win32\versioninfo.res

all: $(TARGETS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGETS): $(OBJECTS) $(LIBS)

.c.exe:
	cl $(COPTS) /c $<
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj $(OBJECTS) $(LIBS)
	if EXIST $@.manifest mt -manifest $@.manifest -outputresource:$@;1
