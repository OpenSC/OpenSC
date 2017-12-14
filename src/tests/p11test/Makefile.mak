TOPDIR = ..\..\..

TARGETS = p11test.exe

OBJECTS = p11test_loader.obj \
	p11test_case_common.obj \
	p11test_case_readonly.obj \
	p11test_case_multipart.obj \
	p11test_case_mechs.obj \
	p11test_case_ec_sign.obj \
	p11test_case_usage.obj \
	p11test_case_wait.obj \
	p11test_case_pss_oaep.obj \
	p11test_helpers.obj \
	$(TOPDIR)\win32\versioninfo.res

all: $(TARGETS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGETS): $(OBJECTS) $(LIBS)

.c.exe:
	cl $(COPTS) /c $<
	link $(LINKFLAGS) /pdb:$*.pdb /out:$@ $*.obj $(OBJECTS) $(LIBS)
	if EXIST $@.manifest mt -manifest $@.manifest -outputresource:$@;1
