COPTS = /Zi /ML /nologo /DHAVE_CONFIG_H /DVERSION=\"0.7.0\" /I$(TOPDIR)\src\include 
LINKFLAGS = /DEBUG /NOLOGO /INCREMENTAL:NO /MACHINE:IX86


install-headers:
	@for %i in ( $(HEADERS) ) do \
		@xcopy /d /q /y %i $(HEADERSDIR) > nul

.c.obj::
	cl $(COPTS) /c $<

