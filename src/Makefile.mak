
SUBDIRS = include common scconf scdl libopensc tests scrandom pkcs15init pkcs11 tools

all::

all depend install clean::
	@for %i in ( $(SUBDIRS) ) do \
        	@cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
