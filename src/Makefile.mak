
SUBDIRS = include common scconf libopensc tools tests scrandom pkcs15init pkcs11

all::

all depend install clean::
	@for %i in ( $(SUBDIRS) ) do \
        	@cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
