
SUBDIRS = include common scconf libopensc tests scrandom pkcs15init tools pkcs11

all::

all depend install clean::
	@for %i in ( $(SUBDIRS) ) do \
        	@cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
