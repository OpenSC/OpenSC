TOPDIR = ..

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

SUBDIRS = include common scconf scdl libopensc tests scrandom pkcs15init pkcs11 tools $(SSL_ENGINES_DIR)

all::

all depend install clean::
	@for %i in ( $(SUBDIRS) ) do \
        	@cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
