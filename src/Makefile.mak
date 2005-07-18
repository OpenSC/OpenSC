TOPDIR = ..

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

SUBDIRS = include common scconf scdl libopensc tests pkcs15init pkcs11 tools $(LIBP11_DIR) $(OPENSSL_ENGINES_DIR)

all::

all depend install clean::
	@for %i in ( $(SUBDIRS) ) do \
        	@cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
