TOPDIR = ..

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

SUBDIRS = include common scconf libopensc tests pkcs15init pkcs11 tools

all::

all depend install clean::
	@for %i in ( $(SUBDIRS) ) do \
        	@cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
