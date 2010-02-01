TOPDIR = ..

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

SUBDIRS = include common scconf pkcs15init libopensc pkcs11 tools tests 

all::

all depend install clean::
	@for %i in ( $(SUBDIRS) ) do \
        	@cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
