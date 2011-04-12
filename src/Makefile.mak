TOPDIR = ..

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

SUBDIRS = common scconf pkcs15init libopensc pkcs11 tools tests

!IF "$(MINIDRIVER_DEF)" == "/DENABLE_MINIDRIVER"
SUBDIRS = $(SUBDIRS) minidriver
!ENDIF

all::

all depend install clean::
	@for %i in ( $(SUBDIRS) ) do \
		@cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
		
