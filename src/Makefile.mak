TOPDIR = ..

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

SUBDIRS = common scconf pkcs15init libopensc pkcs11 tools tests

!IF "$(MINIDRIVER_DEF)" == "/DENABLE_MINIDRIVER"
SUBDIRS = $(SUBDIRS) cardmod
!ENDIF

!IF "$(WIX_MSI_DEF)" == "/DBUILD_MSI"
SUBDIRS = $(SUBDIRS) "$(TOPDIR)\win32\opensc-msi"
!ENDIF

all::

all depend install clean::
	@for %i in ( $(SUBDIRS) ) do \
		@cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
		
