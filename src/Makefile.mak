TOPDIR = ..

SUBDIRS = common scconf libsm pkcs15init libopensc pkcs11 tools tests

default: all

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

!IF "$(MINIDRIVER_DEF)" == "/DENABLE_MINIDRIVER"
SUBDIRS = $(SUBDIRS) minidriver
!ENDIF

!IF "$(SM_DEF)" == "/DENABLE_SM"
SUBDIRS = $(SUBDIRS) smm
!ENDIF

all clean::
	@for %i in ( $(SUBDIRS) ) do \
		@cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
