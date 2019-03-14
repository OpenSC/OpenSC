TOPDIR = ..

SUBDIRS = common scconf ui sm pkcs15init \
		  libopensc pkcs11 tools

default: all

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

!IF "$(MINIDRIVER_DEF)" == "/DENABLE_MINIDRIVER"
SUBDIRS = $(SUBDIRS) minidriver
!ENDIF

!IF "$(SM_DEF)" == "/DENABLE_SM"
SUBDIRS = $(SUBDIRS) smm
!ENDIF

!IF "$(TESTS_DEF)" == "/DENABLE_TESTS"
SUBDIRS = $(SUBDIRS) tests
!ENDIF

all::
	copy /y common\compat_getopt.h getopt.h
	@for %i in ( $(SUBDIRS) ) do \
		@cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"

clean::
	@for %i in ( $(SUBDIRS) ) do \
		@cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
	del /Q getopt.h
