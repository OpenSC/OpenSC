SUBDIRS = etc win32 src

default: all

opensc.msi: all
	cd win32 && $(MAKE) /nologo /f Makefile.mak opensc.msi && cd ..

check: all
	cd src\tests\unittests && $(MAKE) /nologo /f Makefile.mak check && cd ..\..\..

all clean::
	@for %%i in ( $(SUBDIRS) ) do ( cd %%i && $(MAKE) /nologo /f Makefile.mak $@ && cd ..)
