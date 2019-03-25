SUBDIRS = etc win32 src

default: all

32:
	CALL "C:\Program Files\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x86
	$(MAKE) /f Makefile.mak opensc.msi PLATFORM=x86 OPENPACE_DIR=C:\openpace-Win32_1.0.2
	MOVE win32\OpenSC.msi OpenSC_win32.msi

64:
	CALL "C:\Program Files\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x86_amd64
	$(MAKE) /f Makefile.mak opensc.msi OPENPACE_DIR=C:\openpace-Win64_1.0.2
	MOVE win32\OpenSC.msi OpenSC_win64.msi

opensc.msi:
	$(MAKE) /f Makefile.mak all OPENSSL_DEF=/DENABLE_OPENSSL OPENPACE_DEF=/DENABLE_OPENPACE"
	@cmd /c "cd win32 && $(MAKE) /nologo /f Makefile.mak opensc.msi OPENSSL_DEF=/DENABLE_OPENSSL OPENPACE_DEF=/DENABLE_OPENPACE"

all clean::
	@for %i in ( $(SUBDIRS) ) do @cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
