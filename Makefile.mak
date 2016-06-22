SUBDIRS = etc win32 src

default: all

all clean::
	@for %i in ( $(SUBDIRS) ) do @cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
