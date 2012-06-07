
SUBDIRS = etc win32 src

all::

all depend install clean::
	@for %i in ( $(SUBDIRS) ) do @cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
