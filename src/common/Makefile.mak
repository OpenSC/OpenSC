TOPDIR = ..\..

HEADERS = compat_getpass.h compat_getopt.h compat_strlcpy.h simclist.h
HEADERSDIR = $(TOPDIR)\src\include
TARGET = common.lib
OBJECTS = compat_getpass.obj compat_getopt.obj compat_strlcpy.obj simclist.obj

all: install-headers $(TARGET)

$(TARGET): $(OBJECTS)
	lib /nologo /machine:ix86 /out:$(TARGET) $(OBJECTS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

