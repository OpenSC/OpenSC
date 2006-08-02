TOPDIR = ..\..

HEADERS = my_getopt.h strlcpy.h
HEADERSDIR = $(TOPDIR)\src\include
TARGET = common.lib
OBJECTS = getpass.obj my_getopt.obj strlcpy.obj

all: install-headers $(TARGET)

$(TARGET): $(OBJECTS)
	lib /nologo /machine:ix86 /out:$(TARGET) $(OBJECTS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

