TOPDIR = ..\..

HEADERS = scdl.h
HEADERSDIR = $(TOPDIR)\src\include\opensc
TARGET = scdl.lib
OBJECTS = scdl.obj


all: install-headers $(TARGET)

$(TARGET): $(OBJECTS)
	lib /nologo /machine:ix86 /out:$(TARGET) $(OBJECTS) advapi32.lib

!INCLUDE $(TOPDIR)\win32\Make.rules.mak
