TOPDIR = ..\..

HEADERS = scrandom.h
HEADERSDIR = $(TOPDIR)\src\include\opensc
TARGET = scrandom.lib
OBJECTS = scrandom.obj


all: install-headers $(TARGET)

$(TARGET): $(OBJECTS)
	lib /nologo /machine:ix86 /out:$(TARGET) $(OBJECTS) advapi32.lib

!INCLUDE $(TOPDIR)\win32\Make.rules.mak


