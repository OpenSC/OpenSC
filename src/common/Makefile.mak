TOPDIR = ..\..

HEADERS = getopt.h
HEADERSDIR = $(TOPDIR)\src\include
TARGET = common.lib
OBJECTS = getopt.obj getopt1.obj getpass.obj


all: install-headers $(TARGET)

$(TARGET): $(OBJECTS)
	lib /nologo /machine:ix86 /out:$(TARGET) $(OBJECTS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

