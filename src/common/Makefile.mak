TOPDIR = ..\..

HEADERS = getopt.h
TARGET = common.lib
OBJECTS = getopt.obj getopt1.obj getpass.obj


all: $(TARGET) install-headers

$(TARGET): $(OBJECTS)
	lib /nologo /machine:ix86 /out:$(TARGET) $(OBJECTS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

