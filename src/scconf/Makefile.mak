TOPDIR = ..\..

TARGET = scconf.lib
HEADERS = scconf.h
HEADERSDIR = $(TOPDIR)\src\include\opensc
OBJECTS = scconf.obj parse.obj write.obj sclex.obj

.SUFFIXES : .l

all: install-headers $(TARGET)

$(TARGET): $(OBJECTS) ..\common\common.lib
	lib /nologo /machine:ix86 /out:$(TARGET) $(OBJECTS) ..\common\common.lib

!INCLUDE $(TOPDIR)\win32\Make.rules.mak
