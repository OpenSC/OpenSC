TOPDIR = ..\..

TARGET = scconf.lib
HEADERS = scconf.h
HEADERSDIR = $(TOPDIR)\src\include\opensc
OBJECTS = parse.obj scconf.obj write.obj lex-parse.obj

.SUFFIXES : .l

all: install-headers $(TARGET)

lex-parse.c: lex-parse.l
	flex -olex-parse.c < lex-parse.l
                
$(TARGET): $(OBJECTS)
	lib /nologo /machine:ix86 /out:$(TARGET) $(OBJECTS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak
