TOPDIR = ..\..

TARGET = scconf.lib
HEADERS = scconf.h
HEADERSDIR = $(TOPDIR)\src\include\opensc
OBJECTS = parse.obj scconf.obj write.obj lex-parse-win32.obj

.SUFFIXES : .l

all: install-headers $(TARGET)

lex-parse-win32.c: lex-parse.l
	flex -olex-parse-win32.c < lex-parse.l
                
$(TARGET): $(OBJECTS)
	lib /nologo /machine:ix86 /out:$(TARGET) $(OBJECTS)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak
