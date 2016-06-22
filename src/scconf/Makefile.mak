TOPDIR = ..\..

TARGET = scconf.lib
OBJECTS = scconf.obj parse.obj write.obj sclex.obj

.SUFFIXES : .l

all: $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS)
	lib $(LIBFLAGS) /out:$(TARGET) $(OBJECTS)
