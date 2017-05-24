TOPDIR = ..\..

TARGET = strings.lib
OBJECTS = strings.obj

TARGET2 = notify.lib
OBJECTS2 = notify.obj

all: $(TARGET) $(TARGET2)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS)
	lib $(LIBFLAGS) /out:$(TARGET) $(OBJECTS)

$(TARGET2): $(OBJECTS2)
	lib $(LIBFLAGS) /out:$(TARGET2) $(OBJECTS2)
