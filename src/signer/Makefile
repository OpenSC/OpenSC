
PLUGIN_DEFINES=-DXP_UNIX -I/usr/include/mozilla -I/usr/include/mozilla/java

CC= gcc
OPTIMIZER= -g
CFLAGS=-Wall $(OPTIMIZER) $(PLUGIN_DEFINES)

SRC= signer.c stubs.c 
OBJ= signer.o stubs.o

SHAREDTARGET=signer.so

default all: $(SHAREDTARGET)

$(SHAREDTARGET): $(OBJ)
	$(CC) -shared -o $(SHAREDTARGET) $(OBJ) $(LDFLAGS)

signer.o: signer.c
	$(CC) -c $(CFLAGS) signer.c

stubs.o: stubs.c
	$(CC) -c $(CFLAGS) stubs.c

clean:
	$(RM) $(OBJ) $(SHAREDTARGET)

test:
	.do cp $(SHAREDTARGET) /usr/lib/mozilla/plugins
	.do cp $(SHAREDTARGET) /usr/lib/netscape/plugins-libc6
