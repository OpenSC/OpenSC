
PLUGIN_DEFINES=-DXP_UNIX -I/usr/include/mozilla -I/usr/include/mozilla/java

CC= gcc
OPTIMIZER= -g
CFLAGS=-Wall $(OPTIMIZER) $(PLUGIN_DEFINES)
LDFLAGS=-lopensc -lcrypto

SRC= signer.c stubs.c opensc-crypto.c opensc-support.c
OBJ= signer.o stubs.o opensc-crypto.o opensc-support.o

SHAREDTARGET=signer.so

default all: $(SHAREDTARGET) testprog

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

testprog: $(OBJ) testprog.o opensc-crypto.o opensc-support.o
	gcc -Wall -g -o testprog testprog.o opensc-crypto.o opensc-support.o -lopensc -lcrypto -ldl
