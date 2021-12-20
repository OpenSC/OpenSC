# Fuzzing

## Corpus semantics

The corpus files for the `fuzz_pkcs15_reader` are interpreted by the virtual
reader as follows:

 * first two bytes denote the block length N as unsigned integer. The endianness
   depends on the architecture
 * the following block of the length N

The first block is always the ATR of the card, which is very frequently used
for card detection.

All the other following blocks are used as replies from the emulated card.

Example block:
```
0f 00
 -- length indicator saying next block is 15 bytes long
3b f5 96 00 00 81 31 fe 45 4d 79 45 49 44 14
 -- the 15 bytes block (in this case ATR)

29 00
 -- the second block length of 41 bytes
6f 25 81 02 7f ff 82 01 38 83 02 50 15 86 03 11
1f ff 85 02 00 02 8a 01 01 84 0c a0 00 00 00 63
50 4b 43 53 2d 31 35 90 00
 -- 41 bytes data block (APDU response)
```

### How to generate corpus files from existing cards

Modify the `src/libopensc/reader-pcsc.c` and uncomment the following line:
```
#define APDU_LOG_FILE "apdulog"
```
and rebuild OpenSC. Then run any opensc tool talking to the card. For example
```
./src/tools/pkcs11-tool -L --module ./src/pkcs11/.libs/opensc-pkcs11.so
```
Any APDU returned from the card is now logged into the file `apdulog` in the
format expected by the `fuzz_pkcs15_reader`  fuzzer. It is also prefixed with
the ATR of the connected card as expected by the fuzzer. This file can be used
as a starting point which gets through the card detection, but does not go into
all the operations the fuzzer attempts later.

### The pkcs15init fuzzer

The pkcs15init fuzzer consist of two separate parts. The first one is parsing
of the profile file, which is separated from the rest of the input with a NULL
byte (0x00). The rest is interpreted as in case of the `fuzz_pkcs15_reader`.

When creating corpus for this fuzzer, stuff get more messy because:

 * The first part is the profile file
 * The `pkcs15-init` can do only one operation at time so we need to skip the
   card init when concatenating the APDU traces

So at first, erase the card and move away the apdulog:
```
./src/tools/pkcs15-init --erase-card --so-pin 12345678
$ mv apdulog /tmp/apdu_erase
```
Then prepare the separate files for each operation in the fuzzer:
```
$ ./src/tools/pkcs15-init -C --pin 123456 --puk 12345678 --so-pin 12345678 --so-puk 12345678
$ mv apdulog /tmp/apdu_create
$ ./src/tools/pkcs15-init -P -a 1 -l "Basic PIN" --pin 1234555678 --puk 12345678
$ mv apdulog /tmp/apdu_create_pin
$ ./src/tools/pkcs15-init --store-data /path/to/any_file --label label
$ mv apdulog /tmp/apdu_store_data
$ ./src/tools/pkcs15-init --generate-key rsa:1024 --auth-id 01 --so-pin 12345678 --pin 1234555678
$ mv apdulog /tmp/apdu_generate_rsa
$ ./src/tools/pkcs15-init --generate-key ec:prime256v1 --auth-id 01 --so-pin 12345678 --pin 123455678
$ mv apdulog /tmp/apdu_generate_ecdsa
$ ./src/tools/pkcs15-init -F
$ mv apdulog /tmp/apdu_finalize
```

Now, construct the corpus file:
* insert profile and zero byte as delimiter
* apdu create can be used as it is
* from apdu\_create_pin remove part for connecting card
* from apdu\_store_data remove some central parts, since testing data is smaller than data used in apdu
* apdu_generate_* and apdu\_finalize need to skip connecting card and `sc_pcks15_bind()`
* symmetric key generation is not supported on the card, lets fill that part with some dummy values from generating RSA keys
* apdu\_erase needs to skip part for connecting card

```
SKIP=1257
( \
  cat file.profile; printf "\x00"; \
  cat tmp/apdu_create; \
  dd if=tmp/apdu_create_pin bs=1 skip=421; \
  dd if=tmp/apdu_store_data bs=1 skip=1257 count=1675; \
  dd if=tmp/apdu_store_data bs=1 skip=3020; \
  dd if=tmp/apdu_generate_rsa bs=1 skip=$SKIP; \
  dd if=tmp/apdu_generate_ecdsa bs=1 skip=$SKIP; \
  dd if=tmp/apdu_generate_rsa bs=1 skip=$SKIP count=5304; \
  dd if=tmp/apdu_generate_rsa bs=1 skip=$SKIP count=5304; \
  dd if=tmp/apdu_generate_rsa bs=1 skip=$SKIP count=5304; \
  dd if=tmp/apdu_finalize bs=1 skip=$SKIP; \
  dd if=tmp/apdu_erase bs=1 skip=421; \
) > tmp/testcase
```

Now, lets try to feed the data into the fuzzer:
```
OPENSC_DEBUG=9 ./src/tests/fuzzing/fuzz_pkcs15init_profile /tmp/testcase
```
The debug log should show the card detection, which goes through and then some
pkcs15init operations.
