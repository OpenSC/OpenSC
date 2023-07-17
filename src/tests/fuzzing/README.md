# Fuzzing in OpenSC

OpenSC is part of the [OSS-Fuzz project](https://google.github.io/oss-fuzz/), which provides continuous fuzzing support for open-source projects.
Fuzzer [libFuzzer](https://llvm.org/docs/LibFuzzer.html) can be used for local testing.

To the terms used, _fuzzer_ refers to a program that injects malformed inputs to the system under test; _fuzz target_ is a program that accepts data buffer, processes it and passes the data to the tested interface.

## Building

### Building for fuzzing
Successful build of fuzz targets requires `./configure` run with correctly set CC, CFLAGS and FUZZING_LIBS. Note that some of the fuzz targets can be built only with the `--disable-shared` option.

Example configuration for libFuzzer:
```
./configure --disable-optimization --disable-shared --disable-pcsc --enable-ctapi --enable-fuzzing CC=clang CFLAGS=-fsanitize=fuzzer-no-link FUZZING_LIBS=-fsanitize=fuzzer
```

To add some of the LLVM Sanitizers, modify `FUZZING_LIBS`:
```
FUZZING_LIBS=-fsanitize=fuzzer,address,undefined
```
Sanitizers can also be modified by [flags](https://github.com/google/sanitizers/wiki/SanitizerCommonFlags).

### Building without fuzzing support
When fuzzing is not enabled explicitly by `--enable-fuzzing`, fuzz targets are built without fuzzing support. They can be used for local regression testing and accept one argument for filename with input for the testing functions.

Example of testing without fuzzing:
```
./fuzz_pkcs15_reader ./input_file
```

## Reproducing issues
Some of the issues are not reproducible when build outside of the fuzzing images. In that case, the safest
option is to reproduce them with the python/docker helpers provided by [oss-fuzz](https://github.com/google/oss-fuzz/).
You can build latest fuzzers in the oss-fuzz containers with the following steps:
```
python3 infra/helper.py pull_images
python3 infra/helper.py build_image opensc
python3 infra/helper.py build_fuzzers opensc
```
After that, you can download reproducer from the oss-fuzz dashboard and run it locally in the container:
```
python3 infra/helper.py reproduce opensc fuzz_pkcs15_decode /path/to/testcase
```

### Expanding incomplete backtraces
Sometimes the backtrace visible in the oss-fuzz dashboard is not useful, for example showing only part of the
trace ending inside of (outdated) openssl code:
```
Direct leak of 168 byte(s) in 1 object(s) allocated from:
	    #0 0x5318e6 in malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:69:3
	    #1 0x7faca8714c0d in CRYPTO_zalloc
```
In that case, you can use the address sanitizer option `fast_unwind_on_malloc=0` in `ASAN_OPTIONS` environment
variable to expand this trace, for example:
```
python3 infra/helper.py reproduce -eASAN_OPTIONS='fast_unwind_on_malloc=0' opensc fuzz_pkcs15_decode testcase
```

## Fuzzing
### libFuzzer
See libFuzzer [documentation](https://llvm.org/docs/LibFuzzer.html) for details.

Fuzzing with a predefined corpus can be run like this:
```
./fuzz_pkcs15_reader corpus/fuzz_pkcs15_reader
```
Newly generated input files are stored in the corpus directory.

By default, `stdout` is closed for fuzzing. However, some fuzz targets may output to `stderr`. You can suppress `stderr` with the `-close_fd_mask` option (see libFuzzer).

To execute the fuzz target on one input, try:
```
./fuzz_pkcs15_reader ./test-case
```

## Corpus

### Corpus for `fuzz_pkcs15_reader`

The corpus files for the `fuzz_pkcs15_reader` are interpreted by the virtual
reader as follows:

 * first two bytes denote the block length N as an unsigned integer. The endianness
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
and rebuild OpenSC. Then run any OpenSC tool talking to the card. For example
```
./src/tools/pkcs11-tool -L --module ./src/pkcs11/.libs/opensc-pkcs11.so
```
Any APDU returned from the card is now logged into the file `apdulog` in the
format expected by the `fuzz_pkcs15_reader`  fuzz target. It is also prefixed with
the ATR of the connected card as expected by the fuzz target. This file can be used
as a starting point that gets through the card detection but does not go into
all the operations the fuzz target attempts later.

### The pkcs15init fuzz target

The pkcs15init fuzz target consists of two separate parts. The first one is parsing
the profile file, which is separated from the rest of the input with a NULL
byte (0x00). The rest is interpreted as in the case of the `fuzz_pkcs15_reader`.

When creating a corpus for this fuzz target, stuff gets messier because:

 * The first part is the profile file
 * The `pkcs15-init` can do only one operation at a time, so we need to skip the
   card init when concatenating the APDU traces

So at first, erase the card and move away the apdulog:
```
./src/tools/pkcs15-init --erase-card --so-pin 12345678
$ mv apdulog /tmp/apdu_erase
```
Then prepare the separate files for each operation in the fuzz target:
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
* insert profile and zero bytes as a delimiter
* `apdu\_create` can be used as it is
* from `apdu\_create\_pin` remove the part for connecting the card
* from `apdu\_store\_data` remove some central parts since testing data is smaller than data used in apdu
* `apdu_generate_*` and `apdu\_finalize` need to skip connecting card and `sc_pcks15_bind()`
* symmetric key generation is not supported on the card; let's fill that part with some dummy values from generating RSA keys
* `apdu\_erase` needs to skip part for connecting card

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

Now, let's try to feed the data into the fuzz target:
```
OPENSC_DEBUG=9 ./src/tests/fuzzing/fuzz_pkcs15init_profile /tmp/testcase
```
The debug log should show the card detection, which goes through and then some
pkcs15init operations.

### The piv-tool fuzz target

The `fuzz_piv_tool` target allows testing operations of `piv-tool`. What operation is tested depends of first byte of the fuzzing input:

* `\x00` tests loading of the object, the input looks as\
`| \x00 | len1 | len2 | admin key | containerID | \x00 | admin_arg | \x00 | len1 | len2 | file content | APDU part |`[^1]
* `\x01` tests loading of the certificate, the input looks as\
`| \x01 | len1 | len2 | admin key | ref | \x00 | admin_arg | \x00 | len1 | len2 | file content | APDU part |`[^1]
* `\x02` tests loading of the compressed certificate, the input looks as by loading of certificate
* other values for first byte means that whole `argv` is taken from fuzzing input\
`| > \x003 | arg_1 | \x00 | arg_2 | \x00 | ... | arg_n | \x00 | \x00 | APDU part |`

### The pkcs15-tool fuzz target

The `fuzz_pkcs15_tool` target allows testing operations of `pkcs15-tool`. The options are taken from fuzzing input, it is parsed as\
`| arg_1 | \x00 | arg_2 | \x00 | ... | arg_n | \x00 | \x00 | APDU part |`

[^1]: `len1` and `len2` refer to two bytes that are parsed as the length of the content of the file that is extracted from the input

### The pkcs15-crypt fuzz target

The `fuzz_pkcs15_crypt` target allows testing operations of `pkcs15-crypt`. What operation is tested depends of first byte of the fuzzing input:

* the whole `argv` is taken from fuzzing input
* the `-c` and `-s` options are tested with various combinations of other command-line options\
`| op | hash type | padding | format | aid | aid value | \x00 | id | id value | \x00 | len1 |len2 |file content | APDU part |`
