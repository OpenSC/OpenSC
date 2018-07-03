# Non-destructive PKCS#11 test suite (not only for readonly cards)

## What are the dependencies?

In addition to the dependencies needed by OpenSC, the test suite is
using  [`cmocka`](https://cmocka.org/) unit testing framework
(`libcmocka-devel` package in Fedora/EPEL).

## How to use?

Build OpenSC from source:

    git clone git@github.com:OpenSC/OpenSC.git
    cd OpenSC
    ./bootstrap
    ./configure
    make -j4

Plug in the card/reader, change to test directory and run the test:

    cd src/tests/p11test
    ./p11test -p 123456

It will run all tests on the first card found in PKCS#11 API
with pin `123456` and using just built OpenSC shared library from master.

### I have more slots with different cards.

Slot can be selected using `-s` switch on command-line.

    ./p11test -s 4

Slot numbers can be obtained using from `pkcs11-tool -L` (note that different
libraries might have different numbers for the slots).

### I want to test different pkcs11 library

You can specify different library or build from different branch
on command-line:

    ./p11test -m /usr/lib64/pkcs11/libcoolkeypk11.so

or to debug PKCS#11 calls using `/usr/lib64/pkcs11-spy.so`:

    export PKCS11SPY="../pkcs11/.libs/opensc-pkcs11.so"
    ./p11test -m ../pkcs11/.libs/pkcs11-spy.so

You can run the test suite also on the soft tokens. The testbench for
`softhsm` and `opencryptoki` is available in the script `runtest.sh`.

TODO:

 * Test `CKM_ECDSA_DERIVE` mechanism(s)
 * Read pin from environment variable?
 * Keygen write tests (optional)
 * Reflect cmocka dependency in the configure
