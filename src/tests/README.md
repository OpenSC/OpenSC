# pkcs11 test suite for readonly cards

## How to use?

Build OpenSC from source:

    git clone git@github.com:Jakuje/OpenSC.git
    cd OpenSC
    autoconf
    ./configure
    make

Plug in the card/reader, change to test directory and run the test:

    cd src/tests
	./p11test

It will run all tests on PKCS11 API with default 123456 pin.

## My card has different PIN.

PIN can be specified on commandline:

    ./p11test -p 12345678

## I want to test different pkcs11 library

You can specify different library to test on command line:

    ./p11test -m /usr/lib64/pkcs11/libcoolkeypk11.so


TODO:

 * Test EC_DERIVE mechanism
 * Read pin from environment variable?
