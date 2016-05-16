# Non-destructive PKCS#11 test suite (not only for readonly cards)

## What are the dependencies?

In addition to the dependencies needed by OpenSC, the test suite is
using  [`cmocka`](https://cmocka.org/) unit testing framework
(`libcmocka-devel` package in Fedora).

## How to use?

Build OpenSC from source:

    git clone git@github.com:Jakuje/OpenSC.git
    cd OpenSC
	git checkout jjelen-testsuite		# not in master yet
    autoconf
    ./configure
    make

Plug in the card/reader, change to test directory and run the test:

    cd src/tests
	./p11test

It will run all tests on PKCS#11 API with default pin `123456`
and using just built OpenSC shared library.

## My card has different PIN.

PIN can be specified on commandline:

    ./p11test -p 12345678

## I want to test different pkcs11 library

You can specify different library or build from different branch
on command line:

    ./p11test -m /usr/lib64/pkcs11/libcoolkeypk11.so


TODO:

 * Test `CKM_ECDSA_DERIVE` mechanism(s)
 * Read pin from environment variable?
