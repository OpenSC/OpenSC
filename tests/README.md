# OpenSC test scripts

## The pkcs11-tool tests

Some of the tests support running with several PKCS#11 modules:

- SoftHSM,
- Kyoptic,
- and Softokn.

The test can be run with specified token `softhsm | kryoptic | softokn`:

```bash
./test-pkcs11-tool-test.sh # default: softhsm
./test-pkcs11-tool-test.sh softhsm
./test-pkcs11-tool-test.sh kryoptic
./test-pkcs11-tool-sign-verify.sh softokn
```
