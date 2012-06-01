#ifndef PKCS11_OPENSC_H
#define PKCS11_OPENSC_H

/* OpenSC specific extensions */
/*
 * In PKCS#11 there is no CKA_ attribute dedicated to the NON-REPUDIATION flag.
 * We need this flag in PKCS#15/libopensc to make dinstinction between
 * 'signature' and 'qualified signature' key slots.
 */
#define CKA_OPENSC_NON_REPUDIATION      (CKA_VENDOR_DEFINED | 1UL)

#endif
