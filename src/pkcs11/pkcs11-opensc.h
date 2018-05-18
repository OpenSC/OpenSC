#ifndef PKCS11_OPENSC_H
#define PKCS11_OPENSC_H

/* OpenSC specific extensions */
/*
 * define OpenSC specific Vendor Defined  extensions
 * to make unique OpenSC  flags, attributes, mechanisms, etc.
 * 
 * Netscape used NSSCK_VENDOR_NSS 0x4E534350 "NSCP"
 */

#define SC_VENDOR_DEFINED 0x4F534300  /* OSC */

/*
 * In PKCS#11 there is no CKA_ attribute dedicated to the NON-REPUDIATION flag.
 * We need this flag in PKCS#15/libopensc to make distinction between
 * 'signature' and 'qualified signature' key slots.
 */
#define CKA_OPENSC_NON_REPUDIATION      (CKA_VENDOR_DEFINED | SC_VENDOR_DEFINED | 1UL)

#define CKA_SPKI			(CKA_VENDOR_DEFINED | SC_VENDOR_DEFINED | 2UL)

#endif
