/*
 * $Id$
 *
 * Copyright (C) 2001, 2002
 *  Anna Erika Suortti <asuortti@cc.hut.fi>
 *  Antti Tapaninen <aet@cc.hut.fi>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __cert_support_h__
#define __cert_support_h__

#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DIGITAL_SIGNATURE 0
#define NONREPUDIATION 1
#define KEY_ENCIPHERMENT 2
#define DATA_ENCIPHERMENT 3
#define KEY_AGREEMENT 4
#define CERTIFICATE_SIGN 5
#define CRL_SIGN 6
#define ENCIPHER_ONLY 7
#define DECIPHER_ONLY 8

typedef struct _scCertificate {
  unsigned char *buf, *crlbuf;
  unsigned long len, crllen;
  X509 *cert;
  X509_CRL *crl;
  EVP_PKEY *pubkey;
} scCertificate;

extern scCertificate *certAlloc(void);
extern void certFree(scCertificate * cert);
extern void certFreeAll(scCertificate ** cert);

extern X509 *certParseCertificate(unsigned char *certbuf, unsigned int certlen);
extern void certFreeCertificate(X509 * cert);

extern X509_CRL *certParseCRL(unsigned char *crlbuf, unsigned int crllen);
extern void certFreeCRL(X509_CRL * crl);

extern EVP_PKEY *certParsePublicKey(X509 * cert);
extern void certFreePublicKey(EVP_PKEY * pubkey);

extern int certCheckValidity(X509 * cert);
extern int certCheckKeyUsage(X509 * cert, unsigned int bit);

extern int certIsSelfSigned(X509 * cert);
extern char *certGetIssuer(X509 * cert);
extern char *certParseDN(char *entry, char *field);
extern char *certGetSubject(X509 * cert);
extern char *certGetCRLDistributionPoint(X509 * cert);

extern int certVerifyCAChain(scCertificate ** x509CAcerts, X509 * cert);

extern const char *certError(unsigned long error);

#ifdef __cplusplus
}
#endif
#endif
