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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#if defined(HAVE_OPENSSL)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <openssl/err.h>
#include "cert_support.h"

#define CHECK_CTX(ctx, val)			\
  if (!ctx) {					\
    return val;					\
  }

#define CHECK_CTX_VOID(ctx)			\
  if (!ctx) {					\
    return;					\
  }

scCertificate *certAlloc(void)
{
  scCertificate *scCert = (scCertificate *) malloc(sizeof(scCertificate));
  if (scCert) {
    memset(scCert, 0, sizeof(scCertificate));
  }
  return scCert;
}

static void certFreeBuffer(unsigned char *certbuf)
{
  if (certbuf) {
    free(certbuf);
  }
  certbuf = NULL;
}

void certFree(scCertificate * cert)
{
  CHECK_CTX_VOID(cert);
  if (cert) {
    if (cert->pubkey) {
      certFreePublicKey(cert->pubkey);
    }
    cert->pubkey = NULL;
    if (cert->crl) {
      certFreeCRL(cert->crl);
    }
    cert->crl = NULL;
    if (cert->cert) {
      certFreeCertificate(cert->cert);
    }
    cert->cert = NULL;
    if (cert->crlbuf) {
      certFreeBuffer(cert->crlbuf);
    }
    cert->crlbuf = NULL;
    cert->crllen = 0;
    if (cert->buf) {
      certFreeBuffer(cert->buf);
    }
    cert->buf = NULL;
    cert->len = 0;
    free(cert);
    cert = NULL;
  }
}

void certFreeAll(scCertificate ** cert)
{
  scCertificate **p = cert;
  int i;

  CHECK_CTX_VOID(*p);
  for (i = 0; p[i]; i++) {
    certFree(p[i]);
    p[i] = NULL;
  }
}

X509 *certParseCertificate(unsigned char *certbuf, unsigned int certlen)
{
  X509 *cert = NULL;
  unsigned char *certptr = certbuf;

  CHECK_CTX(certptr, NULL);
  /* Parse DER encoded certificate into the x509 structure */
  cert = X509_new();
  if (!d2i_X509(&cert, &certptr, certlen)) {
    return NULL;
  }
  return cert;
}

void certFreeCertificate(X509 * cert)
{
  CHECK_CTX_VOID(cert);
  X509_free(cert);
  cert = NULL;
}

X509_CRL *certParseCRL(unsigned char *crlbuf, unsigned int crllen)
{
  X509_CRL *crl = NULL;
  unsigned char *crlptr = crlbuf;

  CHECK_CTX(crlptr, NULL);
  /* Parse DER encoded certificate into the x509 crl structure */
  crl = X509_CRL_new();
  if (!d2i_X509_CRL(&crl, &crlptr, crllen)) {
    return NULL;
  }
  return crl;
}

void certFreeCRL(X509_CRL * crl)
{
  CHECK_CTX_VOID(crl);
  X509_CRL_free(crl);
  crl = NULL;
}

EVP_PKEY *certParsePublicKey(X509 * cert)
{
  EVP_PKEY *pubkey = NULL;

  CHECK_CTX(cert, NULL);
  pubkey = X509_get_pubkey(cert);
  return pubkey;
}

void certFreePublicKey(EVP_PKEY * pk)
{
  CHECK_CTX_VOID(pk);
  EVP_PKEY_free(pk);
  pk = NULL;
}

/* This function checks the validity of the certificate given
 * in cert and returns 0 if successful and -1 on error.
 */

int certCheckValidity(X509 * cert)
{
  CHECK_CTX(cert, -1);
  /* Check validity dates against the current time
     notBefore < current time and notAfter > current time */
  if (X509_cmp_current_time(X509_get_notBefore(cert)) < 0 &&
      X509_cmp_current_time(X509_get_notAfter(cert)) > 0) {
    return 0;
  } else {
    if (X509_cmp_current_time(X509_get_notBefore(cert)) > 0) {
#if 0
      log_message("Certificate not valid yet\n");
#endif
    } else {
#if 0
      log_message("Certificate not valid anymore\n");
#endif
    }
    return -1;
  }
  return -1;
}

/* This function checks whether the bit bit is set in the keyUsage
 * BITSTRING of the certificate given as argument ie. whether
 * the key in the certificate is fit for a certain use.
 * Returns 1 if set, 0 if not set and -1 on error.
 */

int certCheckKeyUsage(X509 * cert, unsigned int bit)
{
  int loc = -1, rv = -1;
  ASN1_BIT_STRING *b_asn = NULL;
  unsigned char *bitstr = NULL;
  X509_EXTENSION *ext = NULL;

  CHECK_CTX(cert, -1);
  /* keyUsage bits run from 0 to 8 */
  if (bit > 8) {
    return -1;
  }
  /* Try to parse keyUsage extension out of the certificate */
  loc = X509_get_ext_by_NID(cert, NID_key_usage, 0);
  /* No keyUsage existing, bail out */
  if (loc < 0) {
    return -1;
  }
  ext = X509_get_ext(cert, loc);
  if (!ext) {
    return -1;
  }
  bitstr = ext->value->data;

  if (!d2i_ASN1_BIT_STRING(&b_asn, &bitstr, ext->value->length)) {
    return -1;
  }
  if (ASN1_BIT_STRING_get_bit(b_asn, bit)) {
    rv = 1;
  } else {
    rv = 0;
  }
  ASN1_BIT_STRING_free(b_asn);
  return rv;
}

#define ASN1_SEQ 0x30
#define ASN1_CHOICE 0xa0

/* This function parses the CRL distribution point from the 
   certificate. 
   Returns CRL location or NULL on error.
 */

char *certGetCRLDistributionPoint(X509 * cert)
{
  X509_EXTENSION *ext = NULL;
  ASN1_OCTET_STRING *o_asn = NULL;
  char *crlbuf = NULL, *distpoint = NULL;
  int rv = -1, crllen = 0;
  int asnlen = 0, i = 0, j = 0, k = 0;

  CHECK_CTX(cert, NULL);
  /* Try to parse crlDistributionPoints extension out of the certificate */
  rv = X509_get_ext_by_NID(cert, NID_crl_distribution_points, 0);
  if (rv < 0) {
    return NULL;
  }
  ext = X509_get_ext(cert, rv);
  if (!ext) {
    return NULL;
  }
  o_asn = X509_EXTENSION_get_data(ext);
  if (!o_asn) {
    return NULL;
  }
  for (i = 0; i < o_asn->length;) {
    switch (*(o_asn->data + i)) {
    case ASN1_SEQ:
      {
	i++;
	if (*(o_asn->data + i) & 0x80) {
	  asnlen = (*(o_asn->data + i) & ~0x80);
	  i++;

	  crllen = 0;
	  for (j = 0; j < asnlen; j++) {
	    if (j == 0) {
	      crllen += (*(o_asn->data + i));
	    } else {
	      crllen += (j * 0x100) * (*(o_asn->data + i));
	    }
	    i++;
	  }

	} else {
	  i++;
	  crllen = (*(o_asn->data + i));
	}
	break;
      }
    case ASN1_CHOICE:
      {
	i++;
	if (*(o_asn->data + i) & 0x80) {
	  asnlen = (*(o_asn->data + i) & ~0x80);
	  i++;
	  crllen = 0;
	  for (j = 0; j < asnlen; j++) {
	    if (j == 0) {
	      crllen += (*(o_asn->data + i));
	    } else {
	      crllen += (j * 0x100) * (*(o_asn->data + i));
	    }
	    i++;
	  }
	} else {
	  i++;
	  crllen = (*(o_asn->data + i));
	  i++;
	}

	for (j = 0; j < crllen; j++) {
	  if (*(o_asn->data + i) == 0x86) {
	    i++;
	    if (*(o_asn->data + i) & 0x80) {
	      asnlen = (*(o_asn->data + i) & ~0x80);
	      i++;
	      crllen = 0;
	      for (j = 0; j < asnlen; j++) {
		if (j == 0) {
		  crllen += (*(o_asn->data + i));
		} else {
		  crllen += (j * 0x100) * (*(o_asn->data + i));
		}
		i++;
	      }
	    } else {
	      crllen = (*(o_asn->data + i));
	      i++;
	    }
	    crlbuf = (char *) malloc(crllen + 1);
	    if (!crlbuf) {
	      return NULL;
	    }
	    memset(crlbuf, 0, crllen + 1);
	    memcpy(crlbuf, (o_asn->data + i), crllen);
	    for (k = 0; k < crllen; k++) {
	      i++;
	    }
	    break;
	  }
	  i++;
	}
	break;
      }
    default:
      return NULL;
    }
  }

  distpoint = (char *) malloc(crllen + 1);
  if (!distpoint) {
    free(crlbuf);
    return NULL;
  }
  memset(distpoint, 0, crllen + 1);
  memcpy(distpoint, crlbuf, crllen);
  free(crlbuf);
  return distpoint;
}

/* This function checks whether the X.509 format certificate cert 
   is self-signed (ie. issuer and subject names match). 
   Returns 1 if it is self-signed, 0 if it is not and -1 on error.
 */

int certIsSelfSigned(X509 * cert)
{
  CHECK_CTX(cert, -1);
  if (!X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert))) {
    return 1;
  } else {
    return 0;
  }
}

/* This function returns the issuer of the X.509 format certificate 
   cert.
 */

char *certGetIssuer(X509 * cert)
{
  CHECK_CTX(cert, NULL);
  return X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
}

/* This function returns the subject of the X.509 format certificate 
   cert.
 */
char *certGetSubject(X509 * cert)
{
  CHECK_CTX(cert, NULL);
  return X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
}

char *certParseDN(char *entry, char *field)
{
  char *token = NULL, *value = NULL, *p = NULL;

  CHECK_CTX(entry, NULL);
  CHECK_CTX(field, NULL);

  token = strtok(entry, "/");
  if (!token) {
    return NULL;
  }
  if ((p = strstr(token, field))) {
    p = p + strlen(field);
    if (*p == '=') {
      p++;
    }
    value = (char *) malloc((strlen(p) + 1) * sizeof(char));
    if (!value) {
      return NULL;
    }
    strcpy(value, p);
    return value;
  }
  while ((token = strtok(NULL, "/"))) {
    if ((p = strstr(token, field))) {
      p = p + strlen(field);
      if (*p == '=') {
	p++;
      }
      value = (char *) malloc((strlen(p) + 1) * sizeof(char));
      if (!value) {
	return NULL;
      }
      strcpy(value, p);
      return value;
    }
  }
  return NULL;
}

/* This function searches the serial number list of a CRL for 
   serialNumber. 
   Returns 1 if found, 0 if not found and -1 on error.
 */

static int certIsRevoked(ASN1_STRING * serialNumber, X509_CRL_INFO * crlinfo)
{
  int i = 0, numrevoked = 0, revoked = 0;

  if (!serialNumber || !crlinfo) {
    return -1;
  }
  numrevoked = sk_num(crlinfo->revoked);

  for (i = 0; i < numrevoked && !revoked; i++) {
    X509_REVOKED *r = (X509_REVOKED *) sk_value(crlinfo->revoked, i);
    if (!ASN1_INTEGER_cmp(serialNumber, r->serialNumber)) {
      revoked = 1;
    }
  }
  return revoked;
}

/* This function sets up a certificate store with all the CA certificates
 * in X509CAcert and checks the validity and the issuer signature of
 * the user certificate and all the CA certificates. This couldn't be
 * tested with a real certificate chain, though, as we have none.
 * Returns 0 on success and the real openssl error on error (NOTE: these
 * are positive integers!).
 */

int certVerifyCAChain(scCertificate ** CAcerts, X509 * cert)
{
  scCertificate *currCAcert = CAcerts[0];
  X509 *usercert = cert, *x509CAcert = NULL;
  ASN1_INTEGER *serialNumber = NULL;
  EVP_PKEY *pubkey = NULL;
  X509_STORE_CTX cst_ctx;
  X509_STORE *cst = NULL;
  X509_CRL *x509crl = NULL;
  int rv = 0, err = 0, i = 0;

  /* There has to be a user certificate and at least one CA certificate */
  if (!usercert || !currCAcert) {
    return -1;
  }
  x509CAcert = (X509 *) currCAcert->cert;

  if (!x509CAcert) {
#if 0
    log_messagex(L_DEBUG, "No CA certs given as argument!\n");
#endif
    return -1;
  }
  /* Set up store */
  cst = X509_STORE_new();
  if (!cst) {
#if 0
    log_messagex(L_DEBUG, "Could not create certificate store, bailing out.\n");
#endif
    return -1;
  }
  /* Add all CA certificates to the store (direction is not
     important, openssl should create a chain for us). */
  while (x509CAcert) {
    rv = X509_STORE_add_cert(cst, x509CAcert);
    /* O joy, sometimes openssl returns 0 for OK and
       sometimes for error */
    if (!rv) {
      /* FIXME: Get real error */
      err = 1;
      X509_STORE_free(cst);
      return err;
    }
    i++;
    currCAcert = CAcerts[i];
    if (!currCAcert) {
      break;
    }
    x509CAcert = (X509 *) currCAcert->cert;
  }

  /* Don't care what algorithm the hash uses, just add everything */
  SSLeay_add_all_algorithms();
  /* Init check of user certificate against CA certs in store */
  X509_STORE_CTX_init(&cst_ctx, cst, usercert, NULL);
  rv = X509_verify_cert(&cst_ctx);

  if (rv < 0) {
    err = -1;
  } else {
    err = X509_STORE_CTX_get_error(&cst_ctx);
  }
  X509_STORE_CTX_cleanup(&cst_ctx);
  X509_STORE_free(cst);

  /* FIXME: Check CRL here by hand, will be in openssl version 0.9.7.
     Do nothing fancy for now, because a real CRL check will probably
     be implemented in openssl before we need multiple CRLs. */
  if (!err) {
    serialNumber = X509_get_serialNumber(usercert);
    currCAcert = CAcerts[0];
    x509crl = (X509_CRL *) currCAcert->crl;
    x509CAcert = (X509 *) currCAcert->cert;

    i = 0;

    while (currCAcert && x509CAcert && x509crl) {
      if (!serialNumber) {
	err = 1;
	break;
      }
      if (!x509crl->crl || !x509CAcert->cert_info) {
	err = 1;
	break;
      }
#if 0
      log_messagex(L_DEBUG, "CA Issuer: %s\n", X509_NAME_oneline(x509CAcert->cert_info->subject, NULL, 0));
      log_messagex(L_DEBUG, "CRL Issuer: %s\n", X509_NAME_oneline(x509crl->crl->issuer, NULL, 0));
#endif

#if 1
      /* Check that CRL issuer and CA subject match */
      rv = X509_NAME_cmp(x509crl->crl->issuer, x509CAcert->cert_info->subject);
      if (rv != 0) {
	err = X509_V_ERR_SUBJECT_ISSUER_MISMATCH;
	break;
      }
#endif
      /* Check signature */
      pubkey = (EVP_PKEY *) certParsePublicKey(x509CAcert);
      if (!pubkey) {
	err = X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
	break;
      }
      /* Check signature */
      if ((rv = X509_CRL_verify(x509crl, pubkey) < 1)) {
	err = X509_V_ERR_CRL_SIGNATURE_FAILURE;
	break;
      }
      /* Check CRL validity */
      if ((rv = X509_cmp_current_time(X509_CRL_get_nextUpdate(x509crl))) < 0) {
	err = X509_V_ERR_CRL_HAS_EXPIRED;
	break;
      }
      /* Check whether the serial number is among the revoked */
      if (certIsRevoked(serialNumber, x509crl->crl) != 0) {
	err = X509_V_ERR_CERT_REVOKED;
	break;
      }
      serialNumber = X509_get_serialNumber(x509CAcert);
      i++;
      currCAcert = CAcerts[i];
      if (!currCAcert) {
	break;
      }
      x509crl = (X509_CRL *) currCAcert->crl;
      x509CAcert = (X509 *) currCAcert->cert;
    }
  }
  EVP_cleanup();
  return err;
}

const char *certError(unsigned long error)
{
  static char buf[1024];

  /* FIXME */
  ERR_load_ERR_strings();
  ERR_load_crypto_strings();
  snprintf(buf, 1024, "%s", ERR_error_string(error, NULL));
  ERR_free_strings();
  return (char *) &buf[0];
}

#endif
