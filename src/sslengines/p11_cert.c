/*
 * p11_cert.c - Handle certificates residing on a PKCS11 token
 *
 * Copyright (C) 2002, Olaf Kirch <okir@lst.de>
 */

#include "pkcs11-internal.h"
#include <string.h>

static int pkcs11_find_certs(PKCS11_TOKEN *);
static int pkcs11_next_cert(PKCS11_CTX *, PKCS11_TOKEN *, CK_SESSION_HANDLE);
static int pkcs11_init_cert(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
			    CK_SESSION_HANDLE session, CK_OBJECT_HANDLE o,
			    PKCS11_CERT **);
static int pkcs11_store_certificate(PKCS11_TOKEN *, X509 *,
				    char *, unsigned char *, unsigned int,
				    PKCS11_CERT **);

static CK_OBJECT_CLASS cert_search_class;
static CK_ATTRIBUTE cert_search_attrs[] = {
	{CKA_CLASS, &cert_search_class, sizeof(cert_search_class)},
};
#define numof(arr)	(sizeof(arr)/sizeof((arr)[0]))

/*
 * Enumerate all certs on the card
 */
int
PKCS11_enumerate_certs(PKCS11_TOKEN * token,
		       PKCS11_CERT ** certp, unsigned int *countp)
{
	PKCS11_TOKEN_private *priv = PRIVTOKEN(token);

	if (priv->ncerts < 0) {
		priv->ncerts = 0;
		if (pkcs11_find_certs(token)) {
			pkcs11_destroy_certs(token);
			return -1;
		}
	}
	*certp = priv->certs;
	*countp = priv->ncerts;
	return 0;
}

/*
 * Find certificate matching a key
 */
PKCS11_CERT *PKCS11_find_certificate(PKCS11_KEY * key)
{
	PKCS11_KEY_private *kpriv;
	PKCS11_CERT_private *cpriv;
	PKCS11_CERT *cert;
	unsigned int n, count;

	kpriv = PRIVKEY(key);
	if (PKCS11_enumerate_certs(KEY2TOKEN(key), &cert, &count))
		return NULL;
	for (n = 0; n < count; n++, cert++) {
		cpriv = PRIVCERT(cert);
		if (cpriv->id_len == kpriv->id_len
		    && !memcmp(cpriv->id, kpriv->id, kpriv->id_len))
			return cert;
	}
	return NULL;
}

/*
 * Find all certs of a given type (public or private)
 */
int pkcs11_find_certs(PKCS11_TOKEN * token)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	CK_SESSION_HANDLE session;
	int rv, res = -1;

	/* Make sure we have a session */
	if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 0))
		return -1;
	session = PRIVSLOT(slot)->session;

	/* Tell the PKCS11 lib to enumerate all matching objects */
	cert_search_class = CKO_CERTIFICATE;
	rv = CRYPTOKI_call(ctx, C_FindObjectsInit(session, cert_search_attrs,
						  numof(cert_search_attrs)));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_CERTS, rv);

	do {
		res = pkcs11_next_cert(ctx, token, session);
	} while (res == 0);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(session));
	return (res < 0) ? -1 : 0;
}

int
pkcs11_next_cert(PKCS11_CTX * ctx, PKCS11_TOKEN * token, CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE obj;
	CK_ULONG count;
	int rv;

	/* Get the next matching object */
	rv = CRYPTOKI_call(ctx, C_FindObjects(session, &obj, 1, &count));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_CERTS, rv);

	if (count == 0)
		return 1;

	if (pkcs11_init_cert(ctx, token, session, obj, NULL))
		return -1;

	return 0;
}

int
pkcs11_init_cert(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
		 CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj, PKCS11_CERT ** ret)
{
	PKCS11_TOKEN_private *tpriv;
	PKCS11_CERT_private *kpriv;
	PKCS11_CERT *cert;
	char label[256], data[2048];
	unsigned char id[256];
	CK_CERTIFICATE_TYPE cert_type;
	size_t size;

	size = sizeof(cert_type);
	if (pkcs11_getattr_var(token, obj, CKA_CERTIFICATE_TYPE, &cert_type, &size))
		return -1;

	/* Ignore any certs we don't understand */
	if (cert_type != CKC_X_509)
		return 0;

	tpriv = PRIVTOKEN(token);
	tpriv->certs = (PKCS11_CERT *) OPENSSL_realloc(tpriv->certs,
						       (tpriv->ncerts +
							1) * sizeof(PKCS11_CERT));

	cert = tpriv->certs + tpriv->ncerts++;
	memset(cert, 0, sizeof(*cert));
	cert->_private = kpriv = PKCS11_NEW(PKCS11_CERT_private);
	kpriv->object = obj;
	kpriv->parent = token;

	if (!pkcs11_getattr_s(token, obj, CKA_LABEL, label, sizeof(label)))
		cert->label = BUF_strdup(label);
	size = sizeof(data);
	if (!pkcs11_getattr_var(token, obj, CKA_VALUE, data, &size)) {
		unsigned char *p = (unsigned char *) data;

		cert->x509 = d2i_X509(NULL, &p, size);
	}
	cert->id_len = sizeof(id);
	if (!pkcs11_getattr_var(token, obj, CKA_ID, id, (size_t *) & cert->id_len)) {
		cert->id = (unsigned char *) malloc(cert->id_len);
		memcpy(cert->id, id, cert->id_len);
	}

	/* Initialize internal information */
	kpriv->id_len = sizeof(kpriv->id);
	if (pkcs11_getattr_var(token, obj, CKA_ID, kpriv->id, &kpriv->id_len))
		kpriv->id_len = 0;

	if (ret)
		*ret = cert;

	return 0;
}

/*
 * Destroy all certs
 */
void pkcs11_destroy_certs(PKCS11_TOKEN * token)
{
	PKCS11_TOKEN_private *priv = PRIVTOKEN(token);

	while (priv->ncerts > 0) {
		PKCS11_CERT *cert = &priv->certs[--(priv->ncerts)];

		if (cert->x509)
			X509_free(cert->x509);
		OPENSSL_free(cert->label);
		if (cert->id)
			free(cert->id);
	}
	if (priv->certs)
		OPENSSL_free(priv->certs);
	priv->ncerts = -1;
	priv->certs = NULL;
}

/*
 * Store certificate
 */
int
pkcs11_store_certificate(PKCS11_TOKEN * token, X509 * x509, char *label,
			 unsigned char *id, unsigned int id_len,
			 PKCS11_CERT ** ret_cert)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[32];
	unsigned int n = 0;
	int rv;

	/* First, make sure we have a session */
	if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 1))
		return -1;
	session = PRIVSLOT(slot)->session;

	/* Now build the template */
	pkcs11_addattr_int(attrs + n++, CKA_CLASS, CKO_CERTIFICATE);
	pkcs11_addattr_int(attrs + n++, CKA_CERTIFICATE_TYPE, CKC_X_509);
	pkcs11_addattr_obj(attrs + n++, CKA_VALUE, (pkcs11_i2d_fn) i2d_X509, x509);
	if (label)
		pkcs11_addattr_s(attrs + n++, CKA_LABEL, label);
	if (id && id_len)
		pkcs11_addattr(attrs + n++, CKA_ID, id, id_len);

	/* Now call the pkcs11 module to create the object */
	rv = CRYPTOKI_call(ctx, C_CreateObject(session, attrs, n, &object));

	/* Zap all memory allocated when building the template */
	pkcs11_zap_attrs(attrs, n);

	CRYPTOKI_checkerr(PKCS11_F_PKCS11_STORE_CERTIFICATE, rv);

	/* Gobble the key object */
	return pkcs11_init_cert(ctx, token, session, object, ret_cert);
}
