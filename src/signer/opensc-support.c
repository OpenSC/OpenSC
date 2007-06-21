#include "opensc-support.h"
#include "opensc-crypto.h"
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pkcs7.h>

static int get_certificate(PluginInstance *inst,
                           X509 **cert_out, struct sc_pkcs15_id *certid_out)
{
        struct sc_pkcs15_cert *cert;
        struct sc_pkcs15_cert_info *cinfo;
	struct sc_pkcs15_object *objs[32], *cert_obj;
        int r, i, count;
        X509 *x509;
        struct sc_pkcs15_id cert_id;
        const u8 *p;

        r = sc_pkcs15_get_objects(inst->p15card, SC_PKCS15_TYPE_PRKEY_RSA, objs, 32);
        if (r < 0)
                return r;
        if (r == 0)
                return SC_ERROR_OBJECT_NOT_FOUND;
        cert_id.len = 0;
        count = r;
        for (i = 0; i < count; i++) {
                struct sc_pkcs15_prkey_info *key = (struct sc_pkcs15_prkey_info *) objs[i]->data;

#if 0
                if (key->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION) {
#endif
                        /* Use the first available non-repudiation key */
                        cert_id = key->id;
                        break;
#if 0
                }
#endif
        }
        if (cert_id.len == 0)
                return SC_ERROR_OBJECT_NOT_FOUND;
        r = sc_pkcs15_find_cert_by_id(inst->p15card, &cert_id, &cert_obj);
        if (r)
                return r;
	cinfo = (struct sc_pkcs15_cert_info *) cert_obj->data;
        r = sc_pkcs15_read_certificate(inst->p15card, cinfo, &cert);
        if (r)
                return r;
        x509 = X509_new();
        p = cert->data;
        if (!d2i_X509(&x509, &p, cert->data_len)) {
                return -1; /* FIXME */
        }
        *certid_out = cinfo->id;
        sc_pkcs15_free_certificate(cert);
        *cert_out = x509;
        return 0;
}

static int init_pkcs15(PluginInstance *inst)
{
        int r;
        
        r = sc_establish_context(&inst->ctx, "opensc-signer");
        if (r)
                return r;
        inst->reader_id = 0;
        r = sc_connect_card(inst->ctx->reader[inst->reader_id], 0, &inst->card);
        if (r)
                return r;
        r = sc_pkcs15_bind(inst->card, &inst->p15card);
        if (r)
                return r;
        return 0;
}

#if 0
static void close_pkcs15(PluginInstance *inst)
{
        if (inst->p15card) {
                sc_pkcs15_unbind(inst->p15card);
                inst->p15card = NULL;
        }
        if (inst->card) {
                sc_disconnect_card(inst->card, 0);
                inst->card = NULL;
        }
        if (inst->ctx) {
                sc_release_context(inst->ctx);
                inst->ctx = NULL;
        }
}
#endif

static int extract_certificate_and_pkey(PluginInstance *inst,
					X509 **x509_out,
					EVP_PKEY **pkey_out)
{
	int r;
	X509 *x509 = NULL;
	struct sc_pkcs15_id cert_id;
	struct sc_priv_data *priv = NULL;
        EVP_PKEY *pkey = NULL;
        RSA *rsa = NULL;
	
        r = init_pkcs15(inst);
        if (r)
                goto err;
        r = get_certificate(inst, &x509, &cert_id);
        if (r)
                goto err;

	r = -1;
        pkey = X509_get_pubkey(x509);
        if (pkey == NULL)
        	goto err;
        if (pkey->type != EVP_PKEY_RSA)
        	goto err;
	rsa = EVP_PKEY_get1_RSA(pkey); /* increases ref count */
	if (rsa == NULL)
		goto err;
	rsa->flags |= RSA_FLAG_SIGN_VER;
	RSA_set_method(rsa, sc_get_method());
	priv = (struct sc_priv_data *) calloc(1, sizeof(*priv));
	if (priv == NULL)
		goto err;
	priv->cert_id = cert_id;
	priv->ref_count = 1;
	RSA_set_app_data(rsa, priv);
	RSA_free(rsa);		/* decreases ref count */
	
	*x509_out = x509;
	*pkey_out = pkey;

	return 0;
err:
	if (pkey)
		EVP_PKEY_free(pkey);
	if (x509)
		X509_free(x509);
	return -1;
	
}

int create_envelope(PluginInstance *inst, u8 **data, int *datalen)
{
        int r;
        PKCS7 *p7 = NULL;
        X509 *x509 = NULL;
	PKCS7_SIGNER_INFO *si = NULL;
        EVP_PKEY *pkey = NULL;
	BIO *in = NULL, *p7bio = NULL;
	u8 *buf;
        
	r = extract_certificate_and_pkey(inst, &x509, &pkey);
	if (r)
		goto err;
        p7 = PKCS7_new();
        if (p7 == NULL) {
        	r = -1;
        	goto err;
        }
        r = PKCS7_set_type(p7, NID_pkcs7_signed);
        if (r != 1) {
        	r = -1;
                goto err;
	}
	EVP_add_digest(EVP_sha1());
        si = PKCS7_add_signature(p7, x509, pkey, EVP_sha1());
        if (si == NULL) {
        	r = -1;
		goto err;
	}
	PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT,
				   OBJ_nid2obj(NID_pkcs7_data));
	r = PKCS7_add_certificate(p7, x509);
	if (r != 1) {
		printf("PKCS7_add_certificate failed.\n");
		goto err;
	}
	PKCS7_content_new(p7, NID_pkcs7_data);

	p7bio = PKCS7_dataInit(p7, NULL);
	if (p7bio == NULL) {
        	r = -1;
		goto err;
	}
	in = BIO_new_mem_buf(inst->signdata, inst->signdata_len);
	if (in == NULL) {
		r = -1;
		goto err;
	}
	for (;;) {
		char lbuf[1024];
		int i = BIO_read(in, lbuf, sizeof(lbuf));
		if (i <= 0)
			break;
		BIO_write(p7bio, lbuf, i);
	}
	if (!PKCS7_dataFinal(p7, p7bio)) {
		r = -1;
		goto err;
	}
	/* FIXME: remove this */
	r = i2d_PKCS7(p7, NULL);
	if (r <= 0) {
		r = -1;
		goto err;
	}
	buf = (u8 *) malloc(r);
	if (buf == NULL)
		goto err;
	*data = buf;
	r = i2d_PKCS7(p7, &buf);
	*datalen = r;
	if (r <= 0) {
		free(buf);
		r = -1;
		goto err;
	}
	r = 0;
err:
	if (p7)
		PKCS7_free(p7);
	if (in)
		BIO_free(in);
	if (p7bio)
		BIO_free(p7bio);
#if 0
	if (si)
		PKCS7_SIGNER_INFO_free(si);
#endif
	if (pkey)
		EVP_PKEY_free(pkey);
	if (x509)
		X509_free(x509);
	if (r) {
#if 0
		ERR_load_crypto_strings();
		ERR_print_errors_fp(stderr);
#endif
	}
        return r;
}
