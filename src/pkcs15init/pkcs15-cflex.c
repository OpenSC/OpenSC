/*
 * Cryptoflex specific operation for PKCS #15 initialization
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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
#include <sys/types.h>
#include <string.h>
#include <openssl/bn.h>
#include "opensc.h"
#include "pkcs15-init.h"
#include "profile.h"

/*
 * Initialize the Application DF
 */
static int cflex_init_app(struct sc_profile *profile, struct sc_card *card,
		const u8 *pin, size_t pin_len, const u8 *puk, size_t puk_len)
{
	/* Create the application DF */
	if (sc_pkcs15init_create_file(profile, card, profile->df_info->file))
		return 1;

	return 0;
}

/*
 * Update the contents of a PIN file
 */
static int cflex_update_pin(struct sc_profile *profile, struct sc_card *card,
		sc_file_t *file,
		const u8 *pin, size_t pin_len, int pin_tries,
		const u8 *puk, size_t puk_len, int puk_tries)
{
	u8		buffer[23], *p = buffer;
	int		r;
	size_t		len;

	memset(p, 0xFF, 3);
	p += 3;
	memset(p, profile->pin_pad_char, 8);
	strncpy((char *) p, pin, pin_len);
	p += 8;
	*p++ = pin_tries;
	*p++ = pin_tries;
	memset(p, profile->pin_pad_char, 8);
	strncpy((char *) p, puk, puk_len);
	p += 8;
	*p++ = puk_tries;
	*p++ = puk_tries;
	len = 23;

	r = sc_pkcs15init_update_file(profile, card, file, buffer, len);
	if (r < 0)
		return r;
	return 0;
}

/*
 * Store a PIN
 */
static int
cflex_new_pin(struct sc_profile *profile, struct sc_card *card,
		struct sc_pkcs15_pin_info *info, unsigned int index,
		const u8 *pin, size_t pin_len,
		const u8 *puk, size_t puk_len)
{
	sc_file_t *pinfile;
	struct sc_pkcs15_pin_info tmpinfo;
	char template[30];
	int pin_tries, puk_tries;
	int r;

	index++;
	sprintf(template, "pinfile-%d", index);
	/* Profile must define a "pinfile" for each PIN */
	if (sc_profile_get_file(profile, template, &pinfile) < 0) {
		profile->cbs->error("Profile doesn't define \"%s\"", template);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	info->path = pinfile->path;
	if (info->path.len > 2)
		info->path.len -= 2;
	info->reference = 1;
	if (pin_len > 8)
		pin_len = 8;
	if (puk_len > 8)
		puk_len = 8;
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &tmpinfo);
	pin_tries = tmpinfo.tries_left;
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PUK, &tmpinfo);
	puk_tries = tmpinfo.tries_left;
	
	r = cflex_update_pin(profile, card, pinfile, pin, pin_len, pin_tries,
				puk, puk_len, puk_tries);
	sc_file_free(pinfile);
	return r;
}

/*
 * Allocate a file
 */
static int
cflex_new_file(struct sc_profile *profile, struct sc_card *card,
		unsigned int type, unsigned int num,
		struct sc_file **out)
{
	struct sc_file	*file;
	char		name[64], *tag, *desc;

	desc = tag = NULL;
	while (1) {
		switch (type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
			desc = "RSA private key";
			tag = "private-key";
			break;
		case SC_PKCS15_TYPE_PUBKEY_RSA:
			desc = "RSA public key";
			tag = "public-key";
			break;
		case SC_PKCS15_TYPE_CERT:
			desc = "certificate";
			tag = "certificate";
			break;
		case SC_PKCS15_TYPE_DATA_OBJECT:
			desc = "data object";
			tag = "data";
			break;
		}
		if (tag)
			break;
		/* If this is a specific type such as
		 * SC_PKCS15_TYPE_CERT_FOOBAR, fall back to
		 * the generic class (SC_PKCS15_TYPE_CERT)
		 */
		if (!(type & ~SC_PKCS15_TYPE_CLASS_MASK)) {
			profile->cbs->error("File type not supported by card driver");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		type &= SC_PKCS15_TYPE_CLASS_MASK;
	}

	snprintf(name, sizeof(name), "template-%s-%d", tag, num+1);
	if (sc_profile_get_file(profile, name, &file) < 0) {
		profile->cbs->error("Profile doesn't define %s template '%s'\n",
				desc, name);
		return SC_ERROR_NOT_SUPPORTED;
	}

	*out = file;
	return 0;
}

static void invert_buf(u8 *dest, const u8 *src, size_t c)
{
        int i;

        for (i = 0; i < c; i++)
                dest[i] = src[c-1-i];
}

static int bn2cf(const BIGNUM *num, u8 *buf)
{
        u8 tmp[512];
        int r;

        r = BN_bn2bin(num, tmp);
        if (r <= 0)
                return r;
        invert_buf(buf, tmp, r);
      
        return r;
}

#if 0
static int gen_d(RSA *rsa)
{
        BN_CTX *ctx, *ctx2;
        BIGNUM *r0, *r1, *r2;
        
        ctx = BN_CTX_new();
        ctx2 = BN_CTX_new();
        BN_CTX_start(ctx);  
        r0 = BN_CTX_get(ctx);
        r1 = BN_CTX_get(ctx);
        r2 = BN_CTX_get(ctx);
        BN_sub(r1, rsa->p, BN_value_one());
        BN_sub(r2, rsa->q, BN_value_one());
        BN_mul(r0, r1, r2, ctx);
        if ((rsa->d = BN_mod_inverse(NULL, rsa->e, r0, ctx2)) == NULL) {
                fprintf(stderr, "BN_mod_inverse() failed.\n");
                return -1;
        }
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        BN_CTX_free(ctx2);
        return 0;
}
#endif

static int cflex_encode_private_key(RSA *rsa, u8 *key, size_t *keysize, int key_num)
{
        u8 buf[512], *p = buf;
	u8 bnbuf[256];
        int base = 0; 
        int r;
        
        switch (BN_num_bits(rsa->n)) {
        case 512:
                base = 32;
                break;
        case 768:
                base = 48;
                break;
        case 1024:
                base = 64;
                break;
        case 2048:
                base = 128;
                break;
        }
        if (base == 0) {
                fprintf(stderr, "Key length invalid.\n");
                return 2;
        }
        *p++ = (5 * base + 3) >> 8;
        *p++ = (5 * base + 3) & 0xFF;
        *p++ = key_num;
        r = bn2cf(rsa->p, bnbuf);
        if (r != base) {
                fprintf(stderr, "Invalid private key.\n");
                return 2;
        }
        memcpy(p, bnbuf, base);
        p += base;

        r = bn2cf(rsa->q, bnbuf);
        if (r != base) {
                fprintf(stderr, "Invalid private key.\n");
                return 2;
        }
        memcpy(p, bnbuf, base);
        p += base;

        r = bn2cf(rsa->iqmp, bnbuf);
        if (r != base) {
                fprintf(stderr, "Invalid private key.\n");
                return 2;
        }
        memcpy(p, bnbuf, base);
        p += base;

        r = bn2cf(rsa->dmp1, bnbuf);
        if (r != base) {
                fprintf(stderr, "Invalid private key.\n");
                return 2;
        }
        memcpy(p, bnbuf, base);
        p += base;

        r = bn2cf(rsa->dmq1, bnbuf);
        if (r != base) {
                fprintf(stderr, "Invalid private key.\n");
                return 2;
        }
        memcpy(p, bnbuf, base);
        p += base;
	*p++ = 0;
	*p++ = 0;
	*p++ = 0;
	
        memcpy(key, buf, p - buf);
        *keysize = p - buf;

        return 0;
}

static int cflex_encode_public_key(RSA *rsa, u8 *key, size_t *keysize, int key_num)
{
        u8 buf[512], *p = buf;
        u8 bnbuf[256];
        int base = 0; 
        int r;
        
        switch (BN_num_bits(rsa->n)) {
        case 512:
                base = 32;
                break;
        case 768:
                base = 48;
                break;
        case 1024:
                base = 64;
                break;
        case 2048:
                base = 128;
                break;
        }
        if (base == 0) {
                fprintf(stderr, "Key length invalid.\n");
                return 2;
        }
        *p++ = (5 * base + 7) >> 8;
        *p++ = (5 * base + 7) & 0xFF;
        *p++ = key_num;
        r = bn2cf(rsa->n, bnbuf);
        if (r != 2*base) {
                fprintf(stderr, "Invalid public key.\n");
                return 2;
        }
        memcpy(p, bnbuf, 2*base);
        p += 2*base;

        memset(p, 0, base);
        p += base;

	memset(bnbuf, 0, 2*base);
        memcpy(p, bnbuf, 2*base);
        p += 2*base;
        r = bn2cf(rsa->e, bnbuf);
        memcpy(p, bnbuf, 4);
        p += 4;
	*p++ = 0;
	*p++ = 0;
	*p++ = 0;

        memcpy(key, buf, p - buf);
        *keysize = p - buf;

        return 0;
}

/*
 * Store a private key
 */
static int
cflex_new_key(struct sc_profile *profile, struct sc_card *card,
		EVP_PKEY *key, unsigned int index,
		struct sc_pkcs15_prkey_info *info)
{
	u8 prv[1024], pub[1024];
	size_t prvsize, pubsize;
	struct sc_file *keyfile = NULL, *tmpfile = NULL;
	RSA *rsa = NULL;
        int r;

	if (key->type != EVP_PKEY_RSA) {
		profile->cbs->error("Cryptoflex supports only RSA keys.");
		return SC_ERROR_NOT_SUPPORTED;
	}
	rsa = EVP_PKEY_get1_RSA(key);
	r = cflex_encode_private_key(rsa, prv, &prvsize, 1);
	if (r)
		goto err;
	r = cflex_encode_public_key(rsa, pub, &pubsize, 1);
	if (r)
		goto err;
	printf("Updating RSA private key...\n");
	r = cflex_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, index,
			    &keyfile);
	if (r < 0)
		goto err;
	keyfile->size = prvsize;
	r = sc_pkcs15init_update_file(profile, card, keyfile, prv, prvsize);
	if (r < 0)
		goto err;
	info->path = keyfile->path;
	info->modulus_length = RSA_size(rsa)*8;
	sc_file_dup(&tmpfile, keyfile);
	sc_file_clear_acl_entries(tmpfile, SC_AC_OP_READ);
	sc_file_add_acl_entry(tmpfile, SC_AC_OP_READ, SC_AC_NONE, SC_AC_KEY_REF_NONE);
	tmpfile->path.len -= 2;
	sc_append_path_id(&tmpfile->path, (const u8 *) "\x10\x12", 2);
	tmpfile->id = 0x1012;
	tmpfile->size = pubsize;
	printf("Updating RSA public key...\n");
	r = sc_pkcs15init_update_file(profile, card, tmpfile, pub, pubsize);
err:
	if (rsa)
		RSA_free(rsa);
	if (tmpfile)
		sc_file_free(tmpfile);
	return r;
}

struct sc_pkcs15init_operations sc_pkcs15init_cflex_operations = {
	NULL,
	cflex_init_app,
	cflex_new_pin,
	cflex_new_key,
	cflex_new_file,
};
