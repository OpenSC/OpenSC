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
#include "cardctl.h"
#include "pkcs15-init.h"
#include "util.h"

/*
 * Update the contents of a PIN file
 */
static int cflex_update_pin(struct sc_card *card, struct pin_info *info)
{
	u8		buffer[23], *p = buffer;
	int		r;
	size_t		len;

	if (!info->attempt[1]) {
		error("Cryptoflex needs a PUK code");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	memset(p, 0xFF, 3);
	p += 3;
	memset(p, info->pkcs15.pad_char, 8);
	strncpy((char *) p, info->secret[0], 8);
	p += 8;
	*p++ = info->attempt[0];
	*p++ = info->attempt[0];
	memset(p, info->pkcs15.pad_char, 8);
	strncpy((char *) p, info->secret[1], 8);
	p += 8;
	*p++ = info->attempt[1];
	*p++ = info->attempt[1];
	len = 23;

	r = sc_update_binary(card, 0, buffer, len, 0);
	if (r < 0)
		return r;
	return 0;
}

/*
 * Create the PIN file and write the PINs
 */
static int cflex_store_pin(struct sc_profile *profile, struct sc_card *card,
			   struct pin_info *info)
{
	struct sc_file	*pinfile;
	int		r;

	sc_file_dup(&pinfile, info->file->file);

	card->ctx->log_errors = 0;
	r = sc_select_file(card, &pinfile->path, NULL);
	card->ctx->log_errors = 1;
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		/* Now create the file */
		if ((r = sc_pkcs15init_create_file(profile, pinfile)) < 0)
			goto out;
		/* The PIN EF is automatically selected */
	} else if (r < 0)
		goto out;

	/* If messing with the PIN file requires any sort of
	 * authentication, send it to the card now */
	if ((r = sc_pkcs15init_authenticate(profile, pinfile, SC_AC_OP_UPDATE)) < 0)
		goto out;

	r = cflex_update_pin(card, info);

out:	sc_file_free(pinfile);
	return r;
}

/*
 * Initialize the Application DF and store the PINs
 *
 */
static int cflex_init_app(struct sc_profile *profile, struct sc_card *card)
{
	struct pin_info	*pin1, *pin2, *pin3;
	int r;

	pin1 = sc_profile_find_pin(profile, "CHV1");
	pin2 = sc_profile_find_pin(profile, "CHV2");
	pin3 = sc_profile_find_pin(profile, "CHV3");
	if (pin1 == NULL) {
		fprintf(stderr, "No CHV1 defined\n");
		return 1;
	}

	card->ctx->log_errors = 0;
	r = sc_select_file(card, &profile->df_info.file->path, NULL);
	card->ctx->log_errors = 1;
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		/* Create the application DF */
		if (sc_pkcs15init_create_file(profile, profile->df_info.file))
			return 1;
	} else if (r < 0) {
		fprintf(stderr, "Unable to select application DF: %s\n",
			sc_strerror(r));
		return 1;
	}

	/* Store CHV3 (ie. SO PIN) */
	if (pin3) {
		if (cflex_store_pin(profile, card, pin3))
			return 1;
	}

	/* Store CHV1 */
	if (cflex_store_pin(profile, card, pin1))
		return 1;

	/* Store CHV2 */
	if (pin2) {
		if (cflex_store_pin(profile, card, pin2))
			return 1;
	}
	
	return 0;
}

/*
 * Allocate a file
 */
static int cflex_allocate_file(struct sc_profile *profile, struct sc_card *card,
		unsigned int type, unsigned int num,
		struct sc_file **out)
{
	struct file_info *templ;
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
			tag = "data";
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
			error("File type not supported by card driver");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		type &= SC_PKCS15_TYPE_CLASS_MASK;
	}

	snprintf(name, sizeof(name), "template-%s-%d", tag, num + 1);
	if (!(templ = sc_profile_find_file(profile, name))) {
		error("Profile doesn't define %s template (%s)",
				desc, name);
		return SC_ERROR_NOT_SUPPORTED;
	}
	sc_file_dup(out, templ->file);

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
 * Store a RSA key on the card
 */
static int cflex_store_rsa_key(struct sc_profile *profile, struct sc_card *card,
		struct sc_key_template *info, RSA *rsa)
{
	u8 prv[1024], pub[1024];
	size_t prvsize, pubsize;
	struct sc_file *tmpfile;
        int r;

	r = cflex_encode_private_key(rsa, prv, &prvsize, 1);
	if (r)
		return -1;
	r = cflex_encode_public_key(rsa, pub, &pubsize, 1);
	if (r)
		return -1;
	info->file->size = prvsize;
	printf("Updating RSA private key...\n");
	r = sc_pkcs15init_update_file(profile, info->file, prv, prvsize);
	if (r < 0)
		return r;
	sc_file_dup(&tmpfile, info->file);
	sc_file_clear_acl_entries(tmpfile, SC_AC_OP_READ);
	sc_file_add_acl_entry(tmpfile, SC_AC_OP_READ, SC_AC_NONE, SC_AC_KEY_REF_NONE);
	tmpfile->path.len -= 2;
	sc_append_path_id(&tmpfile->path, (const u8 *) "\x10\x12", 2);
	tmpfile->id = 0x1012;
	tmpfile->size = pubsize;
	printf("Updating RSA public key...\n");
	r = sc_pkcs15init_update_file(profile, tmpfile, pub, pubsize);
	sc_file_free(tmpfile);
	if (r)
		return r;
		
	return 0;
}

void bind_cflex_operations(struct pkcs15_init_operations *ops)
{
	ops->init_app = cflex_init_app;
	ops->allocate_file = cflex_allocate_file;
	ops->store_rsa = cflex_store_rsa_key;
}
