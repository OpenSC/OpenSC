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
	memset(p, '-', 8);
	strncpy(p, info->secret[0], 8);
	p += 8;
	*p++ = info->attempt[0];
	*p++ = info->attempt[0];
	memset(p, '-', 8);
	strncpy(p, info->secret[0], 8);
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

	/* Now create the file */
	if ((r = sc_pkcs15init_create_file(profile, pinfile)) < 0)
		goto out;

	/* If messing with the PIN file requires any sort of
	 * authentication, send it to the card now */
	if ((r = sc_select_file(card, &pinfile->path, NULL)) < 0
	 || (r = sc_pkcs15init_authenticate(profile, pinfile, SC_AC_OP_UPDATE)) < 0)
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
	struct pin_info	*pin1, *pin2;

	pin1 = sc_profile_find_pin(profile, "CHV1");
	pin2 = sc_profile_find_pin(profile, "CHV2");
	if (pin1 == NULL) {
		fprintf(stderr, "No CHV1 defined\n");
		return 1;
	}

	/* XXX TODO:
	 * if the CHV2 pin file is required to create files
	 * in the application DF, create that file first */

	/* Create the application DF */
	if (sc_pkcs15init_create_file(profile, profile->df_info.file))
		return 1;

	/* Store CHV2 */
	if (pin2) {
		if (cflex_store_pin(profile, card, pin2))
			return 1;
	}

	/* Store CHV1 */
	if (cflex_store_pin(profile, card, pin1))
		return 1;
	
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
	struct sc_file	*file;
	struct sc_path	*p;
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

	snprintf(name, sizeof(name), "template-%s", tag);
	if (!(templ = sc_profile_find_file(profile, name))) {
		error("Profile doesn't define %s template (%s)\n",
				desc, name);
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Now construct file from template */
	sc_file_dup(&file, templ->file);
	file->id += num;

	p = &file->path;
	*p = profile->df_info.file->path;
	p->value[p->len++] = file->id >> 8;
	p->value[p->len++] = file->id;

	*out = file;
	return 0;
}

#if 0
/*
 * Create the PK file
 */
static int gpk_pkfile_create(struct sc_profile *profile, struct sc_card *card,
		struct sc_file *file)
{
	struct sc_file	*found = NULL;
	int		r;

	card->ctx->log_errors = 0;
	r = sc_select_file(card, &file->path, &found);
	card->ctx->log_errors = 1;
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		r = sc_pkcs15init_create_file(profile, file);
		if (r >= 0)
			r = sc_select_file(card, &file->path, &found);
	} else {
		/* XXX: make sure the file has correct type and size? */
	}

	if (r >= 0)
		r = sc_pkcs15init_authenticate(profile, file, SC_AC_OP_UPDATE);
	if (found)
		sc_file_free(found);

	return r;
}

/*
 * Set up the public key record for a signature only public key
 */
static int
gpk_pkfile_init_public(struct sc_card *card, struct sc_file *file,
		unsigned int algo, unsigned int bits,
		unsigned int usage, struct sc_acl_entry *acl)
{
	u8		sysrec[7], buffer[256];
	unsigned int	npins, n;
	int		r;

	/* Set up the system record */
	memset(sysrec, 0, sizeof(sysrec));

	/* XXX: How to map keyUsage to sysrec[2]?
	 * 	0x00	sign & unwrap
	 * 	0x10	sign only
	 * 	0x20	unwrap only
	 * 	0x30	CA key
	 * Which PKCS15 key usage values map to which flag?
	 */
	sysrec[2] = 0x00; /* no restriction for now */

	/* Set the key type and algorithm */
	if ((r = gpk_pkfile_keybits(bits, &sysrec[1])) < 0
	 || (r = gpk_pkfile_keyalgo(algo, &sysrec[5])) < 0)
		return r;

	/* Set PIN protection if requested.  */
	for (npins = 0; acl; acl = acl->next) {
		if (acl->method == SC_AC_NONE
		 || acl->method == SC_AC_NEVER)
			continue;
		if (acl->method == SC_AC_CHV) {
			if (++npins >= 2) {
				error("Too many pins for PrKEY file!\n");
				return SC_ERROR_NOT_SUPPORTED;
			}
			sysrec[2] += 0x40;
			sysrec[3] >>= 4;
			sysrec[3] |= acl->key_ref << 4;
		}
	}

	/* compute checksum - yet another slightly different
	 * checksum algorithm courtesy of Gemplus */
	/* XXX: This is different from what the GPK reference
	 * manual says which tells you to start with 0xA5 -- but
	 * maybe that's just for the GPK8000 */
	for (sysrec[6] = 0xFF, n = 0; n < 6; n++)
		sysrec[6] ^= sysrec[n];

	card->ctx->log_errors = 0;
	r = sc_read_record(card, 1, buffer, sizeof(buffer),
			SC_RECORD_BY_REC_NR);
	card->ctx->log_errors = 1;
	if (r >= 0) {
		if (r != 7 || buffer[0] != 0) {
			error("first record of public key file is not Lsys0");
			return SC_ERROR_OBJECT_NOT_VALID;
		}

		r = sc_update_record(card, 1, sysrec, sizeof(sysrec),
				SC_RECORD_BY_REC_NR);
	} else {
		r = sc_append_record(card, sysrec, sizeof(sysrec), 0);
	}
	return r;
}

static int
gpk_pkfile_update_public(struct sc_card *card, struct pkpart *part)
{
	struct pkcomp	*pe;
	unsigned char	buffer[256];
	unsigned int	m, n, tag;
	int		r = 0, found;

	if (card->ctx->debug > 1)
		printf("Updating public key elements\n");

	/* If we've been given a key with public parts, write them now */
	for (n = 2; n < 256; n++) {
		card->ctx->log_errors = 0;
		r = sc_read_record(card, n, buffer, sizeof(buffer),
				SC_RECORD_BY_REC_NR);
		card->ctx->log_errors = 1;
		if (r < 0) {
			r = 0;
			break;
		}

		/* Check for bad record */
		if (r < 2) {
			error("key file format error: "
				"record %u too small (%u bytes)\n", 
				n, r);
			return SC_ERROR_OBJECT_NOT_VALID;
		}

		tag = buffer[0];

		for (m = 0, found = 0; m < part->count; m++) {
			pe = part->components + m;
			if (pe->tag == tag) {
				r = sc_update_record(card, n,
						pe->data, pe->size,
						SC_RECORD_BY_REC_NR);
				if (r < 0)
					return r;
				pe->tag = 0; /* mark as stored */
				found++;
				break;
			}
		}

		if (!found && card->ctx->debug)
			printf("GPK unknown PK tag %u\n", tag);
	}

	/* Write all remaining elements */
	for (m = 0; r >= 0 && m < part->count; m++) {
		pe = part->components + m;
		if (pe->tag != 0)
			r = sc_append_record(card, pe->data, pe->size, 0);
	}

	return r;
}

static int
gpk_pkfile_init_private(struct sc_card *card,
		struct sc_file *file, unsigned int privlen)
{
	struct sc_cardctl_gpk_pkinit args;

	if (card->ctx->debug > 1)
		printf("Initializing private key portion of file\n");
	args.file = file;
	args.privlen = privlen;
	return sc_card_ctl(card, SC_CARDCTL_GPK_PKINIT, &args);
}

static int
gpk_pkfile_load_private(struct sc_card *card, struct sc_file *file,
			u8 *data, unsigned int len, unsigned int datalen)
{
	struct sc_cardctl_gpk_pkload args;

	args.file = file;
	args.data = data;
	args.len  = len;
	args.datalen = datalen;
	return sc_card_ctl(card, SC_CARDCTL_GPK_PKLOAD, &args);
}

static int
gpk_pkfile_update_private(struct sc_profile *profile,
			struct sc_card *card, struct sc_file *file,
			struct pkpart *part)
{
	struct auth_info *sm;
	unsigned int	m, size, nb, cks;
	struct pkcomp	*pe;
	u8		data[256];
	int		r = 0;

	if (card->ctx->debug > 1)
		printf("Updating private key elements\n");

	/* We must set a secure messaging key before each Load Private Key
	 * command. Any key will do...
	 * The GPK _is_ weird. */
	sm = sc_profile_find_key(profile, SC_AC_PRO, -1);
	if (sm == NULL) {
		error("No secure messaging key defined by profile");
		return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
	}

	for (m = 0; m < part->count; m++) {
		pe = part->components + m;

		if (pe->size + 8 > sizeof(data))
			return SC_ERROR_BUFFER_TOO_SMALL;
		memcpy(data, pe->data, pe->size);
		size = pe->size;

		r = sc_verify(card, SC_AC_PRO,
			       	sm->ref, sm->key, sm->key_len, NULL);
		if (r < 0)
			break;

		/* Pad out data to a multiple of 8 and checksum.
		 * The GPK manual is a bit unclear about whether you
		 * checksum first and then pad, or vice versa.
		 * The following code does seem to work though: */
		for (nb = 0, cks = 0xff; nb < size; nb++)
			cks ^= data[nb];
		data[nb++] = cks;
		while (nb & 7)
			data[nb++] = 0;

		r = gpk_pkfile_load_private(card, file, data, size, nb);
		if (r < 0)
			break;
		pe++;
	}
	return r;
}

/* Sum up the size of the public key elements
 * Each element is type + tag + bignum
 */
static void
gpk_compute_publen(struct pkpart *part)
{
	unsigned int	n, publen = 8;	/* length of sysrec0 */

	for (n = 0; n < part->count; n++)
		publen += 2 + part->components[n].size;
	part->size = (publen + 3) & ~3UL;
}

/* Sum up the size of the private key elements
 * Each element is type + tag + bignum + checksum, padded to a multiple
 * of eight
 */
static void
gpk_compute_privlen(struct pkpart *part)
{
	unsigned int	n, privlen = 8;

	for (n = 0; n < part->count; n++)
		privlen += (3 + part->components[n].size + 7) & ~7UL;
	part->size = privlen;
}

/*
 * Convert BIGNUM to GPK representation, optionally zero padding to size.
 * Note OpenSSL stores BIGNUMs big endian while the GPK wants them
 * little endian
 */
static void
gpk_bn2bin(const BIGNUM *bn, unsigned char *dest, unsigned int size)
{
	u8		temp[256], *src;
	unsigned int	n, len;

	assert(BN_num_bytes(bn) <= sizeof(temp));
	len = BN_bn2bin(bn, temp);

	assert(len <= size);
	for (n = 0, src = temp + len - 1; n < len; n++)
		dest[n] = *src--;
	for (; n < size; n++)
		dest[n] = '\0';
}

/*
 * Add a BIGNUM component, optionally padding out the number to size bytes
 */
static void
gpk_add_bignum(struct pkpart *part, unsigned int tag, BIGNUM *bn, size_t size)
{
	struct pkcomp	*comp;
	
	if (size == 0)
		size = BN_num_bytes(bn);

	comp = &part->components[part->count++];
	memset(comp, 0, sizeof(*comp));
	comp->tag  = tag;
	comp->size = size + 1;
	comp->data = malloc(size + 1);

	/* Add the tag */
	comp->data[0] = tag;

	/* Add the BIGNUM */
	gpk_bn2bin(bn, comp->data + 1, size);

	/* printf("TAG 0x%02x, len=%u\n", tag, comp->size); */
}

int
gpk_encode_rsa_key(RSA *rsa, struct pkdata *p, unsigned int usage)
{
	if (!rsa->n || !rsa->e) {
		error("incomplete RSA public key");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Make sure the exponent is 0x10001 because that's
	 * the only exponent supported by GPK4000 and GPK8000 */
	if (!BN_is_word(rsa->e, RSA_F4)) {
		error("unsupported RSA exponent");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	memset(p, 0, sizeof(*p));
	p->algo  = SC_ALGORITHM_RSA;
	p->usage = usage;
	p->bits  = BN_num_bits(rsa->n);
	p->bytes = BN_num_bytes(rsa->n);

	/* Set up the list of public elements */
	gpk_add_bignum(&p->public, 0x01, rsa->n, 0);
	gpk_add_bignum(&p->public, 0x07, rsa->e, 0);

	/* Set up the list of private elements */
	if (!rsa->p || !rsa->q || !rsa->dmp1 || !rsa->dmq1 || !rsa->iqmp) {
		/* No or incomplete CRT information */
		if (!rsa->d) {
			error("incomplete RSA private key");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		gpk_add_bignum(&p->private, 0x04, rsa->d, 0);
	} else if (5 * (p->bytes / 2) < 256) {
		/* All CRT elements are stored in one record */
		struct pkcomp	*comp;
		unsigned int	K = p->bytes / 2;
		u8		*crtbuf;

		crtbuf = malloc(5 * K + 1);

		crtbuf[0] = 0x05;
		gpk_bn2bin(rsa->p,    crtbuf + 1, K);
		gpk_bn2bin(rsa->q,    crtbuf + 1 + 1 * K, K);
		gpk_bn2bin(rsa->iqmp, crtbuf + 1 + 2 * K, K);
		gpk_bn2bin(rsa->dmp1, crtbuf + 1 + 3 * K, K);
		gpk_bn2bin(rsa->dmq1, crtbuf + 1 + 4 * K, K);

		comp = &p->private.components[p->private.count++];
		comp->tag  = 0x05;
		comp->size = 5 * K + 1;
		comp->data = crtbuf;
	} else {
		/* CRT elements stored in individual records.
		 * Make sure they're all fixed length even if they're
		 * shorter */
		gpk_add_bignum(&p->private, 0x51, rsa->p, p->bytes/2);
		gpk_add_bignum(&p->private, 0x52, rsa->q, p->bytes/2);
		gpk_add_bignum(&p->private, 0x53, rsa->iqmp, p->bytes/2);
		gpk_add_bignum(&p->private, 0x54, rsa->dmp1, p->bytes/2);
		gpk_add_bignum(&p->private, 0x55, rsa->dmq1, p->bytes/2);
	}

	return 0;
}

/*
 * Encode a DSA key.
 * Confusingly, the GPK manual says that the GPK8000 can handle
 * DSA with 512 as well as 1024 bits, but all byte sizes shown
 * in the tables are 512 bits only...
 */
int
gpk_encode_dsa_key(DSA *dsa, struct pkdata *p, unsigned int usage)
{
	if (!dsa->p || !dsa->q || !dsa->g || !dsa->pub_key || !dsa->priv_key) {
		error("incomplete DSA public key");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	memset(p, 0, sizeof(*p));
	p->algo  = SC_ALGORITHM_RSA;
	p->usage = usage;
	p->bits  = BN_num_bits(dsa->p);
	p->bytes = BN_num_bytes(dsa->p);

	/* Make sure the key is either 512 or 1024 bits */
	if (p->bytes <= 64) {
		p->bits  = 512;
		p->bytes = 64;
	} else if (p->bytes <= 128) {
		p->bits  = 1024;
		p->bytes = 128;
	} else {
		error("incompatible DSA key size (%u bits)", p->bits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Set up the list of public elements */
	gpk_add_bignum(&p->public, 0x09, dsa->p, 0);
	gpk_add_bignum(&p->public, 0x0a, dsa->q, 0);
	gpk_add_bignum(&p->public, 0x0b, dsa->g, 0);
	gpk_add_bignum(&p->public, 0x0c, dsa->pub_key, 0);

	/* Set up the list of private elements */
	gpk_add_bignum(&p->private, 0x0d, dsa->priv_key, 0);

	return 0;
}

static int
gpk_store_pk(struct sc_profile *profile, struct sc_card *card,
		struct sc_file *file, struct pkdata *p,
		struct sc_acl_entry *key_acl)
{
	int r;

	/* Compute length of private/public key parts */
	gpk_compute_publen(&p->public);
	gpk_compute_privlen(&p->private);

	if (card->ctx->debug)
		printf("Storing pk: %u bits, pub %u bytes, priv %u bytes\n",
				p->bits, p->bytes, p->private.size);

	/* Strange, strange, strange... when I create the public part with
	 * the exact size of 8 + PK elements, the card refuses to store
	 * the last record even though there's enough room in the file.
	 * XXX: Check why */
	file->size = p->public.size + 8 + p->private.size + 8;
	r = gpk_pkfile_create(profile, card, file);
	if (r < 0)
		return r;

	/* Put the system record */
	r = gpk_pkfile_init_public(card, file, p->algo,
		       	p->bits, p->usage, key_acl);
	if (r < 0)
		return r;

	/* Put the public key elements */
	r = gpk_pkfile_update_public(card, &p->public);
	if (r < 0)
		return r;

	/* Create the private key part */
	r = gpk_pkfile_init_private(card, file, p->private.size);
	if (r < 0)
		return r;

	/* Now store the private key elements */
	r = gpk_pkfile_update_private(profile, card, file, &p->private);

	return r;
}

/*
 * Store a RSA key on the card
 */
static int gpk_store_rsa_key(struct sc_profile *profile, struct sc_card *card,
		struct sc_key_template *info, RSA *rsa)
{
	struct pkdata	data;
	int		r;

	if ((r = gpk_encode_rsa_key(rsa, &data, info->pkcs15.priv.usage)) < 0)
		return r;
	return gpk_store_pk(profile, card, info->file, &data, info->key_acl);
}
#endif

void bind_cflex_operations(struct pkcs15_init_operations *ops)
{
	ops->init_app = cflex_init_app;
	ops->allocate_file = cflex_allocate_file;
//	ops->store_rsa = gpk_store_rsa_key;
}
