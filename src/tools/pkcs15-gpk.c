/*
 * GPK specific operation for PKCS15 initialization
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
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

#define GPK_MAX_PINS		8
#define GPK_FTYPE_SECRET_CODE	0x21
#define GPK_FTYPE_PUBLIC_KEY	0x2C

/*
 * Erase the card
 */
static int
gpk_erase_card(struct sc_profile *pro, struct sc_card *card)
{
	return sc_card_ctl(card, SC_CARDCTL_ERASE_CARD, NULL);
}

/*
 * Lock a file operation
 */
static int
gpk_lock(struct sc_card *card, struct sc_file *file, unsigned int op)
{
	struct sc_cardctl_gpk_lock	args;

	args.file = file;
	args.operation = op;
	return sc_card_ctl(card, SC_CARDCTL_GPK_LOCK, &args);
}

/*
 * Update the contents of a PIN file
 */
static int
gpk_update_pins(struct sc_card *card, struct pin_info *info)
{
	u8		buffer[GPK_MAX_PINS * 8], *blk;
	u8		temp[16];
	unsigned int	npins, i, j, tries, cks;
	int		r;

	npins = info->attempt[1]? 2 : 1;

	memset(buffer, 0, sizeof(buffer));
	for (i = 0, blk = buffer; i < npins; i++, blk += 8) {
		tries = info->attempt[i];
		if (tries == 0 || tries > 7) {
			/*
			error("invalid number of PIN attempts %u "
					"(must be 1 ... 7)",
					tries);
			 */
			return SC_ERROR_INVALID_ARGUMENTS;
		}

		blk[0] = tries;
		if (i < npins)
			blk[2] = 0x8 | (i + 1);

		memset(temp, 0, sizeof(temp));
		strncpy((char *) temp, info->secret[i], 8);
		blk[4] = (temp[0] << 4) | (temp[1] & 0xF);
		blk[5] = (temp[2] << 4) | (temp[3] & 0xF);
		blk[6] = (temp[4] << 4) | (temp[5] & 0xF);
		blk[7] = (temp[6] << 4) | (temp[7] & 0xF);

		/* Compute the CKS */
		for (j = 0, cks = 0; j < 8; j++)
			cks ^= blk[j];
		blk[3] = ~cks;
	}

	r = sc_update_binary(card, info->file_offset, buffer, npins * 8, 0);

	return r < 0;
}

/*
 * Create the PIN file and write the PINs
 */
static int
gpk_store_pin(struct sc_profile *profile, struct sc_card *card,
		struct pin_info *info, int *lockit)
{
	const struct sc_acl_entry *acl;
	struct sc_file	*pinfile;
	int		r;

	sc_file_dup(&pinfile, info->file->file);

	/* Create the PIN file. If the UPDATE AC is NEVER,
	 * we change it to NONE so we're able to init the
	 * file, and then lock it.
	 * If the UPDATE AC is anything else, we assume that
	 * we have the required keys/pins to be granted access. */
	acl = sc_file_get_acl_entry(pinfile, SC_AC_OP_UPDATE);
	if (acl->method == SC_AC_NEVER) {
		sc_file_add_acl_entry(pinfile, SC_AC_OP_UPDATE, SC_AC_NONE, 0);
		*lockit = 1;
	}
	for (; acl; acl = acl->next) {
		if (acl->method == SC_AC_CHV) {
			fprintf(stderr,
				"CHV protected PIN files not supported\n");
			r = SC_ERROR_INVALID_ARGUMENTS;
			goto out;
		}
	}

	/* Now create the file */
	if ((r = sc_pkcs15init_create_file(profile, pinfile)) < 0)
		goto out;

	/* If messing with the PIN file requires any sort of
	 * authentication, send it to the card now */
	if ((r = sc_select_file(card, &pinfile->path, NULL)) < 0
	 || (r = sc_pkcs15init_authenticate(profile, pinfile, SC_AC_OP_UPDATE)) < 0)
		goto out;

	r = gpk_update_pins(card, info);

out:	sc_file_free(pinfile);
	return r;
}

static int
gpk_lock_pinfile(struct sc_profile *profile, struct sc_card *card,
		struct sc_file *pinfile)
{
	struct sc_path	path;
	struct sc_file	*parent = NULL;
	int		r;

	/* Select the parent DF */
	path = pinfile->path;
	if (path.len >= 2)
		path.len -= 2;
	if (path.len == 0)
		sc_format_path("3F00", &path);
	if ((r = sc_select_file(card, &path, &parent)) < 0)
		return r;

	/* Present PINs etc as necessary */
	if (!(r = sc_pkcs15init_authenticate(profile, parent, SC_AC_OP_LOCK)))
		r = gpk_lock(card, pinfile, SC_AC_OP_UPDATE);

	sc_file_free(parent);
	return r;
}

/*
 * Initialize the Application DF and store the PINs
 *
 * Restrictions:
 * For the GPK, it's fairly tricky to store the CHV1 in a
 * file and protect the update operation with CHV2.
 *
 * There are two properties of the GPK that make this difficult:
 *  -	you can have only one secret key file per DF
 *
 *  -	you cannot create the file without PIN protection, then
 *  	write the contents, then set the PIN protection. The GPK
 *  	has a somewhat cumbersome feature where you first protect
 *  	the file with the global PIN, write to it after presenting
 *  	the global PIN, and then "localize" the access condition,
 *  	telling it to use the local PIN EF instead of the global
 *  	one.
 *
 *  A.	Put CHV2 into the MF. This works, but makes dealing with
 *  	CHV2 tricky for applications, because you must first select
 *  	the DF in which the PIN file resides, and then call Verify.
 *
 *  B.	Store both CHV1 and CHV2 in the same PIN file in the 
 *  	application DF. But in order to allow CHV2 to update the
 *  	PIN file directly using you need to create a global PIN file in
 *  	the MF first, and "localize" the application pin file's
 *  	access conditions later.
 *
 * Neither option is really appealing, which is why for now, I
 * simply reject CHV protected pin files.
 */
static int
gpk_init_app(struct sc_profile *profile, struct sc_card *card)
{
	struct pin_info	*pin1, *pin2;
	int		lockit = 0;

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
	lockit = 0;
	if (pin2) {
		if (gpk_store_pin(profile, card, pin2, &lockit))
			return 1;
		/* If both PINs reside in the same file, don't lock
		 * it yet. */
		if (pin1->file != pin2->file && lockit) {
			if (gpk_lock_pinfile(profile, card, pin2->file->file))
				return 1;
			lockit = 0;
		}
	}

	/* Store CHV1 */
	if (gpk_store_pin(profile, card, pin1, &lockit))
		return 1;
	
	if (lockit && gpk_lock_pinfile(profile, card, pin2->file->file))
		return 1;

	return 0;
}

/*
 * Allocate a file
 */
static int
gpk_allocate_file(struct sc_profile *profile, struct sc_card *card,
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
#ifdef SC_PKCS15_TYPE_PRKEY_DSA
		case SC_PKCS15_TYPE_PRKEY_RSA:
			desc = "RSA private key";
			tag = "data";
			break;
		case SC_PKCS15_TYPE_PUBKEY_RSA:
			desc = "RSA public key";
			tag = "data";
			break;
#endif
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

/*
 * GPK public/private key file handling is hideous.
 * 600 lines of coke sweat and tears...
 */
struct pkcomp {
	unsigned char	tag;
	u8 *		data;
	unsigned int	size;
};
struct pkdata {
	unsigned int	algo;
	unsigned int	usage;
	struct pkpart {
		struct pkcomp	components[7];
		unsigned int	count;
		unsigned int	size;
	}		public, private;
	unsigned int	bits, bytes;
};

/*
 * Create the PK file
 * XXX: Handle the UPDATE ACL = NEVER case just like for EFsc files
 */
static int
gpk_pkfile_create(struct sc_profile *profile, struct sc_card *card,
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

static int
gpk_pkfile_keybits(unsigned int bits, unsigned char *p)
{
	switch (bits) {
	case  512: *p = 0x00; return 0;
	case  768: *p = 0x10; return 0;
	case 1024: *p = 0x11; return 0;
	}
	return SC_ERROR_NOT_SUPPORTED;
}

static int
gpk_pkfile_keyalgo(unsigned int algo, unsigned char *p)
{
	switch (algo) {
	case SC_ALGORITHM_RSA: *p = 0x00; return 0;
	case SC_ALGORITHM_DSA: *p = 0x01; return 0;
	}
	return SC_ERROR_NOT_SUPPORTED;
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
	int	r;

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
static int
gpk_store_rsa_key(struct sc_profile *profile, struct sc_card *card,
		struct sc_key_template *info, RSA *rsa)
{
	struct pkdata	data;
	int		r;

	if ((r = gpk_encode_rsa_key(rsa, &data, info->pkcs15.priv.usage)) < 0)
		return r;
	return gpk_store_pk(profile, card, info->file, &data, info->key_acl);
}

/*
 * Store a DSA key on the card
 */
static int
gpk_store_dsa_key(struct sc_profile *profile, struct sc_card *card,
		struct sc_key_template *info, DSA *dsa)
{
	struct pkdata	data;
	int		r;

	if ((r = gpk_encode_dsa_key(dsa, &data, info->pkcs15.priv.usage)) < 0)
		return r;
	return gpk_store_pk(profile, card, info->file, &data, info->key_acl);
}

#ifdef notdef
static int
gpk_bin2bn(const unsigned char *src, unsigned int len, BIGNUM **bn)
{
	unsigned char	num[1024];
	unsigned int	n;

	if (len > sizeof(num)) {
		error("number too big (%u bits)?", len * 8);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	for (n = 0; n < len; n++)
		num[n] = src[len-1-n];

	*bn = BN_bin2bn(num, len, *bn);
	return 0;
}
#endif

void
bind_gpk_operations(struct pkcs15_init_operations *ops)
{
	ops->erase_card = gpk_erase_card;
	ops->init_app = gpk_init_app;
	ops->allocate_file = gpk_allocate_file;
	ops->store_rsa = gpk_store_rsa_key;
	ops->store_dsa = gpk_store_dsa_key;
}
