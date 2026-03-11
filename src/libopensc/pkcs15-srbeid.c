/*
 * pkcs15-srbeid.c: PKCS#15 emulation for Serbian cards using the
 *                 CardEdge PKI applet.
 *
 * Copyright (C) 2026  LibreSCRS contributors
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#ifdef ENABLE_ZLIB
#include "compression.h"
#endif
#include "internal.h"
#include "log.h"
#include "pkcs15.h"

/* CardEdge PKI applet AID  (A0 00 00 00 63 50 4B 43 53 2D 31 35) */
static const u8 AID_PKCS15[] = {
	0xA0, 0x00, 0x00, 0x00, 0x63,
	0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35
};
#define AID_PKCS15_LEN	(sizeof(AID_PKCS15))

/* CardEdge cmapfile constants. */
#define CE_CMAP_RECORD_SIZE	86u
#define CE_CMAP_FLAGS_OFFSET	80u
#define CE_CMAP_SIG_SIZE_OFFSET	82u
#define CE_CMAP_KX_SIZE_OFFSET	84u
#define CE_CMAP_VALID_CONTAINER	0x01u
#define CE_KEYS_BASE_FID	0x6000u
#define CE_KEY_KIND_PRIVATE	1u
#define CE_AT_KEYEXCHANGE	1u
#define CE_AT_SIGNATURE		2u
#define CE_PKI_ROOT_DIR_FID	0x7000u
#define CE_DIR_HEADER_SIZE	10u
#define CE_DIR_ENTRY_SIZE	12u

/* CardEdge PIN constants */
#define CE_PIN_REFERENCE	0x80u
#define CE_PIN_MAX_LENGTH	8u

/* Private key FID formula. */
static unsigned int ce_private_key_fid(unsigned int cont_idx,
	unsigned int key_pair_id)
{
	return CE_KEYS_BASE_FID
		| ((cont_idx    << 4) & 0x0FF0u)
		| ((key_pair_id << 2) & 0x000Cu)
		| CE_KEY_KIND_PRIVATE;
}

/*
 * Select FID and read the entire file into a malloc'd buffer.
 * Uses sc_select_file() (dispatched to card driver's select_file which
 * handles CardEdge's proprietary FCI) and sc_read_binary().
 *
 * *out_len receives the byte count; caller must free() the buffer.
 * Returns SC_SUCCESS or a negative SC_ERROR_* code.
 */
static int srbeid_read_file(sc_card_t *card, unsigned int fid,
	u8 **buf_out, size_t *out_len)
{
	sc_path_t path;
	sc_file_t *file = NULL;
	u8 *buf;
	int r;

	*buf_out = NULL;
	*out_len = 0;

	memset(&path, 0, sizeof(path));
	path.value[0] = (u8)((fid >> 8) & 0xFF);
	path.value[1] = (u8)(fid & 0xFF);
	path.len  = 2;
	path.type = SC_PATH_TYPE_FILE_ID;

	r = sc_select_file(card, &path, &file);
	if (r < 0)
		return r;

	if (!file || file->size == 0) {
		sc_file_free(file);
		return SC_SUCCESS;
	}

	buf = malloc(file->size);
	if (!buf) {
		sc_file_free(file);
		return SC_ERROR_OUT_OF_MEMORY;
	}

	r = sc_read_binary(card, 0, buf, file->size, 0);
	sc_file_free(file);
	if (r < 0) {
		free(buf);
		return r;
	}

	*buf_out = buf;
	*out_len = (size_t)r;
	return SC_SUCCESS;
}

/* One entry from a CardEdge directory file. */
typedef struct ce_dir_entry {
	char     name[9];   /* 8-char name + NUL */
	unsigned fid;
	int      is_dir;
} ce_dir_entry_t;

/*
 * Parse a CardEdge directory file into an array of ce_dir_entry_t.
 *
 * CardEdge directories use a proprietary binary format:
 *   [10-byte header] [12-byte entries...]
 * This is NOT ISO 7816-4 EF.DIR (ASN.1 BER-TLV application templates),
 * so standard sc_enum_apps() / iso7816_read_ef_dir() cannot be used.
 *
 * *entries_out: caller must free().  Returns entry count or -1 on error.
 */
static int ce_parse_dir(const u8 *data, size_t len, ce_dir_entry_t **entries_out)
{
	size_t count, i;
	ce_dir_entry_t *entries;

	*entries_out = NULL;
	if (len < CE_DIR_HEADER_SIZE)
		return -1;

	count = (size_t)data[6] | ((size_t)data[7] << 8);
	if (count == 0)
		return 0;

	entries = calloc(count, sizeof(*entries));
	if (!entries)
		return -1;

	for (i = 0; i < count; i++) {
		size_t off = CE_DIR_HEADER_SIZE + i * CE_DIR_ENTRY_SIZE;
		int k;

		if (off + CE_DIR_ENTRY_SIZE > len) {
			free(entries);
			return -1;
		}
		/* Name: up to 8 ASCII chars, may not be NUL-terminated on card. */
		memcpy(entries[i].name, data + off, 8);
		entries[i].name[8] = '\0';
		/* Strip trailing spaces/NULs. */
		k = 7;
		while (k >= 0 && (entries[i].name[k] == ' ' || entries[i].name[k] == '\0'))
			entries[i].name[k--] = '\0';
		entries[i].fid    = (unsigned)data[off + 8] | ((unsigned)data[off + 9] << 8);
		entries[i].is_dir = (data[off + 10] != 0);
	}

	*entries_out = entries;
	return (int)count;
}

typedef struct cert_entry {
	char     label[32];
	unsigned cert_fid;
	unsigned key_fid;
	unsigned key_size_bits;
	unsigned cont_id;
	unsigned key_pair_id;  /* CE_AT_KEYEXCHANGE or CE_AT_SIGNATURE */
} cert_entry_t;

/* Select AID_PKCS15 and enumerate certificates from mscp/cmapfile.
 * *certs_out: caller must free().  Returns cert count or negative error. */
static int srbeid_enum_certs(sc_card_t *card, cert_entry_t **certs_out)
{
	u8 *dir_buf = NULL, *mscp_buf = NULL, *cmap_buf = NULL;
	size_t dir_len = 0, mscp_len = 0, cmap_len = 0;
	ce_dir_entry_t *root_entries = NULL, *mscp_entries = NULL;
	int root_count = 0, mscp_count = 0;
	unsigned mscp_fid = 0, cmap_fid = 0;
	cert_entry_t *certs = NULL;
	int ncerts = 0, cap = 8;
	int r, i;
	size_t cmap_offset = 0, cmap_nrec = 0;

	*certs_out = NULL;

	/* Select PKI applet. */
	if (iso7816_select_aid(card, AID_PKCS15, AID_PKCS15_LEN, NULL, NULL) != SC_SUCCESS) {
		r = SC_ERROR_CARD_CMD_FAILED;
		goto out;
	}

	/* Read root directory (FID 0x7000). */
	r = srbeid_read_file(card, CE_PKI_ROOT_DIR_FID, &dir_buf, &dir_len);
	if (r < 0)
		goto out;

	root_count = ce_parse_dir(dir_buf, dir_len, &root_entries);
	if (root_count < 0) {
		r = SC_ERROR_INVALID_DATA;
		goto out;
	}

	for (i = 0; i < root_count; i++) {
		if (root_entries[i].is_dir && strcmp(root_entries[i].name, "mscp") == 0) {
			mscp_fid = root_entries[i].fid;
			break;
		}
	}
	if (mscp_fid == 0) {
		r = SC_ERROR_FILE_NOT_FOUND;
		goto out;
	}

	/* Read mscp directory. */
	r = srbeid_read_file(card, mscp_fid, &mscp_buf, &mscp_len);
	if (r < 0)
		goto out;

	mscp_count = ce_parse_dir(mscp_buf, mscp_len, &mscp_entries);
	if (mscp_count < 0) {
		r = SC_ERROR_INVALID_DATA;
		goto out;
	}

	certs = calloc((size_t)cap, sizeof(*certs));
	if (!certs) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	for (i = 0; i < mscp_count; i++) {
		ce_dir_entry_t *e = &mscp_entries[i];
		if (e->is_dir)
			continue;

		if (strcmp(e->name, "cmapfile") == 0) {
			cmap_fid = e->fid;
		} else if (strlen(e->name) == 5) {
			unsigned kp_id;
			const char *lbl;

			if (strncmp(e->name, "kxc", 3) == 0) {
				kp_id = CE_AT_KEYEXCHANGE;
				lbl   = "Key Exchange Certificate";
			} else if (strncmp(e->name, "ksc", 3) == 0) {
				kp_id = CE_AT_SIGNATURE;
				lbl   = "Digital Signature Certificate";
			} else {
				continue;
			}

			if (ncerts >= cap) {
				cert_entry_t *tmp = realloc(certs,
					(size_t)(cap * 2) * sizeof(*certs));
				if (!tmp) {
					r = SC_ERROR_OUT_OF_MEMORY;
					goto out;
				}
				certs = tmp;
				cap  *= 2;
			}

			certs[ncerts].cont_id     = (unsigned)(e->name[3] - '0') * 10
				+ (unsigned)(e->name[4] - '0');
			certs[ncerts].cert_fid    = e->fid;
			certs[ncerts].key_pair_id = kp_id;
			snprintf(certs[ncerts].label, sizeof(certs[ncerts].label), "%s", lbl);
			ncerts++;
		}
	}

	/* Read cmapfile and resolve key FIDs. */
	if (cmap_fid != 0) {
		r = srbeid_read_file(card, cmap_fid, &cmap_buf, &cmap_len);
		if (r == SC_SUCCESS) {
			/* Optional 2-byte prefix present when (len-2) is a multiple of 86. */
			if (cmap_len >= 2 && (cmap_len - 2) % CE_CMAP_RECORD_SIZE == 0)
				cmap_offset = 2;
			cmap_nrec = (cmap_len - cmap_offset) / CE_CMAP_RECORD_SIZE;
		}
	}

	for (i = 0; i < ncerts; i++) {
		unsigned ci = certs[i].cont_id;

		if (cmap_buf && ci < cmap_nrec) {
			size_t rec  = cmap_offset + (size_t)ci * CE_CMAP_RECORD_SIZE;
			u8 flags    = cmap_buf[rec + CE_CMAP_FLAGS_OFFSET];

			if (flags & CE_CMAP_VALID_CONTAINER) {
				size_t sz_off = (certs[i].key_pair_id == CE_AT_KEYEXCHANGE)
					? rec + CE_CMAP_KX_SIZE_OFFSET
					: rec + CE_CMAP_SIG_SIZE_OFFSET;
				unsigned kbits = (unsigned)cmap_buf[sz_off]
					| ((unsigned)cmap_buf[sz_off + 1] << 8);
				if (kbits != 0) {
					certs[i].key_size_bits = kbits;
					certs[i].key_fid = ce_private_key_fid(ci, certs[i].key_pair_id);
				}
			}
		}
		sc_log(card->ctx,
			"srbeid: cert[%d] \"%s\" cert_fid=0x%04x key_fid=0x%04x key_size=%u",
			i, certs[i].label, certs[i].cert_fid,
			certs[i].key_fid, certs[i].key_size_bits);
	}

	*certs_out = certs;
	certs = NULL;
	r = ncerts;

out:
	free(dir_buf);
	free(mscp_buf);
	free(cmap_buf);
	free(root_entries);
	free(mscp_entries);
	free(certs);
	return r;
}

/*
 * Read the raw (possibly zlib-compressed) cert file and return DER bytes.
 *
 * CardEdge cert file layout:
 *   [CardFS len prefix: 2 bytes LE]
 *   [0x01 0x00] [uncompressed len: 2 bytes LE] [zlib data]  — compressed
 *   OR [0x30 ...]                                            — raw DER
 */
static int srbeid_read_cert_der(sc_card_t *card, unsigned cert_fid,
	u8 **der_out, size_t *der_len_out)
{
	u8 *raw = NULL;
	size_t raw_len = 0;
	const u8 *data;
	size_t dlen;
	int r;

	*der_out     = NULL;
	*der_len_out = 0;

	r = srbeid_read_file(card, cert_fid, &raw, &raw_len);
	if (r < 0)
		return r;

	if (raw_len < 6) {
		free(raw);
		return SC_ERROR_INVALID_DATA;
	}

	/* Skip 2-byte CardFS length prefix. */
	data = raw + 2;
	dlen = raw_len - 2;

	if (dlen >= 4 && data[0] == 0x01 && data[1] == 0x00) {
		/* zlib-compressed DER */
#ifdef ENABLE_ZLIB
		size_t uncompressed_len = (size_t)data[2] | ((size_t)data[3] << 8);
		u8 *der = NULL;

		r = sc_decompress_alloc(&der, &uncompressed_len,
			data + 4, dlen - 4, COMPRESSION_ZLIB);
		if (r != SC_SUCCESS) {
			sc_log(card->ctx, "srbeid: zlib decompress failed (ret=%d)", r);
			free(raw);
			return SC_ERROR_INVALID_DATA;
		}
		*der_out     = der;
		*der_len_out = uncompressed_len;
#else
		sc_log(card->ctx, "srbeid: cert is zlib-compressed but zlib not available");
		free(raw);
		return SC_ERROR_NOT_SUPPORTED;
#endif
	} else if (dlen >= 1 && data[0] == 0x30) {
		/* Uncompressed DER (ASN.1 SEQUENCE tag). */
		u8 *der = malloc(dlen);
		if (!der) {
			free(raw);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		memcpy(der, data, dlen);
		*der_out     = der;
		*der_len_out = dlen;
	} else {
		sc_log(card->ctx,
			"srbeid: cert FID 0x%04x: unknown format (byte0=0x%02x)",
			cert_fid, data[0]);
		free(raw);
		return SC_ERROR_INVALID_DATA;
	}

	free(raw);
	return SC_SUCCESS;
}

static int sc_pkcs15emu_srbeid_init(sc_pkcs15_card_t *p15card)
{
	sc_card_t    *card = p15card->card;
	cert_entry_t *certs = NULL;
	int           ncerts, i, r = SC_SUCCESS;

	sc_log(card->ctx, "srbeid: pkcs15 bind");

	ncerts = srbeid_enum_certs(card, &certs);
	if (ncerts < 0) {
		sc_log(card->ctx, "srbeid: cert enumeration failed: %d", ncerts);
		return ncerts;
	}
	if (ncerts == 0) {
		sc_log(card->ctx, "srbeid: no certificates found");
		goto out;
	}

	/* Set card label and manufacturer. */
	set_string(&p15card->tokeninfo->label, "Serbian CardEdge");
	set_string(&p15card->tokeninfo->manufacturer_id, "CardEdge");

	/* Query PIN tries_left via card driver's pin_cmd. */
	{
		struct sc_pin_cmd_data pin_data;
		int pin_tries_left = -1;

		memset(&pin_data, 0, sizeof(pin_data));
		pin_data.cmd           = SC_PIN_CMD_GET_INFO;
		pin_data.pin_type      = SC_AC_CHV;
		pin_data.pin_reference = CE_PIN_REFERENCE;

		/* Best-effort: failure to query PIN status is not fatal. */
		if (sc_pin_cmd(card, &pin_data, &pin_tries_left) >= 0
				&& pin_tries_left < 0)
			pin_tries_left = pin_data.pin1.tries_left;
		sc_log(card->ctx, "srbeid: PIN tries_left=%d", pin_tries_left);

		/* ---- PIN auth object ----
		 * Must be registered before private keys so auth_id links work. */
		{
			sc_pkcs15_auth_info_t auth_info;
			sc_pkcs15_object_t    auth_obj;

			memset(&auth_info, 0, sizeof(auth_info));
			memset(&auth_obj,  0, sizeof(auth_obj));

			auth_info.auth_type               = SC_PKCS15_PIN_AUTH_TYPE_PIN;
			auth_info.auth_method             = SC_AC_CHV;
			auth_info.tries_left              = pin_tries_left;
			auth_info.attrs.pin.reference     = CE_PIN_REFERENCE;
			auth_info.attrs.pin.min_length    = 4;
			auth_info.attrs.pin.max_length    = CE_PIN_MAX_LENGTH;
			auth_info.attrs.pin.stored_length = CE_PIN_MAX_LENGTH;
			auth_info.attrs.pin.type          = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
			auth_info.attrs.pin.pad_char      = 0x00;
			auth_info.attrs.pin.flags         = SC_PKCS15_PIN_FLAG_INITIALIZED
				| SC_PKCS15_PIN_FLAG_LOCAL
				| SC_PKCS15_PIN_FLAG_NEEDS_PADDING;
			auth_info.path.aid.len = AID_PKCS15_LEN;
			memcpy(auth_info.path.aid.value, AID_PKCS15, AID_PKCS15_LEN);
			auth_info.auth_id.len      = 1;
			auth_info.auth_id.value[0] = 1;

			strncpy(auth_obj.label, "User PIN", sizeof(auth_obj.label) - 1);
			auth_obj.auth_id.len = 0;
			auth_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

			r = sc_pkcs15emu_add_pin_obj(p15card, &auth_obj, &auth_info);
			if (r < 0) {
				sc_log(card->ctx, "srbeid: add PIN obj failed: %d", r);
				goto out;
			}
		}
	}

	for (i = 0; i < ncerts; i++) {
		sc_pkcs15_prkey_info_t  key_info;
		sc_pkcs15_object_t      key_obj;
		sc_pkcs15_cert_info_t   cert_info;
		sc_pkcs15_object_t      cert_obj;
		u8                     *der = NULL;
		size_t                  der_len = 0;
		int is_kxc = (certs[i].key_pair_id == CE_AT_KEYEXCHANGE);

		/* ---- Private key object ---- */
		memset(&key_info, 0, sizeof(key_info));
		memset(&key_obj,  0, sizeof(key_obj));

		key_info.id.len      = 1;
		key_info.id.value[0] = (u8)(i + 1);
		key_info.native      = 1;
		key_info.key_reference  = (int)certs[i].key_fid;
		key_info.modulus_length = certs[i].key_size_bits
			? certs[i].key_size_bits : 2048;

		/*
		 * Key usage flags by type:
		 *   kxc (AT_KEYEXCHANGE) — encryption / key wrapping / decryption
		 *   ksc (AT_SIGNATURE)   — digital signature / non-repudiation only
		 */
		if (is_kxc) {
			key_info.usage = SC_PKCS15_PRKEY_USAGE_ENCRYPT
				| SC_PKCS15_PRKEY_USAGE_DECRYPT
				| SC_PKCS15_PRKEY_USAGE_WRAP
				| SC_PKCS15_PRKEY_USAGE_UNWRAP
				| SC_PKCS15_PRKEY_USAGE_SIGN;
		} else {
			key_info.usage = SC_PKCS15_PRKEY_USAGE_SIGN
				| SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;
		}

		/*
		 * Set only the AID on key_info.path (path.len stays 0).
		 * This makes select_key_file() select the PKI applet via AID
		 * before calling set_security_env(), without appending a file
		 * path that would fail on CardEdge's non-TLV FCI.
		 *
		 * The key FID is passed via key_info.key_reference and
		 * reconstructed in set_security_env() from the low byte.
		 */
		key_info.path.aid.len = AID_PKCS15_LEN;
		memcpy(key_info.path.aid.value, AID_PKCS15, AID_PKCS15_LEN);

		strncpy(key_obj.label, certs[i].label, sizeof(key_obj.label) - 1);
		key_obj.flags            = SC_PKCS15_CO_FLAG_PRIVATE;
		key_obj.auth_id.len      = 1;
		key_obj.auth_id.value[0] = 1;

		r = sc_pkcs15emu_add_rsa_prkey(p15card, &key_obj, &key_info);
		if (r < 0) {
			sc_log(card->ctx, "srbeid: add prkey[%d] failed: %d", i, r);
			goto out;
		}

		/* ---- Certificate object ---- */
		if (srbeid_read_cert_der(card, certs[i].cert_fid, &der, &der_len) < 0) {
			sc_log(card->ctx, "srbeid: could not read cert[%d] DER", i);
			continue;
		}

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj,  0, sizeof(cert_obj));

		cert_info.id.len      = 1;
		cert_info.id.value[0] = (u8)(i + 1);
		cert_info.authority   = 0;

		/* Store DER directly in the PKCS#15 value buffer. */
		cert_info.value.value = der;     /* ownership transferred */
		cert_info.value.len   = der_len;

		strncpy(cert_obj.label, certs[i].label, sizeof(cert_obj.label) - 1);

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		if (r < 0) {
			sc_log(card->ctx, "srbeid: add cert[%d] failed: %d", i, r);
			free(der);
			goto out;
		}
		/* der ownership now belongs to p15card; do not free. */
	}

	sc_log(card->ctx, "srbeid: pkcs15 bind OK (%d certs)", ncerts);

out:
	free(certs);
	return r;
}

int sc_pkcs15emu_srbeid_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	(void)aid;

	if (p15card->card->type != SC_CARD_TYPE_SRBEID_BASE)
		return SC_ERROR_WRONG_CARD;

	return sc_pkcs15emu_srbeid_init(p15card);
}
