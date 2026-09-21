/*
 * pkcs15-entersafe-mscp.c: PKCS#15 emulation for EnterSafe/FEITIAN ePass2003
 *		tokens personalized with a Microsoft minidriver (MSCP) file
 *		layout under DF 3F00/2003 instead of a PKCS#15 tree (DF 5015).
 *
 * The on-card layout has no PKCS#15 ODF/AODF/CDF/PrKDF at all: a flat
 * directory index (EF 6f01) lists a handful of EFs holding raw, headerless
 * streams of (CK_ATTRIBUTE_TYPE, length, value) triples -- effectively the
 * PKCS#11 attributes of each certificate/public key/private key object,
 * serialized as-is by the personalization tool. This emulator reads that
 * index and those streams and republishes the certificates and public keys
 * as ordinary PKCS#15 objects, together with the private keys and the PIN.
 *
 * Copyright (C) 2026  Manoel Neto <manoelneto@ufc.br>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/compat_strlcpy.h"

#include "asn1.h"
#include "cardctl.h"
#include "internal.h"
#include "pkcs15.h"

/* Application DF and fixed entry point of the MSCP directory index. The
 * index itself is always at this FID; every other file is discovered by
 * reading it, never hardcoded. */
#define ES_MSCP_APP_PATH     "3F002003"
#define ES_MSCP_INDEX_FID    0x6f01
#define ES_MSCP_INDEX_RECLEN 30
#define ES_MSCP_TOKEN_LABEL  "ENTERSAFE-ESPK"

/* PKCS#11 base-spec attribute type values, as they appear verbatim (as
 * little-endian u32) in the card's attribute streams. Kept local instead of
 * pulling in src/pkcs11/pkcs11.h, which belongs to a different module. */
#define P11_CKA_LABEL		0x00000003U
#define P11_CKA_VALUE		0x00000011U
#define P11_CKA_DECRYPT		0x00000105U
#define P11_CKA_SIGN		0x00000107U
#define P11_CKA_SIGN_RECOVER	0x00000108U
#define P11_CKA_ID		0x00000102U
#define P11_CKA_MODULUS		0x00000120U
#define P11_CKA_PUBLIC_EXPONENT 0x00000122U
/* Vendor attribute: the card's internal key handle (e.g. 0xA060), little-endian. */
#define P11_CKA_VENDOR_KEY_HANDLE 0x80000100U

/* CHV reference for card-epass2003.c's EXTERNAL AUTHENTICATE based PIN check. */
#define ES_MSCP_PIN_REFERENCE 1
#define ES_MSCP_PIN_AUTH_ID   "1"

/* Private key handle range. The generic PKCS#15 layer carries a single key
 * reference byte (senv.key_ref[0] in pkcs15-sec.c) and card-epass2003.c
 * rebuilds the FID as 0xA000 | that byte, so a handle outside 0xA000..0xA0FF
 * cannot survive the round trip: 0xA120 would come back as 0xA020 and address
 * a different key. Reject those instead of signing with the wrong key. */
#define ES_MSCP_PRIV_HANDLE_BASE 0xA020U
#define ES_MSCP_PRIV_HANDLE_MAX	 0xA0FFU

/* Public key handles live in their own range in the containermap. */
#define ES_MSCP_PUB_HANDLE_MIN 0x8000U
#define ES_MSCP_PUB_HANDLE_MAX 0x8FFFU

#define ES_MSCP_MAX_CONTAINERS 16

/* The serial number EF (cardid) is 16 bytes on the observed card; cap what is
 * hex encoded into the token info so a larger file cannot overrun hex[]. */
#define ES_MSCP_MAX_SERIAL_LEN 32

/* tkinfdir/tokeninfo carries the cardholder label in its first 32 bytes. */
#define ES_MSCP_LABEL_FIELD_LEN 32

/* Upper bound on any single EF this emulator reads. Well above the largest
 * object observed on a real card (a 2604 byte certificate), while keeping a
 * corrupt FCI size from driving an unbounded allocation. */
#define ES_MSCP_MAX_EF_SIZE (64 * 1024)

struct es_mscp_entry {
	unsigned int fid;
	char dirname[11];
	char filename[14];
	unsigned int size_used;
};

struct es_p11_attr {
	unsigned int type;
	const u8 *value;
	unsigned int len;
};

static unsigned int
es_le16(const u8 *p)
{
	return (unsigned int)p[0] | ((unsigned int)p[1] << 8);
}

static unsigned int
es_le32(const u8 *p)
{
	return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
	       ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static void
es_strip_leading_zeros(const u8 **p, size_t *len)
{
	while (*len > 1 && **p == 0) {
		(*p)++;
		(*len)--;
	}
}

/* Significant byte length of an RSA modulus. The personalization tool stores
 * CKA_MODULUS with the leading zero byte of its two's complement form, so
 * taking the raw attribute length would report a 2048 bit key as 2056 bit
 * and break key size filters in the PKCS#11 layer. */
static size_t
es_modulus_bytes(const u8 *p, size_t len)
{
	es_strip_leading_zeros(&p, &len);
	return len;
}

/* Select 3F00/2003/<fid> and read the whole EF into a freshly allocated
 * buffer, which the caller frees. Fixed size stack buffers used to cap this
 * at 4096 bytes (1024 for the containermap, which on a real card already
 * fills it exactly), so one extra container or a larger certificate would
 * have been dropped with only a log line. size_used is the index's own byte
 * count for the file, or 0 when the caller has no index entry; the smaller of
 * it and the FCI size wins, and ES_MSCP_MAX_EF_SIZE bounds both so a corrupt
 * or hostile FCI cannot drive a huge allocation. */
static int
es_select_and_read(sc_card_t *card, unsigned int fid, size_t size_used,
		u8 **out_buf, size_t *out_len)
{
	sc_path_t path;
	sc_file_t *file = NULL;
	u8 *buf;
	size_t want;
	int r;

	*out_buf = NULL;
	*out_len = 0;

	sc_format_path(ES_MSCP_APP_PATH, &path);
	r = sc_append_file_id(&path, fid);
	if (r < 0)
		return r;

	r = sc_select_file(card, &path, &file);
	if (r < 0) {
		sc_file_free(file);
		return r;
	}
	if (file == NULL)
		return SC_ERROR_INTERNAL;

	want = file->size;
	if (size_used != 0 && size_used < want)
		want = size_used;
	sc_file_free(file);

	if (want == 0)
		return SC_ERROR_INVALID_DATA;
	if (want > ES_MSCP_MAX_EF_SIZE)
		want = ES_MSCP_MAX_EF_SIZE;

	buf = malloc(want);
	if (buf == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	r = sc_read_binary(card, 0, buf, want, 0);
	if (r < 0) {
		free(buf);
		return r;
	}

	*out_buf = buf;
	*out_len = (size_t)r;
	return SC_SUCCESS;
}

static int
es_parse_index(const u8 *buf, size_t len,
		struct es_mscp_entry **out, size_t *out_count)
{
	size_t n = len / ES_MSCP_INDEX_RECLEN;
	struct es_mscp_entry *entries;
	size_t i, count = 0;

	if (n == 0)
		return SC_ERROR_INVALID_DATA;

	entries = calloc(n, sizeof(*entries));
	if (!entries)
		return SC_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < n; i++) {
		const u8 *rec = buf + i * ES_MSCP_INDEX_RECLEN;
		unsigned int fid = es_le16(rec);
		unsigned int size_used = es_le16(rec + 0x1A);

		/* FID FF FF declares a directory grouping label, not a file;
		 * FID 0000 with size 0 is an unused/padding slot. */
		if (fid == 0xFFFF || fid == 0x0000 || size_used == 0)
			continue;

		entries[count].fid = fid;
		memcpy(entries[count].dirname, rec + 0x02, 10);
		entries[count].dirname[10] = 0;
		memcpy(entries[count].filename, rec + 0x0C, 13);
		entries[count].filename[13] = 0;
		entries[count].size_used = size_used;
		count++;
	}

	*out = entries;
	*out_count = count;
	return SC_SUCCESS;
}

/* Index object names are a fixed 8 characters: a 4 character kind followed by
 * 4 decimal digits (cert0001, pubk0003, prvk0002). Matching the 4 character
 * prefix alone would also accept unrelated names such as "certificate.bak". */
static int
es_name_is(const char *filename, const char *kind)
{
	size_t i;

	if (strlen(filename) != 8 || strncmp(filename, kind, 4) != 0)
		return 0;
	for (i = 4; i < 8; i++)
		if (filename[i] < '0' || filename[i] > '9')
			return 0;
	return 1;
}

static const struct es_mscp_entry *
es_find_entry(const struct es_mscp_entry *entries,
		size_t count, const char *filename)
{
	size_t i;

	for (i = 0; i < count; i++)
		if (strncmp(entries[i].filename, filename, sizeof(entries[i].filename)) == 0)
			return &entries[i];
	return NULL;
}

/* Parse a flat stream of (u32 type, u32 len, u8 value[len]) triples,
 * little-endian, with no envelope of any kind. */
static int
es_parse_p11_attrs(const u8 *buf, size_t len,
		struct es_p11_attr **out, size_t *out_count)
{
	size_t pos = 0, count = 0, i;
	struct es_p11_attr *attrs;

	while (pos + 8 <= len) {
		unsigned int alen = es_le32(buf + pos + 4);

		/* Saturated comparison: pos + 8 + alen would wrap where size_t
		 * is 32 bit wide, letting a hostile alen of ~0xFFFFFFFF pass
		 * the bounds check and point value[] past the end of buf.
		 * pos + 8 <= len holds, so len - pos - 8 cannot underflow. */
		if ((size_t)alen > len - pos - 8)
			break;
		count++;
		pos += 8 + (size_t)alen;
	}
	if (count == 0)
		return SC_ERROR_INVALID_DATA;

	attrs = calloc(count, sizeof(*attrs));
	if (!attrs)
		return SC_ERROR_OUT_OF_MEMORY;

	pos = 0;
	for (i = 0; i < count; i++) {
		unsigned int type = es_le32(buf + pos);
		unsigned int alen = es_le32(buf + pos + 4);

		attrs[i].type = type;
		attrs[i].value = buf + pos + 8;
		attrs[i].len = alen;
		pos += 8 + (size_t)alen;
	}

	*out = attrs;
	*out_count = count;
	return SC_SUCCESS;
}

static const struct es_p11_attr *
es_find_attr(const struct es_p11_attr *attrs,
		size_t count, unsigned int type)
{
	size_t i;

	for (i = 0; i < count; i++)
		if (attrs[i].type == type)
			return &attrs[i];
	return NULL;
}

static int
es_add_cert(sc_pkcs15_card_t *p15card, const struct es_mscp_entry *entry)
{
	sc_card_t *card = p15card->card;
	u8 *buf = NULL;
	size_t len = 0;
	struct es_p11_attr *attrs = NULL;
	size_t nattrs = 0;
	const struct es_p11_attr *a_value, *a_id, *a_label;
	sc_pkcs15_cert_info_t cert_info;
	sc_pkcs15_object_t cert_obj;
	int r;

	r = es_select_and_read(card, entry->fid, entry->size_used, &buf, &len);
	if (r < 0) {
		sc_log(card->ctx, "entersafe-mscp: cannot read %s (fid %04X): %s",
				entry->filename, entry->fid, sc_strerror(r));
		return r;
	}

	r = es_parse_p11_attrs(buf, len, &attrs, &nattrs);
	if (r < 0) {
		sc_log(card->ctx, "entersafe-mscp: cannot parse attributes of %s: %s",
				entry->filename, sc_strerror(r));
		free(buf);
		return r;
	}

	a_value = es_find_attr(attrs, nattrs, P11_CKA_VALUE);
	if (!a_value || a_value->len == 0) {
		sc_log(card->ctx, "entersafe-mscp: %s has no CKA_VALUE, skipping",
				entry->filename);
		free(attrs);
		free(buf);
		return SC_ERROR_OBJECT_NOT_FOUND;
	}

	memset(&cert_info, 0, sizeof cert_info);
	memset(&cert_obj, 0, sizeof cert_obj);

	cert_info.value.value = malloc(a_value->len);
	if (!cert_info.value.value) {
		free(attrs);
		free(buf);
		return SC_ERROR_OUT_OF_MEMORY;
	}
	memcpy(cert_info.value.value, a_value->value, a_value->len);
	cert_info.value.len = a_value->len;

	a_id = es_find_attr(attrs, nattrs, P11_CKA_ID);
	if (a_id && a_id->len > 0) {
		size_t idlen = a_id->len;

		if (idlen > sizeof(cert_info.id.value))
			idlen = sizeof(cert_info.id.value);
		memcpy(cert_info.id.value, a_id->value, idlen);
		cert_info.id.len = idlen;
	}

	a_label = es_find_attr(attrs, nattrs, P11_CKA_LABEL);
	if (a_label && a_label->len > 0) {
		size_t lbl_len = a_label->len;

		if (lbl_len > sizeof(cert_obj.label) - 1)
			lbl_len = sizeof(cert_obj.label) - 1;
		memcpy(cert_obj.label, a_label->value, lbl_len);
	} else {
		strlcpy(cert_obj.label, entry->filename, sizeof(cert_obj.label));
	}

	free(attrs);
	free(buf);

	r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
	if (r < 0) {
		free(cert_info.value.value);
		return r;
	}
	return SC_SUCCESS;
}

static int
es_add_pubkey(sc_pkcs15_card_t *p15card, const struct es_mscp_entry *entry)
{
	sc_card_t *card = p15card->card;
	u8 *buf = NULL;
	size_t len = 0;
	struct es_p11_attr *attrs = NULL;
	size_t nattrs = 0;
	const struct es_p11_attr *a_mod, *a_exp, *a_id, *a_handle;
	sc_pkcs15_pubkey_info_t pubkey_info;
	sc_pkcs15_object_t pubkey_obj;
	sc_pkcs15_pubkey_t pubkey;
	u8 *spki = NULL;
	size_t spki_len = 0;
	int r;

	r = es_select_and_read(card, entry->fid, entry->size_used, &buf, &len);
	if (r < 0) {
		sc_log(card->ctx, "entersafe-mscp: cannot read %s (fid %04X): %s",
				entry->filename, entry->fid, sc_strerror(r));
		return r;
	}

	r = es_parse_p11_attrs(buf, len, &attrs, &nattrs);
	if (r < 0) {
		sc_log(card->ctx, "entersafe-mscp: cannot parse attributes of %s: %s",
				entry->filename, sc_strerror(r));
		free(buf);
		return r;
	}

	a_mod = es_find_attr(attrs, nattrs, P11_CKA_MODULUS);
	a_exp = es_find_attr(attrs, nattrs, P11_CKA_PUBLIC_EXPONENT);
	if (!a_mod || !a_exp || a_mod->len == 0 || a_exp->len == 0) {
		sc_log(card->ctx, "entersafe-mscp: %s missing modulus/exponent, skipping",
				entry->filename);
		free(attrs);
		free(buf);
		return SC_ERROR_OBJECT_NOT_FOUND;
	}

	memset(&pubkey, 0, sizeof pubkey);
	pubkey.algorithm = SC_ALGORITHM_RSA;
	pubkey.u.rsa.modulus.data = (u8 *)a_mod->value;
	pubkey.u.rsa.modulus.len = a_mod->len;
	pubkey.u.rsa.exponent.data = (u8 *)a_exp->value;
	pubkey.u.rsa.exponent.len = a_exp->len;

	r = sc_pkcs15_encode_pubkey_as_spki(card->ctx, &pubkey, &spki, &spki_len);
	/* The encoder fills in alg_id when it is NULL, and it allocates into our
	 * stack struct. modulus and exponent point into buf and are not ours to
	 * free, so release that one field instead of sc_pkcs15_erase_pubkey(). */
	if (pubkey.alg_id) {
		sc_asn1_clear_algorithm_id(pubkey.alg_id);
		free(pubkey.alg_id);
		pubkey.alg_id = NULL;
	}
	if (r < 0) {
		sc_log(card->ctx, "entersafe-mscp: cannot encode SPKI for %s: %s",
				entry->filename, sc_strerror(r));
		free(attrs);
		free(buf);
		return r;
	}

	memset(&pubkey_info, 0, sizeof pubkey_info);
	memset(&pubkey_obj, 0, sizeof pubkey_obj);

	pubkey_info.direct.spki.value = spki;
	pubkey_info.direct.spki.len = spki_len;
	pubkey_info.modulus_length = es_modulus_bytes(a_mod->value, a_mod->len) * 8;
	pubkey_info.native = 1;
	pubkey_info.usage = SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_VERIFY;

	a_handle = es_find_attr(attrs, nattrs, P11_CKA_VENDOR_KEY_HANDLE);
	if (a_handle && a_handle->len == 4) {
		unsigned int h = es_le32(a_handle->value);

		/* Only used to pair this key with a containermap record; anything
		 * outside the public handle range would pair with nothing. */
		if (h >= ES_MSCP_PUB_HANDLE_MIN && h <= ES_MSCP_PUB_HANDLE_MAX)
			pubkey_info.key_reference = (int)h;
	}

	a_id = es_find_attr(attrs, nattrs, P11_CKA_ID);
	if (a_id && a_id->len > 0) {
		size_t idlen = a_id->len;

		if (idlen > sizeof(pubkey_info.id.value))
			idlen = sizeof(pubkey_info.id.value);
		memcpy(pubkey_info.id.value, a_id->value, idlen);
		pubkey_info.id.len = idlen;
	}

	strlcpy(pubkey_obj.label, entry->filename, sizeof(pubkey_obj.label));

	free(attrs);
	free(buf);

	r = sc_pkcs15emu_add_rsa_pubkey(p15card, &pubkey_obj, &pubkey_info);
	if (r < 0) {
		free(spki);
		return r;
	}
	return SC_SUCCESS;
}

struct es_container {
	unsigned int priv_handle;
	unsigned int pub_handle;
};

struct es_containers {
	struct es_container c[ES_MSCP_MAX_CONTAINERS];
	size_t n;
};

/* internal/containermap: a 32 byte header, then 24 byte records holding the
 * private and public vendor key handles as little-endian 32-bit values (the
 * rest of a record is zero). Unused records are zero and end the list. */
#define ES_MSCP_CMAP_HEADER_LEN 0x20
#define ES_MSCP_CMAP_RECORD_LEN 0x18

static void
es_parse_containermap(const u8 *buf, size_t len, struct es_containers *cm)
{
	size_t i;

	cm->n = 0;
	for (i = ES_MSCP_CMAP_HEADER_LEN; i + 8 <= len && cm->n < ES_MSCP_MAX_CONTAINERS;
			i += ES_MSCP_CMAP_RECORD_LEN) {
		unsigned int priv = es_le32(buf + i);
		unsigned int pub = es_le32(buf + i + 4);

		if (priv < 0xA000 || priv > 0xAFFF ||
				pub < ES_MSCP_PUB_HANDLE_MIN || pub > ES_MSCP_PUB_HANDLE_MAX)
			break;
		cm->c[cm->n].priv_handle = priv;
		cm->c[cm->n].pub_handle = pub;
		cm->n++;
	}
}

static void
es_read_containermap(sc_card_t *card, unsigned int fid, size_t size_used,
		struct es_containers *cm)
{
	u8 *buf = NULL;
	size_t len = 0;

	cm->n = 0;
	if (es_select_and_read(card, fid, size_used, &buf, &len) < 0)
		return;
	es_parse_containermap(buf, len, cm);
	free(buf);
}

static int
es_container_priv_for_pub(const struct es_containers *cm, unsigned int pub, unsigned int *priv)
{
	size_t i;

	for (i = 0; i < cm->n; i++) {
		if (cm->c[i].pub_handle == pub) {
			*priv = cm->c[i].priv_handle;
			return 1;
		}
	}
	return 0;
}

static int
es_container_pub_for_priv_low(const struct es_containers *cm, unsigned int priv_low, unsigned int *pub)
{
	size_t i;

	for (i = 0; i < cm->n; i++) {
		if ((cm->c[i].priv_handle & 0xff) == priv_low) {
			*pub = cm->c[i].pub_handle;
			return 1;
		}
	}
	return 0;
}

/* Whether a private key handle can be addressed at all, i.e. whether it fits
 * the single key reference byte the generic layer carries. */
static int
es_priv_handle_usable(unsigned int handle)
{
	return handle >= ES_MSCP_PRIV_HANDLE_BASE && handle <= ES_MSCP_PRIV_HANDLE_MAX;
}

static int
es_container_has_priv(const struct es_containers *cm, unsigned int handle)
{
	size_t i;

	for (i = 0; i < cm->n; i++)
		if (cm->c[i].priv_handle == handle)
			return 1;
	return 0;
}

/* Look up modulus length and vendor key handle for a prvkNNNN object.
 * Normally both come from that object's own attributes; when they're
 * absent (observed on this card's current-generation key), fall back to
 * the paired pubkNNNN object (same NNNN suffix); the private handle is the one
 * the containermap pairs with that public handle. */
static int
es_prkey_lookup_mod_and_handle(sc_pkcs15_card_t *p15card,
		const struct es_mscp_entry *entries, size_t nentries,
		const struct es_containers *cm,
		const struct es_mscp_entry *prvk_entry,
		const struct es_p11_attr *attrs, size_t nattrs,
		size_t *out_modulus_len, unsigned int *out_vendor_handle)
{
	sc_card_t *card = p15card->card;
	const struct es_p11_attr *a_mod, *a_handle;
	char pubk_filename[sizeof(prvk_entry->filename)];
	const struct es_mscp_entry *e_pubk;
	u8 *pubbuf = NULL;
	size_t publen = 0;
	struct es_p11_attr *pubattrs = NULL;
	size_t pubnattrs = 0;
	int r;

	a_mod = es_find_attr(attrs, nattrs, P11_CKA_MODULUS);
	a_handle = es_find_attr(attrs, nattrs, P11_CKA_VENDOR_KEY_HANDLE);
	if (a_mod && a_mod->len > 0 && a_handle && a_handle->len == 4) {
		*out_modulus_len = es_modulus_bytes(a_mod->value, a_mod->len);
		*out_vendor_handle = es_le32(a_handle->value);
		return SC_SUCCESS;
	}

	if (!es_name_is(prvk_entry->filename, "prvk"))
		return SC_ERROR_OBJECT_NOT_FOUND;
	/* es_name_is() guarantees 4 digits plus the terminator fit. */
	memcpy(pubk_filename, "pubk", 4);
	strlcpy(pubk_filename + 4, prvk_entry->filename + 4, sizeof(pubk_filename) - 4);

	e_pubk = es_find_entry(entries, nentries, pubk_filename);
	if (!e_pubk) {
		sc_log(card->ctx, "entersafe-mscp: %s has no modulus/handle and no paired %s",
				prvk_entry->filename, pubk_filename);
		return SC_ERROR_OBJECT_NOT_FOUND;
	}

	r = es_select_and_read(card, e_pubk->fid, e_pubk->size_used, &pubbuf, &publen);
	if (r < 0)
		return r;
	r = es_parse_p11_attrs(pubbuf, publen, &pubattrs, &pubnattrs);
	if (r < 0) {
		free(pubbuf);
		return r;
	}

	a_mod = es_find_attr(pubattrs, pubnattrs, P11_CKA_MODULUS);
	a_handle = es_find_attr(pubattrs, pubnattrs, P11_CKA_VENDOR_KEY_HANDLE);
	if (!a_mod || a_mod->len == 0 || !a_handle || a_handle->len != 4) {
		free(pubattrs);
		free(pubbuf);
		return SC_ERROR_OBJECT_NOT_FOUND;
	}

	if (!es_container_priv_for_pub(cm, es_le32(a_handle->value), out_vendor_handle)) {
		sc_log(card->ctx, "entersafe-mscp: no containermap entry for the key of %s",
				prvk_entry->filename);
		free(pubattrs);
		free(pubbuf);
		return SC_ERROR_OBJECT_NOT_FOUND;
	}
	*out_modulus_len = es_modulus_bytes(a_mod->value, a_mod->len);
	free(pubattrs);
	free(pubbuf);
	return SC_SUCCESS;
}

static int
es_add_prkey(sc_pkcs15_card_t *p15card, const struct es_mscp_entry *entries,
		size_t nentries, const struct es_containers *cm, const struct es_mscp_entry *entry)
{
	sc_card_t *card = p15card->card;
	u8 *buf = NULL;
	size_t len = 0;
	struct es_p11_attr *attrs = NULL;
	size_t nattrs = 0;
	const struct es_p11_attr *a_id, *a_sign, *a_sign_rec, *a_decrypt;
	sc_pkcs15_prkey_info_t prkey_info;
	sc_pkcs15_object_t prkey_obj;
	size_t modulus_len = 0;
	unsigned int vendor_handle = 0;
	int r;

	r = es_select_and_read(card, entry->fid, entry->size_used, &buf, &len);
	if (r < 0) {
		sc_log(card->ctx, "entersafe-mscp: cannot read %s (fid %04X): %s",
				entry->filename, entry->fid, sc_strerror(r));
		return r;
	}

	r = es_parse_p11_attrs(buf, len, &attrs, &nattrs);
	if (r < 0) {
		sc_log(card->ctx, "entersafe-mscp: cannot parse attributes of %s: %s",
				entry->filename, sc_strerror(r));
		free(buf);
		return r;
	}

	r = es_prkey_lookup_mod_and_handle(p15card, entries, nentries, cm, entry,
			attrs, nattrs, &modulus_len, &vendor_handle);
	if (r < 0) {
		sc_log(card->ctx, "entersafe-mscp: %s (fid %04X) missing modulus/vendor handle, skipping",
				entry->filename, entry->fid);
		free(attrs);
		free(buf);
		return SC_ERROR_OBJECT_NOT_FOUND;
	}
	if (!es_priv_handle_usable(vendor_handle)) {
		sc_log(card->ctx,
				"entersafe-mscp: %s (fid %04X) has vendor handle %04X outside the "
				"addressable range %04X..%04X, skipping",
				entry->filename, entry->fid, vendor_handle,
				ES_MSCP_PRIV_HANDLE_BASE, ES_MSCP_PRIV_HANDLE_MAX);
		free(attrs);
		free(buf);
		return SC_ERROR_OBJECT_NOT_FOUND;
	}
	/* A consistency check, not a security control: the containermap comes
	 * from the same card as the handle, so it cannot vouch for it. Warn and
	 * carry on, so a key that is simply not in a container still works. */
	if (cm->n != 0 && !es_container_has_priv(cm, vendor_handle))
		sc_log(card->ctx, "entersafe-mscp: %s uses vendor handle %04X, which the "
				"containermap does not list", entry->filename, vendor_handle);

	memset(&prkey_info, 0, sizeof prkey_info);
	memset(&prkey_obj, 0, sizeof prkey_obj);

	prkey_info.native = 1;
	/* card-epass2003.c's MSE:SET reconstructs the full vendor handle as
	 * 0xA000 | key_reference, so only the low byte needs to survive the
	 * generic pkcs15 layer's single-byte key_ref[0]. All three of this
	 * card's private-key handles (0xA020/0xA040/0xA060) share the high
	 * byte 0xA0, so this is lossless. */
	prkey_info.key_reference = (int)(vendor_handle & 0xff);
	prkey_info.modulus_length = modulus_len * 8;

	a_sign = es_find_attr(attrs, nattrs, P11_CKA_SIGN);
	a_sign_rec = es_find_attr(attrs, nattrs, P11_CKA_SIGN_RECOVER);
	a_decrypt = es_find_attr(attrs, nattrs, P11_CKA_DECRYPT);
	if ((a_sign && a_sign->len && a_sign->value[0]) || (!a_sign && !a_decrypt))
		prkey_info.usage |= SC_PKCS15_PRKEY_USAGE_SIGN;
	if (a_sign_rec && a_sign_rec->len && a_sign_rec->value[0])
		prkey_info.usage |= SC_PKCS15_PRKEY_USAGE_SIGNRECOVER;
	if (a_decrypt && a_decrypt->len && a_decrypt->value[0])
		prkey_info.usage |= SC_PKCS15_PRKEY_USAGE_DECRYPT;

	a_id = es_find_attr(attrs, nattrs, P11_CKA_ID);
	if (a_id && a_id->len > 0) {
		size_t idlen = a_id->len;

		if (idlen > sizeof(prkey_info.id.value))
			idlen = sizeof(prkey_info.id.value);
		memcpy(prkey_info.id.value, a_id->value, idlen);
		prkey_info.id.len = idlen;
	}

	sc_pkcs15_format_id(ES_MSCP_PIN_AUTH_ID, &prkey_obj.auth_id);
	prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
	strlcpy(prkey_obj.label, entry->filename, sizeof(prkey_obj.label));

	free(attrs);
	free(buf);

	return sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
}

static int
es_add_pin(sc_pkcs15_card_t *p15card)
{
	sc_pkcs15_auth_info_t pin_info;
	sc_pkcs15_object_t pin_obj;

	memset(&pin_info, 0, sizeof pin_info);
	memset(&pin_obj, 0, sizeof pin_obj);

	pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	sc_pkcs15_format_id(ES_MSCP_PIN_AUTH_ID, &pin_info.auth_id);
	pin_info.attrs.pin.reference = ES_MSCP_PIN_REFERENCE;
	pin_info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_CASE_SENSITIVE |
				   SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_NEEDS_PADDING;
	/* The card does not restrict the PIN charset; not digits only, or
	 * front ends such as CryptoTokenKit refuse letters. */
	pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_UTF8;
	/* Same limits as internal_sanitize_pin_info() in card-epass2003.c */
	pin_info.attrs.pin.min_length = 4;
	pin_info.attrs.pin.max_length = 16;
	pin_info.attrs.pin.stored_length = 16;
	pin_info.attrs.pin.pad_char = 0x00;
	sc_format_path(ES_MSCP_APP_PATH, &pin_info.path);
	pin_info.tries_left = -1;

	strlcpy(pin_obj.label, "PIN", sizeof(pin_obj.label));
	pin_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;

	return sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
}

static int
es_read_serial(sc_pkcs15_card_t *p15card, unsigned int fid, size_t size_used)
{
	sc_card_t *card = p15card->card;
	u8 *buf = NULL;
	size_t len = 0;
	char hex[ES_MSCP_MAX_SERIAL_LEN * 2 + 1];
	int r;

	r = es_select_and_read(card, fid, size_used, &buf, &len);
	if (r < 0)
		return r;

	if (len > ES_MSCP_MAX_SERIAL_LEN)
		len = ES_MSCP_MAX_SERIAL_LEN;
	r = sc_bin_to_hex(buf, len, hex, sizeof hex, 0);
	free(buf);
	if (r < 0)
		return r;

	set_string(&p15card->tokeninfo->serial_number, hex);
	return SC_SUCCESS;
}

/* Read tkinfdir/tokeninfo's cardholder-personalized label. The first 32
 * bytes are ASCII, space-padded. This is personal data (a name-derived
 * string in the observed personalization): never sc_log() the raw bytes. */
static int
es_read_label(sc_pkcs15_card_t *p15card, unsigned int fid, size_t size_used,
		char *label_out, size_t label_out_size)
{
	sc_card_t *card = p15card->card;
	u8 *buf = NULL;
	size_t len = 0;
	size_t n;
	int r;

	r = es_select_and_read(card, fid, size_used, &buf, &len);
	if (r < 0)
		return r;

	n = ES_MSCP_LABEL_FIELD_LEN;
	if (n > len)
		n = len;
	while (n > 0 && buf[n - 1] == ' ')
		n--;
	if (n >= label_out_size)
		n = label_out_size - 1;
	memcpy(label_out, buf, n);
	label_out[n] = 0;
	free(buf);

	return SC_SUCCESS;
}

#define ES_MSCP_MAX_KEYLIKE 32

struct es_keylike {
	sc_pkcs15_id_t *id;
	u8 *modulus;
	size_t modulus_len;
};

static int
es_same_modulus(const struct es_keylike *a, const struct es_keylike *b)
{
	const u8 *pa = a->modulus, *pb = b->modulus;
	size_t la = a->modulus_len, lb = b->modulus_len;

	es_strip_leading_zeros(&pa, &la);
	es_strip_leading_zeros(&pb, &lb);
	return la == lb && la > 0 && memcmp(pa, pb, la) == 0;
}

/* Some objects (cert0004/cert0005, pubk0003 on the observed card) carry no
 * CKA_ID of their own. Empty ids are not tolerated by CryptoTokenKit (its
 * objectID is a type byte plus the id, so two empty ids collide) and they break
 * certificate <-> key pairing. Certificates and public keys take the id of the
 * object with the same RSA modulus; private keys take the id of the public key
 * the containermap pairs them with. Whatever is still id-less gets a unique
 * synthetic id. */
static void
es_fill_missing_ids(sc_pkcs15_card_t *p15card, const struct es_containers *cm)
{
	sc_context_t *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *objs[ES_MSCP_MAX_KEYLIKE];
	struct sc_pkcs15_object *probjs[ES_MSCP_MAX_KEYLIKE];
	struct es_keylike items[ES_MSCP_MAX_KEYLIKE];
	struct sc_pkcs15_cert *certs[ES_MSCP_MAX_KEYLIKE];
	struct sc_pkcs15_pubkey *pubs[ES_MSCP_MAX_KEYLIKE];
	size_t nitems = 0, i, j, k;
	unsigned int synthetic = 0;
	int n, npub, npr;

	memset(certs, 0, sizeof certs);
	memset(pubs, 0, sizeof pubs);

	n = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, objs, ES_MSCP_MAX_KEYLIKE);
	for (k = 0; n > 0 && k < (size_t)n && nitems < ES_MSCP_MAX_KEYLIKE; k++) {
		struct sc_pkcs15_cert_info *info = objs[k]->data;
		struct sc_pkcs15_cert *cert = NULL;

		if (sc_pkcs15_read_certificate(p15card, info, 0, &cert) < 0 || !cert)
			continue;
		if (!cert->key || cert->key->algorithm != SC_ALGORITHM_RSA) {
			sc_pkcs15_free_certificate(cert);
			continue;
		}
		certs[nitems] = cert;
		items[nitems].id = &info->id;
		items[nitems].modulus = cert->key->u.rsa.modulus.data;
		items[nitems].modulus_len = cert->key->u.rsa.modulus.len;
		nitems++;
	}

	npub = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PUBKEY_RSA, objs, ES_MSCP_MAX_KEYLIKE);
	for (k = 0; npub > 0 && k < (size_t)npub && nitems < ES_MSCP_MAX_KEYLIKE; k++) {
		struct sc_pkcs15_pubkey_info *info = objs[k]->data;
		struct sc_pkcs15_pubkey *pub = NULL;

		if (sc_pkcs15_read_pubkey(p15card, objs[k], &pub) < 0 || !pub)
			continue;
		pubs[nitems] = pub;
		items[nitems].id = &info->id;
		items[nitems].modulus = pub->u.rsa.modulus.data;
		items[nitems].modulus_len = pub->u.rsa.modulus.len;
		nitems++;
	}

	for (i = 0; i < nitems; i++) {
		if (items[i].id->len != 0)
			continue;
		for (j = 0; j < nitems; j++) {
			if (j == i || items[j].id->len == 0 || !es_same_modulus(&items[i], &items[j]))
				continue;
			*items[i].id = *items[j].id;
			sc_log(ctx, "entersafe-mscp: id-less object %zu took id of paired object %zu", i, j);
			break;
		}
	}

	npr = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY_RSA, probjs, ES_MSCP_MAX_KEYLIKE);
	for (k = 0; npr > 0 && k < (size_t)npr; k++) {
		struct sc_pkcs15_prkey_info *pr = probjs[k]->data;
		unsigned int pub_handle = 0;

		if (pr->id.len != 0 ||
				!es_container_pub_for_priv_low(cm, (unsigned int)pr->key_reference & 0xff, &pub_handle))
			continue;
		for (j = 0; npub > 0 && j < (size_t)npub; j++) {
			struct sc_pkcs15_pubkey_info *pi = objs[j]->data;

			if ((unsigned int)pi->key_reference == pub_handle && pi->id.len != 0) {
				pr->id = pi->id;
				break;
			}
		}
	}

	for (i = 0; i < nitems; i++) {
		if (items[i].id->len != 0)
			continue;
		items[i].id->value[0] = 0xF0;
		items[i].id->value[1] = (u8)(++synthetic);
		items[i].id->len = 2;
	}
	for (k = 0; npr > 0 && k < (size_t)npr; k++) {
		struct sc_pkcs15_prkey_info *pr = probjs[k]->data;

		if (pr->id.len != 0)
			continue;
		pr->id.value[0] = 0xF0;
		pr->id.value[1] = (u8)(++synthetic);
		pr->id.len = 2;
	}

	for (i = 0; i < nitems; i++) {
		if (certs[i])
			sc_pkcs15_free_certificate(certs[i]);
		if (pubs[i])
			sc_pkcs15_free_pubkey(pubs[i]);
	}
}

/* The FCI file name of DF 2003 is a 16 byte field, zero padded after the
 * 14 characters of the name. Anything else in the padding is another
 * application (e.g. "ENTERSAFE-ESPKX"). */
static int
es_fci_name_matches(const sc_file_t *file)
{
	size_t n = strlen(ES_MSCP_TOKEN_LABEL), i;

	if (file == NULL || file->namelen < n || memcmp(file->name, ES_MSCP_TOKEN_LABEL, n) != 0)
		return 0;
	for (i = n; i < file->namelen; i++)
		if (file->name[i] != 0)
			return 0;
	return 1;
}

static int
es_mscp_detect_and_bind(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;
	sc_context_t *ctx = card->ctx;
	sc_path_t path;
	sc_file_t *file = NULL;
	u8 *idxbuf = NULL;
	size_t idxlen = 0;
	struct es_mscp_entry *entries = NULL;
	size_t nentries = 0, i;
	const struct es_mscp_entry *e_tokeninfo, *e_cardid, *e_containermap;
	struct es_containers cm;
	char label[33];
	int r, ncerts = 0, npubkeys = 0, nprkeys = 0;
	int mscp_on;

	LOG_FUNC_CALLED(ctx);

	if (card->type != SC_CARD_TYPE_ENTERSAFE_FTCOS_EPASS2003)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);

	/* SELECT returns the DF's own FCI file name (tag 0x84), which for this
	 * personalization is literally "ENTERSAFE-ESPK". That, not anything
	 * inside tokeninfo, is what identifies this specific MSCP layout. */
	sc_format_path(ES_MSCP_APP_PATH, &path);
	r = sc_select_file(card, &path, &file);
	if (r < 0) {
		sc_file_free(file);
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);
	}
	if (!es_fci_name_matches(file)) {
		sc_file_free(file);
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);
	}
	sc_file_free(file);

	/* size_used is unknown here: the index is the file that carries it. */
	r = es_select_and_read(card, ES_MSCP_INDEX_FID, 0, &idxbuf, &idxlen);
	if (r < 0)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);

	r = es_parse_index(idxbuf, idxlen, &entries, &nentries);
	free(idxbuf);
	if (r < 0)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);

	e_tokeninfo = es_find_entry(entries, nentries, "tokeninfo");
	if (!e_tokeninfo) {
		free(entries);
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);
	}

	r = es_read_label(p15card, e_tokeninfo->fid, e_tokeninfo->size_used,
			label, sizeof label);
	if (r < 0) {
		free(entries);
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);
	}

	/* From here on this really is our card: log failures instead of
	 * silently deferring to the next emulator. */

	sc_file_free(p15card->file_app);
	p15card->file_app = sc_file_new();
	if (!p15card->file_app) {
		free(entries);
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	sc_format_path(ES_MSCP_APP_PATH, &p15card->file_app->path);

	set_string(&p15card->tokeninfo->label, label);
	set_string(&p15card->tokeninfo->manufacturer_id, "Feitian/EnterSafe ePass2003 (MSCP)");
	/* This emulator only publishes what the minidriver personalization put on
	 * the card; it cannot create or update MSCP objects. Without this flag
	 * pkcs15-init would happily erase the card through the ePass2003 driver,
	 * which knows nothing about the MSCP layout. */
	p15card->tokeninfo->flags |= SC_PKCS15_TOKEN_READONLY;

	e_cardid = es_find_entry(entries, nentries, "cardid");
	if (e_cardid) {
		r = es_read_serial(p15card, e_cardid->fid, e_cardid->size_used);
		if (r < 0)
			sc_log(ctx, "entersafe-mscp: cannot read cardid: %s", sc_strerror(r));
	}

	e_containermap = es_find_entry(entries, nentries, "containermap");
	cm.n = 0;
	if (e_containermap)
		es_read_containermap(card, e_containermap->fid, e_containermap->size_used, &cm);

	r = es_add_pin(p15card);
	if (r < 0) {
		sc_log(ctx, "entersafe-mscp: cannot add PIN object: %s", sc_strerror(r));
		free(entries);
		LOG_FUNC_RETURN(ctx, r);
	}

	for (i = 0; i < nentries; i++) {
		const char *kind = NULL;

		if (es_name_is(entries[i].filename, "cert")) {
			kind = "certificate";
			r = es_add_cert(p15card, &entries[i]);
			if (r == SC_SUCCESS)
				ncerts++;
		} else if (es_name_is(entries[i].filename, "pubk")) {
			kind = "public key";
			r = es_add_pubkey(p15card, &entries[i]);
			if (r == SC_SUCCESS)
				npubkeys++;
		} else if (es_name_is(entries[i].filename, "prvk")) {
			kind = "private key";
			r = es_add_prkey(p15card, entries, nentries, &cm, &entries[i]);
			if (r == SC_SUCCESS)
				nprkeys++;
		}
		/* Name the object that dropped out, so a partially bound token can
		 * be diagnosed from the log instead of just looking short. */
		if (kind != NULL && r != SC_SUCCESS)
			sc_log(ctx, "entersafe-mscp: skipped %s %s (fid %04X): %s",
					kind, entries[i].filename, entries[i].fid, sc_strerror(r));
	}

	free(entries);

	es_fill_missing_ids(p15card, &cm);

	sc_log(ctx, "entersafe-mscp: bound %d certificate(s), %d public key(s), %d private key(s)",
			ncerts, npubkeys, nprkeys);

	if (ncerts == 0)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_CARD);

	/* Certificates alone still make a usable read-only token, but without a
	 * private key nothing can be signed: say so rather than look healthy. */
	if (nprkeys == 0)
		sc_log(ctx, "entersafe-mscp: no private key was bound; this token cannot sign");

	/* Only now that binding succeeded: RSA keys are addressed by their raw
	 * vendor handle from here on (set_security_env() in card-epass2003.c). */
	mscp_on = 1;
	r = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_MSCP_MODE, &mscp_on);
	if (r < 0) {
		sc_log(ctx, "entersafe-mscp: cannot enable MSCP key addressing: %s", sc_strerror(r));
		LOG_FUNC_RETURN(ctx, r);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

int
sc_pkcs15emu_entersafe_mscp_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	sc_context_t *ctx = p15card->card->ctx;
	int r;

	LOG_FUNC_CALLED(ctx);
	r = es_mscp_detect_and_bind(p15card);
	if (r < 0)
		sc_pkcs15_card_clear(p15card);
	LOG_FUNC_RETURN(ctx, r);
}
