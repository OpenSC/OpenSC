/*
 * entersafe-mscp.c: Unit tests for the EnterSafe/ePass2003 MSCP parsers
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "torture.h"
/* sc.c brings in set_string() and friends, which libopensc does not export;
 * same approach as simpletlv.c. sc.c must come first: pkcs15-entersafe-mscp.c
 * calls set_string(), and clang-format would otherwise alphabetize the two
 * and break that. */
// clang-format off
#include "libopensc/sc.c"
#include "libopensc/pkcs15-entersafe-mscp.c"
// clang-format on

/*
 * These parsers consume data supplied verbatim by the card, i.e. hostile
 * input. Every test below feeds them a hand-built fixture; none of them
 * touches a reader.
 */

static void
put_le32(u8 *p, unsigned int v)
{
	p[0] = (u8)(v & 0xff);
	p[1] = (u8)((v >> 8) & 0xff);
	p[2] = (u8)((v >> 16) & 0xff);
	p[3] = (u8)((v >> 24) & 0xff);
}

/* Append one (type, len, value) triple; returns bytes written. */
static size_t
put_attr(u8 *p, CK_ATTRIBUTE_TYPE type, unsigned int len, u8 fill)
{
	put_le32(p, (unsigned int)type);
	put_le32(p + 4, len);
	memset(p + 8, fill, len);
	return 8 + (size_t)len;
}

/* es_parse_p11_attrs() */

static void
torture_mscp_attrs_wellformed(void **state)
{
	u8 buf[64];
	size_t n = 0;
	struct es_p11_attr *attrs = NULL;
	size_t nattrs = 0;

	n += put_attr(buf + n, CKA_ID, 2, 0xAB);
	n += put_attr(buf + n, CKA_VALUE, 4, 0xCD);

	assert_int_equal(es_parse_p11_attrs(buf, n, &attrs, &nattrs), SC_SUCCESS);
	assert_int_equal(nattrs, 2);
	assert_int_equal(attrs[0].type, CKA_ID);
	assert_int_equal(attrs[0].len, 2);
	assert_ptr_equal(attrs[0].value, buf + 8);
	assert_int_equal(attrs[1].type, CKA_VALUE);
	assert_int_equal(attrs[1].len, 4);
	assert_ptr_equal(attrs[1].value, buf + 8 + 2 + 8);
	free(attrs);
}

/* An attribute whose value ends exactly at the end of the buffer is valid. */
static void
torture_mscp_attrs_exact_fit(void **state)
{
	u8 buf[16];
	struct es_p11_attr *attrs = NULL;
	size_t nattrs = 0;

	put_attr(buf, CKA_VALUE, 8, 0x11);

	assert_int_equal(es_parse_p11_attrs(buf, sizeof buf, &attrs, &nattrs), SC_SUCCESS);
	assert_int_equal(nattrs, 1);
	assert_int_equal(attrs[1 - 1].len, 8);
	free(attrs);
}

/*
 * Regression guard for the 32-bit length wrap: a hostile alen near
 * UINT32_MAX made "pos + 8 + alen > len" wrap where size_t is 32 bit wide,
 * so the bounds check passed and attrs[].value pointed far past buf.
 * The saturated form "alen > len - pos - 8" cannot wrap.
 *
 * NOTE: on a 64-bit host both forms reject this input, because (size_t)alen
 * widens to 64 bit. This test therefore only guards against the check being
 * dropped or loosened; the wrap itself reproduces on a 32-bit build.
 */
static void
torture_mscp_attrs_huge_len_first(void **state)
{
	u8 buf[64];
	struct es_p11_attr *attrs = NULL;
	size_t nattrs = 0;

	memset(buf, 0, sizeof buf);
	put_le32(buf, (unsigned int)CKA_VALUE);
	put_le32(buf + 4, 0xFFFFFFF9u); /* 0 + 8 + alen wraps to 1 in 32 bit */

	assert_int_equal(es_parse_p11_attrs(buf, sizeof buf, &attrs, &nattrs),
			SC_ERROR_INVALID_DATA);
	assert_null(attrs);
}

/* A hostile length after a valid attribute truncates the stream instead of
 * publishing an out-of-bounds value pointer. */
static void
torture_mscp_attrs_huge_len_trailing(void **state)
{
	u8 buf[64];
	size_t n = 0;
	struct es_p11_attr *attrs = NULL;
	size_t nattrs = 0;

	memset(buf, 0, sizeof buf);
	n += put_attr(buf + n, CKA_ID, 2, 0xAB);
	put_le32(buf + n, (unsigned int)CKA_VALUE);
	put_le32(buf + n + 4, 0x80000000u);

	assert_int_equal(es_parse_p11_attrs(buf, sizeof buf, &attrs, &nattrs), SC_SUCCESS);
	assert_int_equal(nattrs, 1);
	assert_int_equal(attrs[0].type, CKA_ID);
	/* value + len must stay inside buf */
	assert_true(attrs[0].value + attrs[0].len <= buf + sizeof buf);
	free(attrs);
}

/* alen just past the end is rejected too (no off-by-one). */
static void
torture_mscp_attrs_one_past_end(void **state)
{
	u8 buf[16];
	struct es_p11_attr *attrs = NULL;
	size_t nattrs = 0;

	memset(buf, 0, sizeof buf);
	put_le32(buf, (unsigned int)CKA_VALUE);
	put_le32(buf + 4, 9); /* 8 + 9 = 17 > 16 */

	assert_int_equal(es_parse_p11_attrs(buf, sizeof buf, &attrs, &nattrs),
			SC_ERROR_INVALID_DATA);
	assert_null(attrs);
}

static void
torture_mscp_attrs_truncated_header(void **state)
{
	u8 buf[7] = {0};
	struct es_p11_attr *attrs = NULL;
	size_t nattrs = 0;

	assert_int_equal(es_parse_p11_attrs(buf, sizeof buf, &attrs, &nattrs),
			SC_ERROR_INVALID_DATA);
	assert_null(attrs);
}

/* es_name_is() */

/*
 * Regression guard: matching only the 4 character prefix also accepted names
 * such as "certificate.bak", which would then be parsed as an object.
 */
static void
torture_mscp_name_is(void **state)
{
	assert_int_equal(es_name_is("cert0001", "cert"), 1);
	assert_int_equal(es_name_is("pubk0003", "pubk"), 1);
	assert_int_equal(es_name_is("prvk9999", "prvk"), 1);

	assert_int_equal(es_name_is("certificate.bak", "cert"), 0);
	assert_int_equal(es_name_is("cert", "cert"), 0);      /* too short */
	assert_int_equal(es_name_is("cert000", "cert"), 0);   /* 7 chars */
	assert_int_equal(es_name_is("cert00011", "cert"), 0); /* 9 chars */
	assert_int_equal(es_name_is("certABCD", "cert"), 0);  /* not digits */
	assert_int_equal(es_name_is("cert 001", "cert"), 0);
	assert_int_equal(es_name_is("cmapfile", "cert"), 0);
	assert_int_equal(es_name_is("pubk0001", "prvk"), 0);
	assert_int_equal(es_name_is("", "cert"), 0);
}

/* es_parse_index() */

static void
put_index_rec(u8 *rec, unsigned int fid, const char *dirname,
		const char *filename, unsigned int size_used)
{
	memset(rec, 0, ES_MSCP_INDEX_RECLEN);
	rec[0] = (u8)(fid & 0xff);
	rec[1] = (u8)(fid >> 8);
	memcpy(rec + 0x02, dirname, strlen(dirname) > 10 ? 10 : strlen(dirname));
	memcpy(rec + 0x0C, filename, strlen(filename) > 13 ? 13 : strlen(filename));
	rec[0x1A] = (u8)(size_used & 0xff);
	rec[0x1B] = (u8)(size_used >> 8);
}

static void
torture_mscp_index_basic(void **state)
{
	u8 buf[ES_MSCP_INDEX_RECLEN * 4];
	struct es_mscp_entry *entries = NULL;
	size_t count = 0;

	put_index_rec(buf + 0 * ES_MSCP_INDEX_RECLEN, 0xFFFF, "mscp", "dirlabel", 10);
	put_index_rec(buf + 1 * ES_MSCP_INDEX_RECLEN, 0x6F02, "mscp", "cert0001", 900);
	put_index_rec(buf + 2 * ES_MSCP_INDEX_RECLEN, 0x0000, "", "", 0);
	put_index_rec(buf + 3 * ES_MSCP_INDEX_RECLEN, 0x6F03, "mscp", "prvk0001", 64);

	assert_int_equal(es_parse_index(buf, sizeof buf, &entries, &count), SC_SUCCESS);
	assert_int_equal(count, 2);
	assert_int_equal(entries[0].fid, 0x6F02);
	assert_string_equal(entries[0].filename, "cert0001");
	assert_int_equal(entries[0].size_used, 900);
	assert_int_equal(entries[1].fid, 0x6F03);
	assert_string_equal(entries[1].filename, "prvk0001");
	assert_non_null(es_find_entry(entries, count, "prvk0001"));
	assert_null(es_find_entry(entries, count, "prvk0002"));
	free(entries);
}

/* A trailing partial record must not be parsed. */
static void
torture_mscp_index_partial_record(void **state)
{
	u8 buf[ES_MSCP_INDEX_RECLEN + 7];
	struct es_mscp_entry *entries = NULL;
	size_t count = 0;

	memset(buf, 0xAA, sizeof buf);
	put_index_rec(buf, 0x6F02, "mscp", "cert0001", 900);

	assert_int_equal(es_parse_index(buf, sizeof buf, &entries, &count), SC_SUCCESS);
	assert_int_equal(count, 1);
	free(entries);
}

static void
torture_mscp_index_too_short(void **state)
{
	u8 buf[ES_MSCP_INDEX_RECLEN - 1] = {0};
	struct es_mscp_entry *entries = NULL;
	size_t count = 0;

	assert_int_equal(es_parse_index(buf, sizeof buf, &entries, &count),
			SC_ERROR_INVALID_DATA);
}

/* es_parse_containermap() */

static void
torture_mscp_containermap(void **state)
{
	u8 buf[ES_MSCP_CMAP_HEADER_LEN + ES_MSCP_CMAP_RECORD_LEN * 3];
	struct es_containers cm;
	unsigned int priv = 0, pub = 0;

	memset(buf, 0, sizeof buf);
	put_le32(buf + ES_MSCP_CMAP_HEADER_LEN, 0xA020);
	put_le32(buf + ES_MSCP_CMAP_HEADER_LEN + 4, 0x8020);
	put_le32(buf + ES_MSCP_CMAP_HEADER_LEN + ES_MSCP_CMAP_RECORD_LEN, 0xA040);
	put_le32(buf + ES_MSCP_CMAP_HEADER_LEN + ES_MSCP_CMAP_RECORD_LEN + 4, 0x8040);
	/* third record left zeroed: ends the list */

	es_parse_containermap(buf, sizeof buf, &cm);
	assert_int_equal(cm.n, 2);
	assert_int_equal(cm.c[0].priv_handle, 0xA020);
	assert_int_equal(cm.c[1].pub_handle, 0x8040);

	assert_int_equal(es_container_priv_for_pub(&cm, 0x8040, &priv), 1);
	assert_int_equal(priv, 0xA040);
	assert_int_equal(es_container_priv_for_pub(&cm, 0x8099, &priv), 0);

	assert_int_equal(es_container_pub_for_priv_low(&cm, 0x20, &pub), 1);
	assert_int_equal(pub, 0x8020);
}

/* A containermap shorter than its header must yield nothing, not garbage. */
static void
torture_mscp_containermap_short(void **state)
{
	u8 buf[ES_MSCP_CMAP_HEADER_LEN - 1] = {0};
	struct es_containers cm;

	es_parse_containermap(buf, sizeof buf, &cm);
	assert_int_equal(cm.n, 0);
}

/* es_priv_handle_usable() / es_container_has_priv() */

/*
 * Regression guard: the generic layer carries one key reference byte and the
 * driver rebuilds 0xA000 | byte, so 0xA120 would come back as 0xA020 and sign
 * with a different key. Only 0xA020..0xA0FF round-trips.
 */
static void
torture_mscp_priv_handle_range(void **state)
{
	assert_int_equal(es_priv_handle_usable(0xA020), 1);
	assert_int_equal(es_priv_handle_usable(0xA060), 1);
	assert_int_equal(es_priv_handle_usable(0xA0FF), 1);

	assert_int_equal(es_priv_handle_usable(0xA01F), 0); /* below the base */
	assert_int_equal(es_priv_handle_usable(0xA100), 0); /* aliases 0xA000 */
	assert_int_equal(es_priv_handle_usable(0xA120), 0); /* aliases 0xA020 */
	assert_int_equal(es_priv_handle_usable(0xAFFF), 0);
	assert_int_equal(es_priv_handle_usable(0x8020), 0); /* a public handle */
	assert_int_equal(es_priv_handle_usable(0), 0);
}

static void
torture_mscp_container_has_priv(void **state)
{
	struct es_containers cm;

	cm.n = 2;
	cm.c[0].priv_handle = 0xA020;
	cm.c[0].pub_handle = 0x8020;
	cm.c[1].priv_handle = 0xA040;
	cm.c[1].pub_handle = 0x8040;

	assert_int_equal(es_container_has_priv(&cm, 0xA040), 1);
	assert_int_equal(es_container_has_priv(&cm, 0xA060), 0);

	cm.n = 0;
	assert_int_equal(es_container_has_priv(&cm, 0xA020), 0);
}

/* es_strip_leading_zeros() */

static void
torture_mscp_strip_leading_zeros(void **state)
{
	static const u8 padded[] = {0x00, 0xC3, 0x5A};
	static const u8 zeros[] = {0x00, 0x00, 0x00};
	const u8 *p = padded;
	size_t len = sizeof padded;

	es_strip_leading_zeros(&p, &len);
	assert_int_equal(len, 2);
	assert_ptr_equal(p, padded + 1);

	/* an all-zero value keeps one byte, it never empties */
	p = zeros;
	len = sizeof zeros;
	es_strip_leading_zeros(&p, &len);
	assert_int_equal(len, 1);
}

/* es_modulus_bytes() */

/*
 * Regression guard: CKA_MODULUS arrives with the leading zero byte of its
 * two's complement form, so a 2048 bit key is stored as 257 bytes. Using the
 * raw attribute length reported modulus_length = 2056 bit.
 */
static void
torture_mscp_modulus_bytes(void **state)
{
	u8 mod2048[257];
	u8 mod1024[128];

	memset(mod2048, 0xC3, sizeof mod2048);
	mod2048[0] = 0x00; /* padding byte */
	assert_int_equal(es_modulus_bytes(mod2048, sizeof mod2048), 256);
	assert_int_equal(es_modulus_bytes(mod2048, sizeof mod2048) * 8, 2048);

	/* an unpadded modulus is left alone */
	memset(mod1024, 0xC3, sizeof mod1024);
	assert_int_equal(es_modulus_bytes(mod1024, sizeof mod1024) * 8, 1024);

	/* a degenerate all-zero value never collapses to length 0 */
	memset(mod1024, 0, sizeof mod1024);
	assert_int_equal(es_modulus_bytes(mod1024, sizeof mod1024), 1);
}

/* Attribute type numbers written out from the PKCS#11 specification on
 * purpose, independent of the constants the emulator uses. */
#define SPEC_CKA_DECRYPT      0x105U
#define SPEC_CKA_UNWRAP	      0x107U
#define SPEC_CKA_SIGN	      0x108U
#define SPEC_CKA_SIGN_RECOVER 0x109U

static unsigned int
usage_of(unsigned int decrypt, unsigned int unwrap, unsigned int sign, unsigned int sign_recover)
{
	u8 buf[4 * 9];
	size_t n = 0;
	struct es_p11_attr *attrs = NULL;
	size_t nattrs = 0;
	unsigned int usage;

	n += put_attr(buf + n, SPEC_CKA_DECRYPT, 1, (u8)decrypt);
	n += put_attr(buf + n, SPEC_CKA_UNWRAP, 1, (u8)unwrap);
	n += put_attr(buf + n, SPEC_CKA_SIGN, 1, (u8)sign);
	n += put_attr(buf + n, SPEC_CKA_SIGN_RECOVER, 1, (u8)sign_recover);
	assert_int_equal(es_parse_p11_attrs(buf, n, &attrs, &nattrs), SC_SUCCESS);
	usage = es_prkey_usage(attrs, nattrs);
	free(attrs);
	return usage;
}

/* Each flag must be read from its own attribute: a signing key that cannot
 * unwrap still signs, and an unwrap-only key does not. */
static void
torture_mscp_prkey_usage(void **state)
{
	unsigned int all;

	(void)state;
	assert_int_equal(usage_of(0, 0, 1, 0), SC_PKCS15_PRKEY_USAGE_SIGN);
	assert_int_equal(usage_of(0, 1, 0, 0), 0);
	assert_int_equal(usage_of(0, 0, 0, 1), SC_PKCS15_PRKEY_USAGE_SIGNRECOVER);
	assert_int_equal(usage_of(1, 0, 0, 0), SC_PKCS15_PRKEY_USAGE_DECRYPT);
	/* the reference card: all four set */
	all = SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER |
	      SC_PKCS15_PRKEY_USAGE_DECRYPT;
	assert_int_equal(usage_of(1, 1, 1, 1), all);
}

int
main(void)
{
	int rc;
	struct CMUnitTest tests[] = {
			/* es_parse_p11_attrs() */
			cmocka_unit_test(torture_mscp_attrs_wellformed),
			cmocka_unit_test(torture_mscp_attrs_exact_fit),
			cmocka_unit_test(torture_mscp_attrs_huge_len_first),
			cmocka_unit_test(torture_mscp_attrs_huge_len_trailing),
			cmocka_unit_test(torture_mscp_attrs_one_past_end),
			cmocka_unit_test(torture_mscp_attrs_truncated_header),
			/* es_name_is() */
			cmocka_unit_test(torture_mscp_name_is),
			/* es_parse_index() */
			cmocka_unit_test(torture_mscp_index_basic),
			cmocka_unit_test(torture_mscp_index_partial_record),
			cmocka_unit_test(torture_mscp_index_too_short),
			/* es_parse_containermap() */
			cmocka_unit_test(torture_mscp_containermap),
			cmocka_unit_test(torture_mscp_containermap_short),
			/* key handle validation */
			cmocka_unit_test(torture_mscp_priv_handle_range),
			cmocka_unit_test(torture_mscp_container_has_priv),
			/* es_strip_leading_zeros() / es_modulus_bytes() */
			cmocka_unit_test(torture_mscp_strip_leading_zeros),
			cmocka_unit_test(torture_mscp_modulus_bytes),
			/* es_prkey_usage() */
			cmocka_unit_test(torture_mscp_prkey_usage),
	};

	rc = cmocka_run_group_tests(tests, NULL, NULL);
	return rc;
}
