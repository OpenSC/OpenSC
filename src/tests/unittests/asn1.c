/*
 * asn1.c: Unit tests for ASN1 parsers
 *
 * Copyright (C) 2019 Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
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
#include "libopensc/log.c"
#include "libopensc/asn1.c"

/* The last argument is an OID value */
#define TORTURE_OID(name, asn1_data, ...) \
	static void torture_asn1_oid_## name (void **state) \
	{ \
		u8 data[] = asn1_data; \
		size_t datalen = sizeof(data) - 1; \
		struct sc_object_id ref_oid = {{__VA_ARGS__}}; \
		struct sc_object_id oid; \
		int rv; \
		u8 *buf = NULL; \
		size_t buflen = 0; \
	\
		rv = sc_asn1_decode_object_id(data, datalen, &oid); \
		assert_int_equal(rv, SC_SUCCESS); \
		assert_int_equal(sc_compare_oid(&ref_oid, &oid), 1); /* XXX */ \
		rv = sc_asn1_encode_object_id(&buf, &buflen, &oid); \
		assert_int_equal(rv, SC_SUCCESS); \
		assert_int_equal(buflen, datalen); \
		assert_memory_equal(buf, data, buflen); \
		free(buf); \
	}
#define TORTURE_OID_ERROR(name, asn1_data, error) \
	static void torture_asn1_oid_## name (void **state) \
	{ \
		u8 data[] = asn1_data; \
		size_t datalen = sizeof(data) - 1; \
		struct sc_object_id oid; \
		int rv; \
	\
		rv = sc_asn1_decode_object_id(data, datalen, &oid); \
		assert_int_equal(rv, error); \
	}

/* Without the tag (0x06) and length */
/* Small OID values */
TORTURE_OID(small, "\x01\x02\x03\x04\x05\x06", 0, 1, 2, 3, 4, 5, 6, -1)
/* Limit what we can fit into the first byte */
TORTURE_OID(limit, "\x7F", 2, 47, -1)
/* The second octet already overflows to the second byte */
TORTURE_OID(two_byte, "\x81\x00", 2, 48, -1)
/* Existing OID ec publickey */
TORTURE_OID(ecpubkey, "\x2A\x86\x48\xCE\x3D\x02\x01", 1, 2, 840, 10045, 2, 1, -1)

/* Negative tests */
/* Missing second byte, even though indicated with the first bit */
TORTURE_OID_ERROR(missing, "\x81", SC_ERROR_INVALID_ASN1_OBJECT)
/* Missing second byte in later identifiers */
TORTURE_OID_ERROR(missing_second, "\x2A\x48\x81", SC_ERROR_INVALID_ASN1_OBJECT)
/* Non-minimal encoding of first part */
TORTURE_OID_ERROR(non_minimal_second, "\x2A\x80\x01", SC_ERROR_INVALID_ASN1_OBJECT)
/* Non-minimal encoding of first part */
TORTURE_OID_ERROR(non_minimal, "\x80\x01", SC_ERROR_INVALID_ASN1_OBJECT)

/*
 * Test undefined behavior of too large parts of OID encoding
 *
 * The specification does not place any limits to these values, but they
 * are internally in opensc stored as ints so it makes sense to reject
 * the too-large onese for now, rather than causing undefined overflow.
 *
 * https://oss-fuzz.com/testcase-detail/5673497895895040
 */
#if INT_MAX == 2147483647
/* 2.5.4.2147483647 (The last part is largest 32 bit integer) */
TORTURE_OID(last_int_max, "\x55\x04\x87\xFF\xFF\xFF\x7F", 2, 5, 4, 2147483647, -1)
/* 2.2147483647.4.3 (The second part is largest 32 bit integer) */
TORTURE_OID(first_int_max, "\x88\x80\x80\x80\x4F\x04\x03", 2, 2147483647, 4, 3, -1)
#else
/* 2.5.4.2147483647 (The last part is largest 32 bit integer) */
TORTURE_OID_ERROR(last_int_max, "\x55\x04\x87\xFF\xFF\xFF\x7F", SC_ERROR_NOT_SUPPORTED)
/* 2.2147483647.4.3 (The second part is largest 32 bit integer) */
TORTURE_OID_ERROR(first_int_max, "\x88\x80\x80\x80\x4F\x04\x03", SC_ERROR_NOT_SUPPORTED)
#endif

/* 2.5.4.2147483648 (The last part is 32 bit integer overflow) */
TORTURE_OID_ERROR(last_32b_overflow, "\x55\x04\x88\x80\x80\x80\x00", SC_ERROR_NOT_SUPPORTED)
/* 2.2147483648.4.3 (The second part is 32 bit integer overflow) */
TORTURE_OID_ERROR(first_32b_overflow, "\x88\x80\x80\x80\x50\x04\x03", SC_ERROR_NOT_SUPPORTED)
/* TODO SC_MAX_OBJECT_ID_OCTETS */

#define TORTURE_INTEGER(name, asn1_data, int_value) \
	static void torture_asn1_integer_## name (void **state) \
	{ \
		u8 data[] = asn1_data; \
		size_t datalen = sizeof(data) - 1; \
		int value = 0; \
		int rv; \
		u8 *buf = NULL; \
		size_t buflen = 0; \
	\
		rv = sc_asn1_decode_integer(data, datalen, &value, 1); \
		assert_int_equal(rv, SC_SUCCESS); \
		assert_int_equal(value, int_value); \
		rv = asn1_encode_integer(value, &buf, &buflen); \
		assert_int_equal(rv, SC_SUCCESS); \
		assert_int_equal(buflen, datalen); \
		assert_memory_equal(buf, data, buflen); \
		free(buf); \
	}
#define TORTURE_INTEGER_ERROR(name, asn1_data, error) \
	static void torture_asn1_integer_## name (void **state) \
	{ \
		u8 data[] = asn1_data; \
		size_t datalen = sizeof(data) - 1; \
		int value = 0; \
		int rv; \
	\
		rv = sc_asn1_decode_integer(data, datalen, &value, 1); \
		assert_int_equal(rv, error); \
	}
#define TORTURE_INTEGER_NONSTRICT(name, asn1_data, error, int_value) \
	static void torture_asn1_integer_## name (void **state) \
	{ \
		u8 data[] = asn1_data; \
		size_t datalen = sizeof(data) - 1; \
		int value = 0; \
		int rv; \
	\
		rv = sc_asn1_decode_integer(data, datalen, &value, 1); \
		assert_int_equal(rv, error); \
		/* but we can parse them without the strict checking */ \
		rv = sc_asn1_decode_integer(data, datalen, &value, 0); \
		assert_int_equal(rv, SC_SUCCESS); \
		assert_int_equal(value, int_value); \
	}

/* Data are without the Tag (0x02) and Length */
/* Positive test cases, mostly corner cases */
TORTURE_INTEGER(zero, "\x00", 0)
TORTURE_INTEGER(one, "\x01", 1)
TORTURE_INTEGER(minus_one, "\xFF", -1)
TORTURE_INTEGER(padded_128, "\x00\x80", 128)
TORTURE_INTEGER(max2, "\x7F\xFF", 32767)
TORTURE_INTEGER(min2, "\x80\x00", -32768)

#if INT_MAX == 2147483647
TORTURE_INTEGER(max4, "\x7F\xFF\xFF\xFF", 2147483647)
TORTURE_INTEGER(min4, "\x80\x00\x00\x00", -2147483648)
#else
TORTURE_INTEGER_ERROR(max4, "\x7F\xFF\xFF\xFF", SC_ERROR_NOT_SUPPORTED)
TORTURE_INTEGER_ERROR(min4, "\x80\x00\x00\x00", SC_ERROR_NOT_SUPPORTED)
#endif

/* Negative test cases */
TORTURE_INTEGER_ERROR(null, "", SC_ERROR_INVALID_ASN1_OBJECT)
TORTURE_INTEGER_ERROR(over, "\x7F\xFF\xFF\xFF\xFF", SC_ERROR_NOT_SUPPORTED)

/* Tests fail in strict mode, but work otherwise */
TORTURE_INTEGER_NONSTRICT(padded_zero, "\x00\x00", SC_ERROR_INVALID_ASN1_OBJECT, 0)
TORTURE_INTEGER_NONSTRICT(padded_one, "\x00\x01", SC_ERROR_INVALID_ASN1_OBJECT, 1)
TORTURE_INTEGER_NONSTRICT(padded_minus_one, "\xFF\xFF", SC_ERROR_INVALID_ASN1_OBJECT, -1)
TORTURE_INTEGER_NONSTRICT(padded_127, "\x00\x7F", SC_ERROR_INVALID_ASN1_OBJECT, 127)

/*
 * Test undefined behavior of negative INTEGERS handling.
 * https://oss-fuzz.com/testcase-detail/5125815506829312
 *
 * The issue was not actually the size of the integers, but that first
 * negative value wrote ones to the whole integer and it was not possible
 * to shift values afterward.
 */
TORTURE_INTEGER(negative, "\xff\x20", -224)

#define TORTURE_BIT_FIELD(name, asn1_data, int_value) \
	static void torture_asn1_bit_field_## name (void **state) \
	{ \
		u8 data[] = asn1_data; \
		size_t datalen = sizeof(data) - 1; \
		unsigned int value = 0; \
		size_t value_len = sizeof(value); \
		int rv; \
	\
		rv = decode_bit_field(data, datalen, &value, value_len); \
		assert_int_equal(rv, SC_SUCCESS); \
		assert_int_equal(value, int_value); \
	}
#define TORTURE_BIT_FIELD_ERROR(name, asn1_data, error) \
	static void torture_asn1_bit_field_## name (void **state) \
	{ \
		u8 data[] = asn1_data; \
		size_t datalen = sizeof(data) - 1; \
		unsigned int value = 0; \
		size_t value_len = sizeof(value); \
		int rv; \
	\
		rv = decode_bit_field(data, datalen, &value, value_len); \
		assert_int_equal(rv, error); \
	}
/* Without the Tag (0x03) and Length */
/* Simple value 0 */
TORTURE_BIT_FIELD(zero, "\x07\x00", 0)
/* Simple value 1 */
TORTURE_BIT_FIELD(one, "\x07\x80", 1)
/* This is the last value that can be represented in the unsigned int */
TORTURE_BIT_FIELD(uint_max, "\x00\xff\xff\xff\xff", UINT_MAX)
/* Valid padding */
TORTURE_BIT_FIELD(padding, "\x01\xfe", 127)
/* Empty bit field needs zero padding */
TORTURE_BIT_FIELD(zero_only, "\x00", 0)

/* Negative test cases */
/* Too large unused bits field */
TORTURE_BIT_FIELD_ERROR(large_unused_bits, "\x20\xff\xff\xff\xff", SC_ERROR_INVALID_ASN1_OBJECT)
/* Too large to represent in the unsigned int type */
TORTURE_BIT_FIELD_ERROR(too_large, "\x00\xff\xff\xff\xff\xff", SC_ERROR_BUFFER_TOO_SMALL)
/* Invalid (non-zero bits) padding */
TORTURE_BIT_FIELD_ERROR(invalid_padding, "\x01\xff", SC_ERROR_INVALID_ASN1_OBJECT)
/* Empty bit field with non-zero zero-bits */
TORTURE_BIT_FIELD_ERROR(zero_invalid, "\x07", SC_ERROR_INVALID_ASN1_OBJECT)
/* Empty BIT FIELD is not valid */
TORTURE_BIT_FIELD_ERROR(empty, "", SC_ERROR_INVALID_ASN1_OBJECT)

/* Setup context */
static int setup_sc_context(void **state)
{
	sc_context_t *ctx = NULL;
	int rv;

	rv = sc_establish_context(&ctx, "fuzz");
	assert_non_null(ctx);
	assert_int_equal(rv, SC_SUCCESS);

	*state = ctx;

	return 0;
}

/* Cleanup context */
static int teardown_sc_context(void **state)
{
	sc_context_t *ctx = *state;
	int rv;

	rv = sc_release_context(ctx);
	assert_int_equal(rv, SC_SUCCESS);

	return 0;
}

#define DEPTH 1
static void torture_asn1_decode_entry_octet_string_empty(void **state)
{
	sc_context_t *ctx = *state;
	/* Skipped the Tag and Length (0x04, 0x00) */
	const u8 octet_string[0] = {};
	struct sc_asn1_entry asn1_struct[2] = {
		{ "direct",     SC_ASN1_OCTET_STRING, SC_ASN1_CTX | SC_ASN1_CONS, SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	u8 *result = NULL;
	size_t resultlen = 0;
	int rv;

	/* set the pointers to the expected results */
	sc_format_asn1_entry(asn1_struct, &result, &resultlen, 0);
	rv = asn1_decode_entry(ctx, asn1_struct, octet_string, 0, DEPTH);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(resultlen, 0);
	assert_null(result);
}

static void torture_asn1_decode_entry_octet_string_short(void **state)
{
	sc_context_t *ctx = *state;
	/* Skipped the Tag and Length (0x04, 0x01) */
	const u8 octet_string[] = {0xbc};
	struct sc_asn1_entry asn1_struct[2] = {
		{ "direct",     SC_ASN1_OCTET_STRING, SC_ASN1_CTX | SC_ASN1_CONS,
			SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	u8 *result = NULL;
	size_t resultlen = 0;
	int rv;

	/* set the pointers to the expected results */
	sc_format_asn1_entry(asn1_struct, &result, &resultlen, 0);
	rv = asn1_decode_entry(ctx, asn1_struct, octet_string, sizeof(octet_string), DEPTH);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(resultlen, sizeof(octet_string));
	assert_memory_equal(result, octet_string, resultlen);
}

/* In case of we expect UNSIGNED value from this, the parser already takes
 * care of removing initial zero byte, which is used to avoid mismatches with
 * negative integers */
static void torture_asn1_decode_entry_octet_string_unsigned(void **state)
{
	sc_context_t *ctx = *state;
	/* Skipped the Tag and Length (0x04, 0x02) */
	const u8 octet_string[] = {0x00, 0xff};
	struct sc_asn1_entry asn1_struct[2] = {
		{ "direct",     SC_ASN1_OCTET_STRING, SC_ASN1_CTX | SC_ASN1_CONS,
			SC_ASN1_ALLOC | SC_ASN1_UNSIGNED, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	u8 *result = NULL;
	size_t resultlen = 0;
	int rv;

	/* set the pointers to the expected results */
	sc_format_asn1_entry(asn1_struct, &result, &resultlen, 0);
	rv = asn1_decode_entry(ctx, asn1_struct, octet_string, sizeof(octet_string), DEPTH);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(resultlen, sizeof(octet_string) -1);
	assert_memory_equal(result, octet_string + 1, resultlen);
}

static void torture_asn1_decode_entry_octet_string_pre_allocated(void **state)
{
	sc_context_t *ctx = *state;
	/* Skipped the Tag and Length (0x04, 0x02) */
	const u8 octet_string[] = {0x01, 0x02, 0x03, 0x04};
	struct sc_asn1_entry asn1_struct[2] = {
		{ "direct",     SC_ASN1_OCTET_STRING, SC_ASN1_CTX | SC_ASN1_CONS, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	u8 result[8];
	size_t resultlen = sizeof(result);
	int rv;

	/* set the pointers to the expected results */
	sc_format_asn1_entry(asn1_struct, &result, &resultlen, 0);
	rv = asn1_decode_entry(ctx, asn1_struct, octet_string, sizeof(octet_string), DEPTH);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(resultlen, sizeof(octet_string));
	assert_memory_equal(result, octet_string, resultlen);
}

static void torture_asn1_decode_entry_octet_string_pre_allocated_truncate(void **state)
{
	sc_context_t *ctx = *state;
	/* Skipped the Tag and Length (0x04, 0x02) */
	const u8 octet_string[] = {0x01, 0x02, 0x03, 0x04};
	struct sc_asn1_entry asn1_struct[2] = {
		{ "direct",     SC_ASN1_OCTET_STRING, SC_ASN1_CTX | SC_ASN1_CONS, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	u8 result[2];
	size_t resultlen = sizeof(result);
	int rv;

	/* set the pointers to the expected results */
	sc_format_asn1_entry(asn1_struct, &result, &resultlen, 0);
	rv = asn1_decode_entry(ctx, asn1_struct, octet_string, sizeof(octet_string), DEPTH);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(resultlen, sizeof(result));
	assert_memory_equal(result, octet_string, resultlen);
}

static void torture_asn1_decode_entry_bit_string_empty(void **state)
{
	sc_context_t *ctx = *state;
	/* Skipped the Tag and Length (0x04, 0x00) */
	const u8 bit_string[] = {0x00};
	struct sc_asn1_entry asn1_struct[2] = {
		{ "signatureValue", SC_ASN1_BIT_STRING, SC_ASN1_TAG_BIT_STRING, SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	u8 *result = NULL;
	size_t resultlen = 0;
	int rv;

	/* set the pointers to the expected results */
	sc_format_asn1_entry(asn1_struct, &result, &resultlen, 0);
	rv = asn1_decode_entry(ctx, asn1_struct, bit_string, sizeof(bit_string), DEPTH);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(resultlen, 0);
	assert_null(result);
}

static void torture_asn1_decode_entry_bit_string_short(void **state)
{
	sc_context_t *ctx = *state;
	/* Skipped the Tag and Length (0x04, 0x00) */
	const u8 bit_string[] = {0x00, 0xFE};
	/* By default, the bit string has MSB on the right. Yay */
	const u8 exp_result[] = {0x7F};
	struct sc_asn1_entry asn1_struct[2] = {
		{ "signatureValue", SC_ASN1_BIT_STRING, SC_ASN1_TAG_BIT_STRING, SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	u8 *result = NULL;
	size_t resultlen = 0;
	int rv;

	/* set the pointers to the expected results */
	sc_format_asn1_entry(asn1_struct, &result, &resultlen, 0);
	rv = asn1_decode_entry(ctx, asn1_struct, bit_string, sizeof(bit_string), DEPTH);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(resultlen, 8);
	assert_memory_equal(exp_result, result, resultlen/8);
}

/* This modification does not invert the bit order */
static void torture_asn1_decode_entry_bit_string_ni(void **state)
{
	sc_context_t *ctx = *state;
	/* Skipped the Tag and Length (0x04, 0x00) */
	const u8 bit_string[] = {0x00, 0xFE};
	struct sc_asn1_entry asn1_struct[2] = {
		{ "signatureValue", SC_ASN1_BIT_STRING_NI, SC_ASN1_TAG_BIT_STRING, SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	u8 *result = NULL;
	size_t resultlen = 0;
	int rv;

	/* set the pointers to the expected results */
	sc_format_asn1_entry(asn1_struct, &result, &resultlen, 0);
	rv = asn1_decode_entry(ctx, asn1_struct, bit_string, sizeof(bit_string), DEPTH);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(resultlen, 8);
	assert_memory_equal(bit_string + 1, result, resultlen/8);
}

static void torture_asn1_put_tag_short(void **state)
{
	unsigned int tag = 0xAC;
	const u8 expected[] = {0xAC, 0x01, 0x02};
	const u8 data[] = {0x02};
	size_t data_len = 1;
	u8 out[10];
	size_t out_len = sizeof(out);
	u8 *p = out;
	int rv;

	/* Without the out and out_len we are getting expected length */
	rv = sc_asn1_put_tag(tag, data, data_len, NULL, 0, &p);
	assert_int_equal(rv, sizeof(expected));
	assert_ptr_equal(p, out);

	/* Now we do the actual encoding */
	rv = sc_asn1_put_tag(tag, data, data_len, out, out_len, &p);
	assert_int_equal(rv, SC_SUCCESS);
	assert_memory_equal(out, expected, sizeof(expected));
	assert_ptr_equal(p, out + sizeof(expected));

	/* Short buffer */
	rv = sc_asn1_put_tag(tag, data, data_len, out, 2, &p);
	assert_int_equal(rv, SC_ERROR_BUFFER_TOO_SMALL);
}

static void torture_asn1_put_tag_long_tag(void **state)
{
	/* Max supported value already encoded as ASN1 tag */
	unsigned int tag = 0xFFFFFF7F;
	const u8 expected[] = {0xFF, 0xFF, 0xFF, 0x7F, 0x01, 0x02};
	const u8 data[] = {0x02};
	size_t data_len = 1;
	u8 out[10];
	size_t out_len = sizeof(out);
	u8 *p = out;
	int rv;

	/* Without the out and out_len we are getting expected length */
	rv = sc_asn1_put_tag(tag, data, data_len, NULL, 0, &p);
	assert_int_equal(rv, sizeof(expected));
	assert_ptr_equal(p, out);

	/* Now we do the actual encoding */
	rv = sc_asn1_put_tag(tag, data, data_len, out, out_len, &p);
	assert_int_equal(rv, SC_SUCCESS);
	assert_memory_equal(out, expected, sizeof(expected));
	assert_ptr_equal(p, out + sizeof(expected));

	/* The buffer is too small */
	rv = sc_asn1_put_tag(tag, data, data_len, out, 5, &p);
	assert_int_equal(rv, SC_ERROR_BUFFER_TOO_SMALL);

	/* the MSB of last byte needs to be 0 */
	tag = 0xFFFFFF8F;
	rv = sc_asn1_put_tag(tag, data, data_len, NULL, 0, NULL);
	assert_int_equal(rv, SC_ERROR_INVALID_DATA);

	/* the MSB of all byts needs to be 1 */
	tag = 0xFFFF7F7F;
	rv = sc_asn1_put_tag(tag, data, data_len, NULL, 0, NULL);
	assert_int_equal(rv, SC_ERROR_INVALID_DATA);

	/* First byte has bits 5-1 set to 1 */
	tag = 0xE0FFFF7F;
	rv = sc_asn1_put_tag(tag, data, data_len, NULL, 0, NULL);
	assert_int_equal(rv, SC_ERROR_INVALID_DATA);
}

static void torture_asn1_put_tag_long_data(void **state)
{
	unsigned int tag = 0xAC;
	const u8 expected[131] = {0xAC, 0x81, 0x80, 0x00, /* the rest is zero */};
	const u8 data[128] = {0};
	size_t data_len = sizeof(data);
	u8 out[200];
	size_t out_len = sizeof(out);
	u8 *p = out;
	int rv;

	/* Without the out and out_len we are getting expected length */
	rv = sc_asn1_put_tag(tag, data, data_len, NULL, 0, &p);
	assert_int_equal(rv, sizeof(expected));
	assert_ptr_equal(p, out);

	/* Now we do the actual encoding */
	rv = sc_asn1_put_tag(tag, data, data_len, out, out_len, &p);
	assert_int_equal(rv, SC_SUCCESS);
	assert_memory_equal(out, expected, sizeof(expected));
	assert_ptr_equal(p, out + sizeof(expected));

	/* The buffer is too small */
	rv = sc_asn1_put_tag(tag, data, data_len, out, 130, &p);
	assert_int_equal(rv, SC_ERROR_BUFFER_TOO_SMALL);
}

static void torture_asn1_put_tag_without_data(void **state)
{
	unsigned int tag = 0xAC;
	const u8 expected[] = {0xAC, 0x01};
	size_t data_len = 1;
	u8 out[10];
	size_t out_len = sizeof(out);
	u8 *p = out;
	int rv;

	/* Without the out and out_len we are getting expected length */
	rv = sc_asn1_put_tag(tag, NULL, data_len, NULL, 0, &p);
	assert_int_equal(rv, sizeof(expected) + data_len);
	assert_ptr_equal(p, out);

	/* Now we do the actual encoding, but data field is not filled */
	rv = sc_asn1_put_tag(tag, NULL, data_len, out, out_len, &p);
	assert_int_equal(rv, SC_SUCCESS);
	assert_memory_equal(out, expected, sizeof(expected));
	assert_ptr_equal(p, out + sizeof(expected));
}

int main(void)
{
	int rc;
	struct CMUnitTest tests[] = {
		/* INTEGER */
		cmocka_unit_test(torture_asn1_integer_zero),
		cmocka_unit_test(torture_asn1_integer_one),
		cmocka_unit_test(torture_asn1_integer_minus_one),
		cmocka_unit_test(torture_asn1_integer_padded_128),
		cmocka_unit_test(torture_asn1_integer_max2),
		cmocka_unit_test(torture_asn1_integer_min2),
		cmocka_unit_test(torture_asn1_integer_max4),
		cmocka_unit_test(torture_asn1_integer_min4),
		cmocka_unit_test(torture_asn1_integer_null),
		cmocka_unit_test(torture_asn1_integer_over),
		cmocka_unit_test(torture_asn1_integer_padded_zero),
		cmocka_unit_test(torture_asn1_integer_padded_one),
		cmocka_unit_test(torture_asn1_integer_padded_minus_one),
		cmocka_unit_test(torture_asn1_integer_padded_127),
		cmocka_unit_test(torture_asn1_integer_negative),
		/* OBJECT ID */
		cmocka_unit_test(torture_asn1_oid_small),
		cmocka_unit_test(torture_asn1_oid_limit),
		cmocka_unit_test(torture_asn1_oid_two_byte),
		cmocka_unit_test(torture_asn1_oid_ecpubkey),
		cmocka_unit_test(torture_asn1_oid_missing),
		cmocka_unit_test(torture_asn1_oid_missing_second),
		cmocka_unit_test(torture_asn1_oid_last_int_max),
		cmocka_unit_test(torture_asn1_oid_first_int_max),
		cmocka_unit_test(torture_asn1_oid_last_32b_overflow),
		cmocka_unit_test(torture_asn1_oid_first_32b_overflow),
		cmocka_unit_test(torture_asn1_oid_non_minimal),
		cmocka_unit_test(torture_asn1_oid_non_minimal_second),
		/* BIT FIELD */
		cmocka_unit_test(torture_asn1_bit_field_zero),
		cmocka_unit_test(torture_asn1_bit_field_one),
		cmocka_unit_test(torture_asn1_bit_field_uint_max),
		cmocka_unit_test(torture_asn1_bit_field_padding),
		cmocka_unit_test(torture_asn1_bit_field_zero_only),
		cmocka_unit_test(torture_asn1_bit_field_large_unused_bits),
		cmocka_unit_test(torture_asn1_bit_field_too_large),
		cmocka_unit_test(torture_asn1_bit_field_invalid_padding),
		cmocka_unit_test(torture_asn1_bit_field_zero_invalid),
		cmocka_unit_test(torture_asn1_bit_field_empty),
		/* decode_entry(): OCTET STRING */
		cmocka_unit_test_setup_teardown(torture_asn1_decode_entry_octet_string_empty,
			setup_sc_context, teardown_sc_context),
		cmocka_unit_test_setup_teardown(torture_asn1_decode_entry_octet_string_short,
			setup_sc_context, teardown_sc_context),
		cmocka_unit_test_setup_teardown(torture_asn1_decode_entry_octet_string_unsigned,
			setup_sc_context, teardown_sc_context),
		cmocka_unit_test_setup_teardown(torture_asn1_decode_entry_octet_string_pre_allocated,
			setup_sc_context, teardown_sc_context),
		cmocka_unit_test_setup_teardown(torture_asn1_decode_entry_octet_string_pre_allocated_truncate,
			setup_sc_context, teardown_sc_context),
		/* decode_entry(): BIT STRING */
		cmocka_unit_test_setup_teardown(torture_asn1_decode_entry_bit_string_empty,
			setup_sc_context, teardown_sc_context),
		cmocka_unit_test_setup_teardown(torture_asn1_decode_entry_bit_string_short,
			setup_sc_context, teardown_sc_context),
		cmocka_unit_test_setup_teardown(torture_asn1_decode_entry_bit_string_ni,
			setup_sc_context, teardown_sc_context),
		/* put_tag() */
		cmocka_unit_test(torture_asn1_put_tag_short),
		cmocka_unit_test(torture_asn1_put_tag_without_data),
		cmocka_unit_test(torture_asn1_put_tag_long_tag),
		cmocka_unit_test(torture_asn1_put_tag_long_data),
	};

	rc = cmocka_run_group_tests(tests, NULL, NULL);
	return rc;
}
