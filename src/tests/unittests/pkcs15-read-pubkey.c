/*
 * pkcs15-read-pubkey.c: Unit tests for reading public keys through card drivers
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

#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"
#include "torture.h"

/* P-256 base point G as uncompressed ECPoint */
#define P256_G \
	0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, \
			0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, \
			0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, \
			0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, \
			0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, \
			0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5

/* SubjectPublicKeyInfo: id-ecPublicKey, prime256v1, BIT STRING with the point */
static const u8 spki_p256[] = {
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
		0x03, 0x42, 0x00, P256_G};

/* RAW value: ECPoint as OCTET STRING, without curve parameters */
static const u8 raw_p256[] = {0x04, 0x41, P256_G};

static const u8 oid_prime256v1[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

static const u8 *card_data;
static size_t card_data_len;

static int
fake_read_public_key(sc_card_t *card, unsigned algorithm, struct sc_path *path, unsigned key_reference,
		unsigned modulus_length, u8 **out, size_t *out_len)
{
	(void)card;
	(void)algorithm;
	(void)path;
	(void)key_reference;
	(void)modulus_length;

	*out = malloc(card_data_len);
	if (*out == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(*out, card_data, card_data_len);
	*out_len = card_data_len;
	return SC_SUCCESS;
}

static int
read_ec_pubkey(sc_context_t *ctx, const u8 *data, size_t len, struct sc_pkcs15_pubkey **pubkey)
{
	struct sc_card_operations ops = {0};
	sc_card_t card = {0};
	struct sc_pkcs15_card p15card = {0};
	struct sc_pkcs15_pubkey_info info = {0};
	struct sc_pkcs15_object obj = {0};

	ops.read_public_key = fake_read_public_key;
	card.ctx = ctx;
	card.ops = &ops;
	p15card.card = &card;
	sc_format_path("3F0041005001", &info.path);
	obj.type = SC_PKCS15_TYPE_PUBKEY_EC;
	obj.data = &info;

	card_data = data;
	card_data_len = len;
	return sc_pkcs15_read_pubkey(&p15card, &obj, pubkey);
}

static int
setup(void **state)
{
	sc_context_t *ctx = NULL;

	assert_int_equal(sc_establish_context(&ctx, "pkcs15-read-pubkey"), SC_SUCCESS);
	*state = ctx;
	return 0;
}

static int
teardown(void **state)
{
	assert_int_equal(sc_release_context(*state), SC_SUCCESS);
	return 0;
}

/* A card driver returning an SPKI keeps the curve parameters */
static void
torture_ec_spki_from_card(void **state)
{
	struct sc_pkcs15_pubkey *pubkey = NULL;

	assert_int_equal(read_ec_pubkey(*state, spki_p256, sizeof(spki_p256), &pubkey), SC_SUCCESS);
	assert_non_null(pubkey);
	assert_int_equal(pubkey->algorithm, SC_ALGORITHM_EC);
	assert_int_equal(pubkey->u.ec.ecpointQ.len, 65);
	assert_int_equal(pubkey->u.ec.ecpointQ.value[0], 0x04);
	assert_int_equal(pubkey->u.ec.params.der.len, sizeof(oid_prime256v1));
	assert_memory_equal(pubkey->u.ec.params.der.value, oid_prime256v1, sizeof(oid_prime256v1));
	sc_pkcs15_free_pubkey(pubkey);
}

/* A RAW ECPoint is still decoded as before */
static void
torture_ec_raw_from_card(void **state)
{
	struct sc_pkcs15_pubkey *pubkey = NULL;

	assert_int_equal(read_ec_pubkey(*state, raw_p256, sizeof(raw_p256), &pubkey), SC_SUCCESS);
	assert_non_null(pubkey);
	assert_int_equal(pubkey->u.ec.ecpointQ.len, 65);
	assert_int_equal(pubkey->u.ec.ecpointQ.value[0], 0x04);
	sc_pkcs15_free_pubkey(pubkey);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup_teardown(torture_ec_spki_from_card, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_ec_raw_from_card, setup, teardown),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
