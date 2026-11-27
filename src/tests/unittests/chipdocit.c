/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Regression tests for the ChipDoc-IT (Bit4id Digital-DNA) driver and PKCS#15
 * emulator. The card is simulated at the reader level with synthetic public
 * EF contents: no PIN, PACE, Secure Messaging or private-key operation is
 * performed, and no real certificate or card data is used.
 */
#include "torture.h"

#include "libopensc/internal.h"
#include "libopensc/pkcs15-syn.h"
#include "libopensc/pkcs15.h"

/* sc_get_chipdocit_driver() (cards.h, via internal.h) and the emulator entry
 * point are not exported by the shared library: this test is linked statically
 * (see Makefile.am). */

/* Synthetic EF payloads. The certificate stand-ins are distinct ASN.1 values
 * used to check the EF -> certificate association, not X.509 parsing. */
static const u8 cert_ef[2][5] = {
		{0x30, 0x03, 0x02, 0x01, 0x01},
		{0x30, 0x03, 0x02, 0x01, 0x02}
};
static const u8 enc_can_ef[24] = {0};

/* State of the simulated card and of the observed card operations. */
static struct {
	const u8 *ef;
	size_t ef_len;
	unsigned int transmits;
	unsigned int reads;
	unsigned int set_env_calls;
	unsigned int sign_calls;
	unsigned int decipher_calls;
	int env_operation;
	u8 env_key_ref;
	size_t sign_len;
	u8 sign_head[2];
} sim;

static int
sim_transmit(sc_reader_t *reader, sc_apdu_t *apdu)
{
	(void)reader;
	sim.transmits++;
	apdu->sw1 = 0x90;
	apdu->sw2 = 0x00;

	switch (apdu->ins) {
	case 0xA4: /* SELECT: by AID, by path or by file ID */
		if (apdu->p1 != 0x04 && apdu->datalen >= 2) {
			unsigned int fid = apdu->data[apdu->datalen - 2] << 8 | apdu->data[apdu->datalen - 1];

			sim.ef = NULL;
			sim.ef_len = 0;
			if (fid == 0x0001 || fid == 0x0002) {
				sim.ef = cert_ef[fid - 1];
				sim.ef_len = sizeof cert_ef[0];
			} else if (fid == 0xE000) {
				sim.ef = enc_can_ef;
				sim.ef_len = sizeof enc_can_ef;
			}
		}
		apdu->resplen = 0;
		break;
	case 0xB0: { /* READ BINARY */
		size_t offset = (size_t)apdu->p1 << 8 | apdu->p2;
		size_t n = 0;

		sim.reads++;
		if (sim.ef && offset < sim.ef_len) {
			n = MIN(sim.ef_len - offset, apdu->resplen);
			memcpy(apdu->resp, sim.ef + offset, n);
		}
		apdu->resplen = n;
		break;
	}
	case 0xCA: /* GET DATA (card serial): not provided */
		apdu->resplen = 0;
		apdu->sw1 = 0x6A;
		apdu->sw2 = 0x88;
		break;
	default:
		apdu->resplen = 0;
		apdu->sw1 = 0x6D;
		apdu->sw2 = 0x00;
		break;
	}
	return SC_SUCCESS;
}

/* Card operations observed by the routing test. They only record the call: the
 * point is which operation OpenSC selects, not the card-side cryptography. */
static int
sim_set_security_env(sc_card_t *card, const sc_security_env_t *env, int se_num)
{
	(void)card;
	(void)se_num;
	sim.set_env_calls++;
	sim.env_operation = env->operation;
	sim.env_key_ref = (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) && env->key_ref_len == 1 ? env->key_ref[0] : 0;
	return SC_SUCCESS;
}

static int
sim_compute_signature(sc_card_t *card, const u8 *data, size_t data_len, u8 *out, size_t outlen)
{
	(void)card;
	sim.sign_calls++;
	sim.sign_len = data_len;
	if (data_len >= 2)
		memcpy(sim.sign_head, data, 2);
	if (outlen < data_len)
		return SC_ERROR_BUFFER_TOO_SMALL;
	memset(out, 0x5A, data_len);
	return (int)data_len;
}

static int
sim_decipher(sc_card_t *card, const u8 *in, size_t inlen, u8 *out, size_t outlen)
{
	(void)card;
	(void)in;
	sim.decipher_calls++;
	if (outlen < inlen)
		return SC_ERROR_BUFFER_TOO_SMALL;
	memset(out, 0x5A, inlen);
	return (int)inlen;
}

static struct sc_reader_operations sim_reader_ops = {
		.transmit = sim_transmit,
};

struct fixture {
	sc_context_t ctx;
	sc_reader_t reader;
	sc_card_t card;
	struct sc_card_operations observed_ops;
	struct sc_card_operations *driver_ops;
	sc_pkcs15_card_t *p15;
};

/* Bind the real chipdoc-it card driver to the simulated reader and run its
 * init, so the tests see the algorithm flags the driver really registers. No
 * OpenSC context is established, hence no system reader is ever touched. */
static int
setup(void **state)
{
	struct fixture *f = calloc(1, sizeof(*f));
	struct sc_card_driver *drv = sc_get_chipdocit_driver();

	assert_non_null(f);
	assert_non_null(drv);
	memset(&sim, 0, sizeof sim);

	f->reader.ctx = &f->ctx;
	f->reader.name = "Simulated reader";
	f->reader.ops = &sim_reader_ops;
	f->reader.active_protocol = SC_PROTO_T1;

	f->card.ctx = &f->ctx;
	f->card.reader = &f->reader;
	f->card.driver = drv;
	f->card.ops = drv->ops;
	f->card.type = SC_CARD_TYPE_CHIPDOC_IT;
	f->card.name = "Simulated ChipDoc";
	f->driver_ops = drv->ops;
	assert_int_equal(drv->ops->init(&f->card), SC_SUCCESS);

	f->p15 = sc_pkcs15_card_new();
	assert_non_null(f->p15);
	f->p15->card = &f->card;
	sim.transmits = 0;
	sim.reads = 0;
	*state = f;
	return 0;
}

static int
teardown(void **state)
{
	struct fixture *f = *state;

	sc_pkcs15_card_free(f->p15);
	f->card.ops = f->driver_ops;
	f->driver_ops->finish(&f->card);
	free(f->card.algorithms);
	free(f);
	return 0;
}

static sc_pkcs15_object_t *
object_by_id(struct fixture *f, unsigned int type, u8 id)
{
	sc_pkcs15_id_t wanted = {0};
	sc_pkcs15_object_t *objects[3];
	sc_pkcs15_object_t *found = NULL;
	int i;

	wanted.len = 1;
	wanted.value[0] = id;
	assert_int_equal(sc_pkcs15_get_objects(f->p15, type, objects, 3), 2);
	for (i = 0; i < 2; i++) {
		sc_pkcs15_id_t *object_id;

		if (type == SC_PKCS15_TYPE_PRKEY_RSA)
			object_id = &((sc_pkcs15_prkey_info_t *)objects[i]->data)->id;
		else
			object_id = &((sc_pkcs15_cert_info_t *)objects[i]->data)->id;
		if (sc_pkcs15_compare_id(object_id, &wanted)) {
			assert_null(found);
			found = objects[i];
		}
	}
	assert_non_null(found);
	return found;
}

/* EF 0001 <-> ID 01 <-> key ref 0x10 and EF 0002 <-> ID 02 <-> key ref 0x11,
 * with the certificate and the key sharing ID, label and the single PIN. */
static void
torture_certificate_key_mapping(void **state)
{
	struct fixture *f = *state;
	unsigned int i;

	assert_int_equal(sc_pkcs15emu_chipdocit_init_ex(f->p15, NULL), SC_SUCCESS);
	assert_true(sim.reads >= 2);
	for (i = 0; i < 2; i++) {
		sc_pkcs15_object_t *cert = object_by_id(f, SC_PKCS15_TYPE_CERT_X509, i + 1);
		sc_pkcs15_object_t *key = object_by_id(f, SC_PKCS15_TYPE_PRKEY_RSA, i + 1);
		sc_pkcs15_cert_info_t *ci = cert->data;
		sc_pkcs15_prkey_info_t *ki = key->data;

		assert_int_equal(ci->value.len, sizeof cert_ef[i]);
		assert_memory_equal(ci->value.value, cert_ef[i], sizeof cert_ef[i]);
		assert_int_equal(ki->key_reference, 0x10 + i);
		assert_true(sc_pkcs15_compare_id(&ci->id, &ki->id));
		assert_string_equal(key->label, cert->label);
		assert_int_equal(key->auth_id.len, 1);
		assert_int_equal(key->auth_id.value[0], 1);
	}
}

/* The driver implements signing only (raw RSA through PSO:DECIPHER on the
 * signature applet); it has no decryption operation for these keys, so no key
 * may advertise a decipher usage. */
static void
torture_no_unsupported_decipher_usage(void **state)
{
	struct fixture *f = *state;
	unsigned int i;

	assert_int_equal(sc_pkcs15emu_chipdocit_init_ex(f->p15, NULL), SC_SUCCESS);
	for (i = 0; i < 2; i++) {
		sc_pkcs15_object_t *key = object_by_id(f, SC_PKCS15_TYPE_PRKEY_RSA, i + 1);
		sc_pkcs15_prkey_info_t *ki = key->data;

		assert_true(ki->usage & (SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION));
		assert_false(ki->usage & (SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP));
	}
}

/*
 * Signing with either key must reach the driver's compute_signature with a
 * software-padded block, and never go through decipher. The driver registers
 * SC_ALGORITHM_NEED_USAGE, so a key with both sign and decipher usage is
 * signed through sc_pkcs15_decipher() instead.
 */
static void
check_sign(struct fixture *f, sc_pkcs15_object_t *key, unsigned long flags,
		const u8 *in, size_t inlen)
{
	sc_pkcs15_prkey_info_t *ki = key->data;
	size_t modlen = BYTES4BITS(ki->modulus_length);
	u8 out[1024];
	int r;

	assert_true(modlen <= sizeof out);
	sim.set_env_calls = sim.sign_calls = sim.decipher_calls = 0;
	sim.sign_len = 0;
	r = sc_pkcs15_compute_signature(f->p15, key, flags, in, inlen, out, sizeof out, NULL);
	assert_int_equal(sim.decipher_calls, 0);
	assert_int_equal(sim.sign_calls, 1);
	assert_int_equal(r, (int)modlen);
	assert_int_equal(sim.set_env_calls, 1);
	assert_int_equal(sim.env_operation, SC_SEC_OPERATION_SIGN);
	assert_int_equal(sim.env_key_ref, ki->key_reference);
	/* The card gets a full PKCS#1 type 1 block. */
	assert_int_equal(sim.sign_len, modlen);
	assert_int_equal(sim.sign_head[0], 0x00);
	assert_int_equal(sim.sign_head[1], 0x01);
}

static void
torture_sign_uses_compute_signature(void **state)
{
	struct fixture *f = *state;
	/* SHA-256 DigestInfo prefix followed by a dummy digest. */
	static const u8 digest_info[51] = {
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
			0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0x01};
	unsigned int i;

	assert_int_equal(sc_pkcs15emu_chipdocit_init_ex(f->p15, NULL), SC_SUCCESS);
	f->observed_ops = *f->driver_ops;
	f->observed_ops.set_security_env = sim_set_security_env;
	f->observed_ops.compute_signature = sim_compute_signature;
	f->observed_ops.decipher = sim_decipher;
	f->card.ops = &f->observed_ops;

	for (i = 0; i < 2; i++) {
		sc_pkcs15_object_t *key = object_by_id(f, SC_PKCS15_TYPE_PRKEY_RSA, i + 1);
		sc_pkcs15_prkey_info_t *ki = key->data;
		size_t modlen = BYTES4BITS(ki->modulus_length);
		sc_algorithm_info_t *alg = sc_card_find_rsa_alg(&f->card, ki->modulus_length);
		u8 block[512];

		assert_non_null(alg);
		assert_true(alg->flags & SC_ALGORITHM_NEED_USAGE);

		/* Flags used for CKM_SHA256_RSA_PKCS: OpenSC adds DigestInfo and padding. */
		check_sign(f, key, SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_HASH_SHA256,
				digest_info + 19, 32);
		/* Flags used for CKM_RSA_PKCS: the caller supplies the DigestInfo. */
		check_sign(f, key, SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_HASH_NONE,
				digest_info, sizeof digest_info);

		/* Flags used for CKM_RSA_X_509: the caller supplies the padded block. */
		assert_true(modlen <= sizeof block && modlen > sizeof digest_info + 11);
		block[0] = 0x00;
		block[1] = 0x01;
		memset(block + 2, 0xFF, modlen - sizeof digest_info - 3);
		block[modlen - sizeof digest_info - 1] = 0x00;
		memcpy(block + modlen - sizeof digest_info, digest_info, sizeof digest_info);
		check_sign(f, key, SC_ALGORITHM_RSA_RAW, block, modlen);
	}
}

/*
 * Usage, user consent and labels are static values of the emulator, not read
 * from the card: native descriptors and certificate roles are known to differ
 * between card personalizations. This test only records the current static
 * profile so that a change to it is deliberate; it does not assert that these
 * values match any particular card. The PKCS#11 layer maps user_consent >= 1
 * to CKA_ALWAYS_AUTHENTICATE.
 */
static void
torture_static_profile_values(void **state)
{
	struct fixture *f = *state;
	sc_pkcs15_object_t *key_10, *key_11;
	sc_pkcs15_prkey_info_t *info_10, *info_11;

	assert_int_equal(sc_pkcs15emu_chipdocit_init_ex(f->p15, NULL), SC_SUCCESS);
	key_10 = object_by_id(f, SC_PKCS15_TYPE_PRKEY_RSA, 1);
	key_11 = object_by_id(f, SC_PKCS15_TYPE_PRKEY_RSA, 2);
	info_10 = key_10->data;
	info_11 = key_11->data;

	assert_int_equal(info_10->usage, SC_PKCS15_PRKEY_USAGE_SIGN);
	assert_int_equal(key_10->user_consent, 0);
	assert_string_equal(key_10->label, "CNS");
	assert_int_equal(info_11->usage, SC_PKCS15_PRKEY_USAGE_NONREPUDIATION);
	assert_int_equal(key_11->user_consent, 1);
	assert_string_equal(key_11->label, "DS3");
}

static void
torture_other_card_rejected(void **state)
{
	struct fixture *f = *state;

	f->card.type = SC_CARD_TYPE_UNKNOWN;
	assert_int_equal(sc_pkcs15emu_chipdocit_init_ex(f->p15, NULL), SC_ERROR_WRONG_CARD);
	assert_int_equal(sim.transmits, 0);
	assert_null(f->p15->obj_list);
	f->card.type = SC_CARD_TYPE_CHIPDOC_IT;
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup_teardown(torture_certificate_key_mapping, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_no_unsupported_decipher_usage, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_sign_uses_compute_signature, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_static_profile_values, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_other_card_rejected, setup, teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
