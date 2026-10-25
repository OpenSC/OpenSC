/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "libopensc/internal.h"
#include "torture.h"

/* Use typed expectations with cmocka 2, while retaining 1.x support. */
#ifndef check_expected_int
#define check_expected_int(parameter) check_expected(parameter)
#endif
#ifndef check_expected_uint
#define check_expected_uint(parameter) check_expected(parameter)
#endif
#ifndef expect_int_value
#define expect_int_value(function, parameter, value) expect_value(function, parameter, value)
#endif
#ifndef expect_uint_value
#define expect_uint_value(function, parameter, value) expect_value(function, parameter, value)
#endif

/* Include the internal encoding selector as other padding unit tests do. */
#include "libopensc/padding.c"
/* Validate the complete synthetic extended APDU without sending it. */
static size_t
unexpected_reader_send_size(const sc_card_t *card)
{
	fail_msg("The APDU serializer test must never access a reader");
	return 0;
}
#define sc_get_max_send_size unexpected_reader_send_size
#include "libopensc/apdu.c"
#undef sc_get_max_send_size

static int select_calls;
static int select_result;
static int model_pin_verified;
static int enforce_model_auth;
static int
mock_select_aid(sc_card_t *card, const u8 *aid, size_t len,
		u8 *response, size_t *response_len)
{
	static const u8 expected[] = {
			0xa0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4b, 0x43, 0x53, 0x2d, 0x31, 0x35};
	assert_int_equal(len, sizeof(expected));
	assert_memory_equal(aid, expected, sizeof(expected));
	assert_null(response);
	assert_null(response_len);
	assert_true(card->lock_count > 0);
	select_calls++;
	return select_result;
}

static int file_select_calls;
static int child_file_type = SC_FILE_TYPE_WORKING_EF;
static int
mock_select_file(sc_card_t *card, const sc_path_t *path, sc_file_t **file_out)
{
	int path_type = path->type;
	size_t path_len = path->len;
	const u8 *value = path->value;
	int want_fci = (file_out != NULL);
	int result;

	file_select_calls++;
	if (path->type == SC_PATH_TYPE_DF_NAME)
		model_pin_verified = 0;
	check_expected_int(path_type);
	check_expected_uint(path_len);
	check_expected_ptr(value);
	check_expected_int(want_fci);
	result = mock_type(int);
	if (result == SC_SUCCESS && file_out != NULL &&
			(path->type == SC_PATH_TYPE_DF_NAME || child_file_type >= 0)) {
		*file_out = sc_file_new();
		assert_non_null(*file_out);
		(*file_out)->path = *path;
		(*file_out)->type = path->type == SC_PATH_TYPE_DF_NAME ? SC_FILE_TYPE_DF : child_file_type;
	}
	return result;
}

static struct sc_card_driver *
mock_iso_driver(void)
{
	static struct sc_card_driver driver;
	static struct sc_card_operations ops;
	const struct sc_card_driver *iso = sc_get_iso7816_driver();
	ops = *iso->ops;
	ops.select_file = mock_select_file;
	driver = *iso;
	driver.ops = &ops;
	return &driver;
}

struct expected_apdu {
	unsigned cla, ins, p1, p2;
	int cse;
	const u8 *data;
	size_t data_len, le;
	unsigned long required_flags, forbidden_flags;
	const u8 *response;
	size_t response_len;
	unsigned sw1, sw2;
	int result;
};
static struct expected_apdu next_apdu, following_apdu;
static int have_following_apdu;
static int transmit_calls;

static int
mock_transmit_apdu(sc_card_t *card, sc_apdu_t *apdu)
{
	if (apdu->ins == 0xca)
		assert_true(card->lock_count > 0);
	transmit_calls++;
	assert_int_equal(apdu->cla, next_apdu.cla);
	assert_int_equal(apdu->ins, next_apdu.ins);
	assert_int_equal(apdu->p1, next_apdu.p1);
	assert_int_equal(apdu->p2, next_apdu.p2);
	assert_int_equal(apdu->cse, next_apdu.cse);
	assert_int_equal(apdu->lc, next_apdu.data_len);
	assert_int_equal(apdu->datalen, next_apdu.data_len);
	assert_int_equal(apdu->le, next_apdu.le);
	if (next_apdu.data_len)
		assert_memory_equal(apdu->data, next_apdu.data, next_apdu.data_len);
	assert_int_equal(apdu->flags & next_apdu.required_flags, next_apdu.required_flags);
	assert_int_equal(apdu->flags & next_apdu.forbidden_flags, 0);
	if (apdu->cse == (SC_APDU_CASE_4_EXT)) {
		static const u8 header[] = {0x00, 0x2a, 0x80, 0x86, 0x00, 0x01, 0x00};
		u8 wire[265];
		/* Exercise OpenSC's real validator/serializer, not just the
		 * driver's logical APDU fields. The response remains bounded
		 * even though the applet requests extended Le=0000.
		 */
		assert_int_equal(apdu->resplen, 256);
		assert_int_equal(sc_check_apdu(card, apdu), SC_SUCCESS);
		assert_int_equal(sc_apdu_get_length(apdu, SC_PROTO_T1), sizeof(wire));
		assert_int_equal(sc_apdu2bytes(card->ctx, apdu, SC_PROTO_T1,
						 wire, sizeof(wire)),
				SC_SUCCESS);
		assert_memory_equal(wire, header, sizeof(header));
		assert_memory_equal(wire + sizeof(header), next_apdu.data, 256);
		assert_int_equal(wire[263], 0);
		assert_int_equal(wire[264], 0);
	}
	if (next_apdu.response_len) {
		assert_true(apdu->resplen >= next_apdu.response_len);
		memcpy(apdu->resp, next_apdu.response, next_apdu.response_len);
	}
	apdu->resplen = next_apdu.response_len;
	apdu->sw1 = next_apdu.sw1;
	apdu->sw2 = next_apdu.sw2;
	if (apdu->ins == 0x20 && apdu->sw1 == 0x90 && apdu->sw2 == 0)
		model_pin_verified = 1;
	if (enforce_model_auth && (apdu->ins == 0x22 || apdu->ins == 0x2a) && !model_pin_verified) {
		apdu->sw1 = 0x69;
		apdu->sw2 = 0x82;
	}
	int result = next_apdu.result;
	if (have_following_apdu) {
		next_apdu = following_apdu;
		have_following_apdu = 0;
	}
	return result;
}

static int
mock_check_sw(sc_card_t *card, unsigned sw1, unsigned sw2)
{
	if (sw1 == 0x90 && sw2 == 0)
		return SC_SUCCESS;
	if (sw1 == 0x69 && sw2 == 0x82)
		return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
	return SC_ERROR_CARD_CMD_FAILED;
}

static int reset_at_next_lock;
static int new_transaction_at_next_lock;
static int
mock_lock(sc_card_t *card)
{
	card->lock_count++;
	if (reset_at_next_lock) {
		reset_at_next_lock = 0;
		card->ops->card_reader_lock_obtained(card, 1);
	} else if (new_transaction_at_next_lock) {
		new_transaction_at_next_lock = 0;
		card->ops->card_reader_lock_obtained(card, 0);
	}
	return SC_SUCCESS;
}
static int
mock_unlock(sc_card_t *card)
{
	assert_true(card->lock_count > 0);
	card->lock_count--;
	return SC_SUCCESS;
}
#define sc_lock			    mock_lock
#define sc_unlock		    mock_unlock
#define sc_transmit_apdu	    mock_transmit_apdu
#define sc_check_sw		    mock_check_sw
#define sc_get_iso7816_driver	    mock_iso_driver
#define iso7816_select_aid	    mock_select_aid
#define sc_get_epki_research_driver sc_get_test_epki_research_driver
#include "libopensc/card-epki-research.c"
#undef sc_get_epki_research_driver
#undef iso7816_select_aid
#undef sc_get_iso7816_driver
#undef sc_transmit_apdu
#undef sc_check_sw
#undef sc_lock
#undef sc_unlock

static sc_card_t
observed_card(void)
{
	sc_card_t card = {0};
	card.atr.len = sizeof(epki_atr);
	memcpy(card.atr.value, epki_atr, sizeof(epki_atr));
	select_calls = 0;
	transmit_calls = 0;
	have_following_apdu = 0;
	file_select_calls = 0;
	child_file_type = SC_FILE_TYPE_WORKING_EF;
	select_result = SC_SUCCESS;
	model_pin_verified = 0;
	enforce_model_auth = 0;
	return card;
}

static void
deny_security_operations_without_io(void **state)
{
	sc_card_t card = observed_card();
	sc_context_t ctx = {0};
	sc_security_env_t env = {0};
	struct sc_pin_cmd_data pin = {0};
	u8 input[32] = {0}, output[256], args = 0;
	unsigned commands[] = {SC_PIN_CMD_VERIFY, SC_PIN_CMD_CHANGE,
			SC_PIN_CMD_UNBLOCK, SC_PIN_CMD_GET_INFO};
	size_t i;
	card.ctx = &ctx;
	card.ops = sc_get_test_epki_research_driver()->ops;
	for (i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
		pin.cmd = commands[i];
		assert_int_equal(sc_pin_cmd(&card, &pin), SC_ERROR_NOT_SUPPORTED);
	}
	assert_int_equal(sc_compute_signature(&card, input, sizeof(input), output, sizeof(output)), SC_ERROR_NOT_SUPPORTED);
	assert_int_equal(sc_decipher(&card, input, sizeof(input), output, sizeof(output)), SC_ERROR_NOT_SUPPORTED);
	assert_int_equal(sc_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	assert_int_equal(sc_card_ctl(&card, ~0UL, &args), SC_ERROR_NOT_SUPPORTED);
	assert_int_equal(select_calls, 0);
	assert_int_equal(file_select_calls, 0);
	assert_int_equal(transmit_calls, 0);
}

static void
expect_selection(int type, const u8 *value, size_t len, int fci, int result)
{
	expect_int_value(mock_select_file, path_type, type);
	expect_uint_value(mock_select_file, path_len, len);
	expect_memory(mock_select_file, value, value, len);
	expect_int_value(mock_select_file, want_fci, fci);
	will_return(mock_select_file, result);
}

static void
map_only_observed_application_paths(void **state)
{
	sc_card_t card = observed_card();
	sc_path_t path = {0};
	sc_file_t *file = NULL;
	static const u8 certificate_fid[] = {0x54, 0x01};

	sc_format_path("3F0050155401", &path);
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	expect_selection(SC_PATH_TYPE_FILE_ID, certificate_fid, sizeof(certificate_fid), 1, SC_SUCCESS);
	assert_int_equal(epki_select_file(&card, &path, &file), SC_SUCCESS);
	assert_non_null(file);
	sc_file_free(file);
	assert_int_equal(file_select_calls, 2);

	/* The same exact selection sequence is used without a returned file. */
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	expect_selection(SC_PATH_TYPE_FILE_ID, certificate_fid, sizeof(certificate_fid), 1, SC_SUCCESS);
	assert_int_equal(epki_select_file(&card, &path, NULL), SC_SUCCESS);

	sc_format_path("3F005015", &path);
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	assert_int_equal(epki_select_file(&card, &path, NULL), SC_SUCCESS);
	assert_int_equal(file_select_calls, 5);
}

static void
preserve_other_paths_and_selection_errors(void **state)
{
	sc_card_t card = observed_card();
	sc_path_t path = {0};
	const char *paths[] = {"3F005031", "3F0050165401", "3F00501554010001", "5401"};
	static const u8 certificate_fid[] = {0x54, 0x01};
	size_t i;

	for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		sc_format_path(paths[i], &path);
		expect_selection(path.type, path.value, path.len, 0, SC_ERROR_FILE_NOT_FOUND);
		assert_int_equal(epki_select_file(&card, &path, NULL), SC_ERROR_FILE_NOT_FOUND);
	}

	/* Explicit AIDs must not be replaced, even for the matching path. */
	sc_format_path("3F0050155401", &path);
	path.aid.len = 1;
	path.aid.value[0] = 0x01;
	expect_selection(path.type, path.value, path.len, 0, SC_ERROR_FILE_NOT_FOUND);
	assert_int_equal(epki_select_file(&card, &path, NULL), SC_ERROR_FILE_NOT_FOUND);
	path.aid.len = 0;

	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_ERROR_TRANSMIT_FAILED);
	assert_int_equal(epki_select_file(&card, &path, NULL), SC_ERROR_TRANSMIT_FAILED);

	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	expect_selection(SC_PATH_TYPE_FILE_ID, certificate_fid, sizeof(certificate_fid), 1, SC_ERROR_FILE_NOT_FOUND);
	assert_int_equal(epki_select_file(&card, &path, NULL), SC_ERROR_FILE_NOT_FOUND);
	assert_int_equal(epki_select_file(NULL, &path, NULL), SC_ERROR_INVALID_ARGUMENTS);
	assert_int_equal(epki_select_file(&card, NULL, NULL), SC_ERROR_INVALID_ARGUMENTS);
	assert_int_equal(file_select_calls, 8);
}

static void
only_public_read_callbacks_are_inherited(void **state)
{
	struct sc_card_operations *ops = sc_get_test_epki_research_driver()->ops;
	const struct sc_card_operations *iso = sc_get_iso7816_driver()->ops;
	assert_ptr_equal(ops->read_binary, iso->read_binary);
	assert_ptr_equal(ops->read_record, iso->read_record);
	assert_ptr_equal(ops->select_file, epki_select_file);
	assert_ptr_equal(ops->get_response, iso->get_response);
	assert_ptr_equal(ops->process_fci, iso->process_fci);
	assert_null(ops->write_binary);
	assert_null(ops->update_binary);
	assert_null(ops->erase_binary);
	assert_null(ops->write_record);
	assert_null(ops->append_record);
	assert_null(ops->update_record);
	assert_null(ops->create_file);
	assert_null(ops->delete_file);
	assert_null(ops->delete_record);
	assert_null(ops->verify);
	assert_null(ops->change_reference_data);
	assert_null(ops->reset_retry_counter);
	assert_null(ops->restore_security_env);
	assert_null(ops->put_data);
	assert_null(ops->get_data);
	assert_null(ops->get_challenge);
	assert_ptr_equal(ops->logout, epki_logout);
	assert_null(ops->wrap);
	assert_null(ops->unwrap);
	assert_null(ops->encrypt_sym);
	assert_null(ops->decrypt_sym);
}

static void
expect_version(const u8 *version, size_t len)
{
	next_apdu = (struct expected_apdu){0x80, 0xca, 0x01, 0x82,
			SC_APDU_CASE_2_SHORT, NULL, 0, 2,
			SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP,
			SC_APDU_FLAGS_CHAINING, version, len, 0x90, 0, SC_SUCCESS};
}

static void
set_detection_config(sc_card_t *card, sc_context_t *ctx, const char *config)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->conf = scconf_new(NULL);
	assert_non_null(ctx->conf);
	assert_int_equal(scconf_parse_string(ctx->conf, config), 1);
	ctx->conf_blocks[0] = ctx->conf->root;
	card->ctx = ctx;
}

static void
no_implicit_profile_probe(void **state)
{
	static const char *configs[] = {
			"card_driver epki-research { enable_local_signing = true; }",
			"card_driver epki-research { enable_profile = false; enable_local_signing = true; }",
			"card_driver epki-research { enable_profile = false; }"};
	sc_card_t card = observed_card();
	sc_context_t ctx;
	size_t i;
	assert_int_equal(epki_match_card(NULL), 0);
	assert_int_equal(epki_init(NULL), SC_ERROR_INVALID_CARD);
	assert_int_equal(epki_match_card(&card), 0);
	assert_int_equal(epki_init(&card), SC_ERROR_INVALID_CARD);
	for (i = 0; i < sizeof(configs) / sizeof(configs[0]); i++) {
		set_detection_config(&card, &ctx, configs[i]);
		assert_int_equal(epki_match_card(&card), 0);
		/* OpenSC initializes forced drivers even after failed matching. */
		assert_int_equal(epki_init(&card), SC_ERROR_INVALID_CARD);
		assert_null(card.drv_data);
		scconf_free(ctx.conf);
	}
	assert_int_equal(select_calls, 0);
	assert_int_equal(transmit_calls, 0);
	assert_int_equal(card.lock_count, 0);
}

static void
enabled_profile_still_requires_observed_atr(void **state)
{
	sc_card_t card = observed_card();
	sc_context_t ctx;
	set_detection_config(&card, &ctx,
			"card_driver epki-research { enable_profile = true; }");
	card.atr.value[14] ^= 1;
	assert_int_equal(epki_match_card(&card), 0);
	assert_int_equal(epki_init(&card), SC_ERROR_INVALID_CARD);
	card.atr.value[14] ^= 1;
	card.atr.len--;
	assert_int_equal(epki_match_card(&card), 0);
	assert_int_equal(epki_init(&card), SC_ERROR_INVALID_CARD);
	assert_int_equal(select_calls, 0);
	assert_int_equal(transmit_calls, 0);
	scconf_free(ctx.conf);
}

static void
read_only_profile_rejects_unverified_versions(void **state)
{
	static const u8 versions[][2] = {
			{0x02, 0x81},
			{0x02, 0x7e},
			{0x03, 0x82}
	    };
	sc_card_t card = observed_card();
	sc_context_t ctx;
	size_t i;
	set_detection_config(&card, &ctx,
			"card_driver epki-research { enable_profile = true; }");
	for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
		expect_version(versions[i], sizeof(versions[i]));
		assert_int_equal(epki_match_card(&card), 0);
		assert_int_equal(epki_init(&card), SC_ERROR_INVALID_CARD);
		assert_null(card.drv_data);
		assert_int_equal(card.algorithm_count, 0);
		assert_int_equal(card.lock_count, 0);
	}
	assert_int_equal(select_calls, 6);
	assert_int_equal(transmit_calls, 6);
	scconf_free(ctx.conf);
}

static void
read_only_profile_requires_complete_successful_probe(void **state)
{
	static const u8 good[] = {0x02, 0x82};
	sc_card_t card = observed_card();
	sc_context_t ctx;
	set_detection_config(&card, &ctx,
			"card_driver epki-research { enable_profile = true; }");
	expect_version(good, 0);
	assert_int_equal(epki_init(&card), SC_ERROR_INVALID_CARD);
	expect_version(good, 1);
	assert_int_equal(epki_init(&card), SC_ERROR_INVALID_CARD);
	expect_version(good, sizeof(good));
	next_apdu.sw1 = 0x6a;
	next_apdu.sw2 = 0x88;
	assert_int_equal(epki_init(&card), SC_ERROR_INVALID_CARD);
	expect_version(good, sizeof(good));
	next_apdu.result = SC_ERROR_TRANSMIT_FAILED;
	assert_int_equal(epki_init(&card), SC_ERROR_INVALID_CARD);
	assert_null(card.drv_data);
	assert_int_equal(card.algorithm_count, 0);
	assert_int_equal(card.lock_count, 0);
	scconf_free(ctx.conf);
}

static void
explicit_read_only_profile_is_narrow(void **state)
{
	static const u8 good[] = {0x02, 0x82};
	sc_card_t card = observed_card();
	sc_context_t ctx;
	set_detection_config(&card, &ctx,
			"card_driver epki-research { enable_profile = true; }");
	expect_version(good, sizeof(good));
	assert_int_equal(epki_match_card(&card), 1);
	assert_int_equal(epki_init(&card), SC_SUCCESS);
	assert_int_equal(card.type, SC_CARD_TYPE_EPKI_RESEARCH);
	assert_int_equal(card.algorithm_count, 0);
	assert_null(card.algorithms);
	assert_false(card.caps & SC_CARD_CAP_APDU_EXT);
	assert_int_equal(select_calls, 2);
	assert_int_equal(transmit_calls, 2);
	assert_int_equal(card.lock_count, 0);
	epki_finish(&card);
	scconf_free(ctx.conf);
}

static void
enabled_profile_requires_aid_selection(void **state)
{
	sc_card_t card = observed_card();
	sc_context_t ctx;
	set_detection_config(&card, &ctx,
			"card_driver epki-research { enable_profile = true; }");
	select_result = SC_ERROR_FILE_NOT_FOUND;
	assert_int_equal(epki_match_card(&card), 0);
	assert_int_equal(epki_init(&card), SC_ERROR_INVALID_CARD);
	select_result = SC_ERROR_TRANSMIT_FAILED;
	assert_int_equal(epki_init(&card), SC_ERROR_INVALID_CARD);
	assert_int_equal(select_calls, 3);
	assert_int_equal(transmit_calls, 0);
	assert_int_equal(card.lock_count, 0);
	scconf_free(ctx.conf);
}

static void
enable_signing_for_explicit_matching_profile(void **state)
{
	sc_card_t card = observed_card();
	sc_context_t ctx = {0};
	static const u8 good[] = {0x02, 0x82};
	card.ctx = &ctx;
	ctx.conf = scconf_new(NULL);
	assert_non_null(ctx.conf);
	assert_int_equal(scconf_parse_string(ctx.conf,
					 "card_driver epki-research { enable_profile = true; enable_local_signing = true; }"),
			1);
	ctx.conf_blocks[0] = ctx.conf->root;
	expect_version(good, sizeof(good));
	assert_int_equal(epki_init(&card), SC_SUCCESS);
	assert_non_null(card.drv_data);
	assert_true(((struct epki_data *)card.drv_data)->profile_checked);
	assert_int_equal(card.algorithm_count, 1);
	assert_int_equal(card.algorithms[0].key_length, 2048);
	assert_int_equal(card.algorithms[0].flags,
			SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_HASH_NONE);
	assert_false(card.caps & SC_CARD_CAP_ISO7816_PIN_INFO);
	assert_false(card.caps & SC_CARD_CAP_APDU_EXT);
	assert_false(((struct epki_data *)card.drv_data)->raw_rsa_enabled);
	assert_int_equal(transmit_calls, 1);
	epki_finish(&card);
	free(card.algorithms);
	scconf_free(ctx.conf);
}

static void
prepare_enabled(sc_card_t *card, sc_context_t *ctx, struct epki_data *priv)
{
	*card = observed_card();
	memset(ctx, 0, sizeof(*ctx));
	memset(priv, 0, sizeof(*priv));
	priv->signing_enabled = 1;
	priv->security_operation = SC_SEC_OPERATION_SIGN;
	priv->profile_checked = 1;
	priv->app_selected = 1;
	card->ctx = ctx;
	card->drv_data = priv;
}

static struct sc_pin_cmd_data
valid_pin_request(void)
{
	static const u8 synthetic_pin[] = {'a', 'b', 'c', 'd'};
	struct sc_pin_cmd_data pin = {0};
	pin.cmd = SC_PIN_CMD_VERIFY;
	pin.pin_type = SC_AC_CHV;
	pin.pin_reference = 1;
	pin.pin1.data = synthetic_pin;
	pin.pin1.len = sizeof(synthetic_pin);
	pin.pin1.encoding = SC_PIN_ENCODING_ASCII;
	return pin;
}

static void
expect_pin(unsigned sw1, unsigned sw2)
{
	static const u8 padded[] = {'a', 'b', 'c', 'd', 0xff, 0xff, 0xff, 0xff};
	next_apdu = (struct expected_apdu){0, 0x20, 0, 1,
			SC_APDU_CASE_3_SHORT, padded, sizeof(padded), 0,
			SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP,
			SC_APDU_FLAGS_CHAINING, NULL, 0, sw1, sw2, SC_SUCCESS};
}

static void
verify_once_per_request_and_preserve_retry_count(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	struct sc_pin_cmd_data pin = valid_pin_request();
	prepare_enabled(&card, &ctx, &priv);
	expect_pin(0x63, 0xc2);
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_ERROR_PIN_CODE_INCORRECT);
	assert_int_equal(pin.pin1.tries_left, 2);
	assert_false(priv.pin_verified);
	assert_int_equal(transmit_calls, 1); /* Never retry inside a request. */
	expect_pin(0x90, 0);
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_SUCCESS);
	assert_int_equal(pin.pin1.tries_left, -1);
	assert_int_equal(pin.pin1.logged_in, SC_PIN_STATE_LOGGED_IN);
	assert_int_equal(transmit_calls, 2); /* A new explicit request is allowed. */
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_SUCCESS);
	assert_int_equal(transmit_calls, 3); /* Re-login need not recreate the card. */

	prepare_enabled(&card, &ctx, &priv);
	expect_pin(0x90, 0);
	next_apdu.result = SC_ERROR_TRANSMIT_FAILED;
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_ERROR_TRANSMIT_FAILED);
	assert_false(priv.pin_verified);
	assert_false(priv.app_selected);
	assert_int_equal(transmit_calls, 1);
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	expect_pin(0x90, 0);
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_SUCCESS);
	assert_true(priv.pin_verified);
	assert_int_equal(transmit_calls, 2);
	epki_clear_selection(&priv);
}

static void
reject_unsafe_pin_requests_before_io(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	struct sc_pin_cmd_data pin;
	unsigned commands[] = {SC_PIN_CMD_CHANGE, SC_PIN_CMD_UNBLOCK,
			SC_PIN_CMD_GET_INFO, SC_PIN_CMD_GET_SESSION_PIN};
	size_t i;
	prepare_enabled(&card, &ctx, &priv);
	for (i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
		pin = valid_pin_request();
		pin.cmd = commands[i];
		assert_int_equal(epki_pin_cmd(&card, &pin), SC_ERROR_NOT_SUPPORTED);
	}
	pin = valid_pin_request();
	pin.pin_reference = 2;
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_ERROR_NOT_SUPPORTED);
	pin = valid_pin_request();
	pin.pin_type = SC_AC_CONTEXT_SPECIFIC;
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_ERROR_NOT_SUPPORTED);
	pin = valid_pin_request();
	pin.flags = SC_PIN_CMD_USE_PINPAD;
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_ERROR_NOT_SUPPORTED);
	pin = valid_pin_request();
	pin.pin1.len = 0;
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_ERROR_INVALID_ARGUMENTS);
	pin.pin1.len = 3;
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_ERROR_INVALID_ARGUMENTS);
	pin.pin1.len = 9;
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_ERROR_INVALID_ARGUMENTS);
	pin = valid_pin_request();
	pin.pin1.data = NULL;
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_ERROR_INVALID_ARGUMENTS);
	pin = valid_pin_request();
	pin.pin1.encoding = SC_PIN_ENCODING_BCD;
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_ERROR_INVALID_ARGUMENTS);
	pin = valid_pin_request();
	ctx.debug = 1;
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_ERROR_NOT_ALLOWED);
	assert_int_equal(transmit_calls, 0);
}

static sc_security_env_t
valid_security_env(void)
{
	sc_security_env_t env = {0};
	env.flags = SC_SEC_ENV_ALG_PRESENT | SC_SEC_ENV_KEY_REF_PRESENT;
	env.operation = SC_SEC_OPERATION_SIGN;
	env.algorithm = SC_ALGORITHM_RSA;
	env.algorithm_flags = SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_HASH_NONE;
	env.key_size_bits = 2048;
	env.key_ref_len = 1;
	env.key_ref[0] = 0x42;
	return env;
}

static void
expect_mse(void)
{
	static const u8 mse[] = {0x84, 0x01, 0x42, 0x80, 0x01, 0x00};
	next_apdu = (struct expected_apdu){0, 0x22, 0x41, 0xb6,
			SC_APDU_CASE_3_SHORT, mse, sizeof(mse), 0,
			SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP,
			SC_APDU_FLAGS_CHAINING, NULL, 0, 0x90, 0, SC_SUCCESS};
}

static void
only_verified_signing_environment(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	sc_security_env_t env;
	prepare_enabled(&card, &ctx, &priv);
	env = valid_security_env();
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	priv.pin_verified = 1;
	env.key_ref[0] = 0;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	env = valid_security_env();
	env.key_ref_len = 0;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	env = valid_security_env();
	env.key_ref_len = 2;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	env = valid_security_env();
	env.algorithm_flags = SC_ALGORITHM_RSA_PAD_PSS | SC_ALGORITHM_RSA_HASH_SHA256;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	env = valid_security_env();
	env.operation = SC_SEC_OPERATION_DECIPHER;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	env = valid_security_env();
	env.key_size_bits = 1024;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	env = valid_security_env();
	env.flags |= SC_SEC_ENV_ALG_REF_PRESENT;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	env = valid_security_env();
	env.params[0].param_type = SC_SEC_ENV_PARAM_IV;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	assert_int_equal(transmit_calls, 0);
	env = valid_security_env();
	env.flags |= SC_SEC_ENV_FILE_REF_PRESENT;
	env.file_ref.type = SC_PATH_TYPE_FILE_ID;
	env.file_ref.len = 2;
	env.file_ref.value[0] = 0x50;
	env.file_ref.value[1] = 0x16;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	env.file_ref.value[1] = 0x15;
	expect_mse();
	next_apdu.sw1 = 0x69;
	next_apdu.sw2 = 0x82;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	assert_false(priv.security_env_valid);
	assert_false(priv.pin_verified);
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	assert_int_equal(transmit_calls, 1);
	/* An explicit authentication request recovers without reconnecting. */
	struct sc_pin_cmd_data pin = valid_pin_request();
	expect_pin(0x90, 0);
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_SUCCESS);
	expect_mse();
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_SUCCESS);
	assert_true(priv.security_env_valid);
}

static void
failed_mse_allows_a_new_authenticated_operation(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	sc_security_env_t env = valid_security_env();
	struct sc_pin_cmd_data pin = valid_pin_request();
	prepare_enabled(&card, &ctx, &priv);
	priv.pin_verified = 1;
	expect_mse();
	next_apdu.result = SC_ERROR_TRANSMIT_FAILED;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_TRANSMIT_FAILED);
	assert_int_equal(transmit_calls, 1); /* The failed command was not retried. */
	assert_false(priv.pin_verified);
	assert_false(priv.app_selected);
	assert_false(priv.security_env_valid);
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	assert_int_equal(transmit_calls, 1);
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	expect_pin(0x90, 0);
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_SUCCESS);
	expect_mse();
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_SUCCESS);
	assert_true(priv.security_env_valid);
	assert_int_equal(transmit_calls, 3);
	epki_clear_selection(&priv);
}

static void
selected_pkcs15_key_reference_is_preserved(void **state)
{
	const u8 references[] = {1, 0x41, 0x42, 0x46, 0xff};
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	sc_security_env_t env = valid_security_env();
	u8 mse[] = {0x84, 0x01, 0, 0x80, 0x01, 0x00};
	size_t i;

	for (i = 0; i < sizeof(references); i++) {
		prepare_enabled(&card, &ctx, &priv);
		priv.pin_verified = 1;
		env.key_ref[0] = mse[2] = references[i];
		expect_mse();
		next_apdu.data = mse;
		assert_int_equal(epki_set_security_env(&card, &env, 0), SC_SUCCESS);
		assert_true(priv.security_env_valid);
		assert_false(priv.raw_signature);
		assert_int_equal(transmit_calls, 1);
	}
}

static void
raw_rsa_requires_both_explicit_options(void **state)
{
	static const u8 good[] = {0x02, 0x82};
	const char *configs[] = {
			"card_driver epki-research { enable_profile = true; enable_raw_rsa_signing = true; }",
			"card_driver epki-research { enable_profile = true; enable_local_signing = true; enable_raw_rsa_signing = false; }",
			"card_driver epki-research { enable_profile = true; enable_local_signing = true; enable_raw_rsa_signing = true; }"};
	size_t i;

	for (i = 0; i < sizeof(configs) / sizeof(configs[0]); i++) {
		sc_card_t card = observed_card();
		sc_context_t ctx = {0};
		card.ctx = &ctx;
		ctx.conf = scconf_new(NULL);
		assert_non_null(ctx.conf);
		assert_int_equal(scconf_parse_string(ctx.conf, configs[i]), 1);
		ctx.conf_blocks[0] = ctx.conf->root;
		expect_version(good, sizeof(good));
		assert_int_equal(epki_init(&card), SC_SUCCESS);
		assert_int_equal(transmit_calls, 1); /* Read-only mode also checks the profile. */
		assert_int_equal(card.algorithm_count, i ? 1 : 0);
		if (i) {
			assert_int_equal(!!(card.algorithms[0].flags & SC_ALGORITHM_RSA_RAW), i == 2);
			assert_false(card.algorithms[0].flags & SC_ALGORITHM_RSA_PAD_PSS);
			assert_int_equal(!!(card.caps & SC_CARD_CAP_APDU_EXT), i == 2);
			if (i == 2) {
				assert_int_equal(card.max_send_size, 256);
				assert_int_equal(card.max_recv_size, 256);
			}
			epki_finish(&card);
			free(card.algorithms);
		} else {
			assert_null(card.drv_data);
			assert_false(card.caps & SC_CARD_CAP_APDU_EXT);
		}
		scconf_free(ctx.conf);
	}
}

static void
prepare_raw(sc_card_t *card, sc_context_t *ctx, struct epki_data *priv)
{
	prepare_enabled(card, ctx, priv);
	priv->raw_rsa_enabled = 1;
	card->caps |= SC_CARD_CAP_APDU_EXT;
	card->max_send_size = card->max_recv_size = 256;
}

static void
raw_rsa_remains_sign_only_and_requires_authentication(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	sc_security_env_t env = valid_security_env();
	u8 encoded[256] = {0}, out[256];

	prepare_enabled(&card, &ctx, &priv);
	priv.pin_verified = 1;
	env.algorithm_flags = SC_ALGORITHM_RSA_PAD_NONE;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	assert_false(priv.raw_signature);
	assert_int_equal(transmit_calls, 0);
	prepare_raw(&card, &ctx, &priv);
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	priv.pin_verified = 1;
	env.operation = SC_SEC_OPERATION_DECIPHER;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	card.ops = sc_get_test_epki_research_driver()->ops;
	assert_int_equal(sc_decipher(&card, encoded, sizeof(encoded), out, sizeof(out)),
			SC_ERROR_NOT_SUPPORTED);
	env.operation = SC_SEC_OPERATION_SIGN;
	env.algorithm_flags |= SC_ALGORITHM_RSA_HASH_NONE;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	assert_int_equal(transmit_calls, 0);
}

static void
raw_rsa_uses_exact_extended_framing_and_bounded_response(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	sc_security_env_t env = valid_security_env();
	u8 encoded[256], signature[256], out[256];
	size_t i;

	prepare_raw(&card, &ctx, &priv);
	for (i = 0; i < sizeof(encoded); i++)
		encoded[i] = (u8)i;
	memset(signature, 0x5a, sizeof(signature));
	priv.raw_signature = 1;
	assert_int_equal(epki_compute_signature(&card, encoded, sizeof(encoded), out, sizeof(out)),
			SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	priv.pin_verified = 1;
	assert_int_equal(epki_compute_signature(&card, encoded, sizeof(encoded), out, sizeof(out)),
			SC_ERROR_NOT_ALLOWED);
	env.algorithm_flags = SC_ALGORITHM_RSA_PAD_NONE;
	expect_mse();
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_SUCCESS);
	assert_true(priv.raw_signature);
	assert_int_equal(epki_compute_signature(&card, encoded, 255, out, sizeof(out)),
			SC_ERROR_INVALID_ARGUMENTS);
	assert_int_equal(epki_compute_signature(&card, encoded, 257, out, sizeof(out)),
			SC_ERROR_INVALID_ARGUMENTS);
	assert_int_equal(epki_compute_signature(&card, encoded, sizeof(encoded), out, 255),
			SC_ERROR_BUFFER_TOO_SMALL);
	assert_int_equal(transmit_calls, 1);
	next_apdu = (struct expected_apdu){0, 0x2a, 0x80, 0x86,
			SC_APDU_CASE_4_EXT, encoded, sizeof(encoded), 65536,
			SC_APDU_FLAGS_NO_RETRY_WL, SC_APDU_FLAGS_CHAINING | SC_APDU_FLAGS_NO_GET_RESP,
			signature, sizeof(signature), 0x90, 0, SC_SUCCESS};
	assert_int_equal(epki_compute_signature(&card, encoded, sizeof(encoded), out, sizeof(out)), 256);
	assert_memory_equal(out, signature, sizeof(out));
	assert_false(priv.security_env_valid);
	assert_int_equal(epki_compute_signature(&card, encoded, sizeof(encoded), out, sizeof(out)),
			SC_ERROR_NOT_ALLOWED);
	assert_int_equal(transmit_calls, 2);
}

static void
decryption_requires_its_own_opt_in(void **state)
{
	static const u8 good[] = {0x02, 0x82};
	sc_card_t card = observed_card();
	sc_context_t ctx = {0};
	sc_security_env_t env = valid_security_env();
	struct epki_data *priv;
	u8 input[256] = {0}, output[256];

	set_detection_config(&card, &ctx,
			"card_driver epki-research { enable_profile = true; enable_local_decryption = true; }");
	expect_version(good, sizeof(good));
	assert_int_equal(epki_init(&card), SC_SUCCESS);
	priv = card.drv_data;
	assert_non_null(priv);
	assert_true(priv->decryption_enabled);
	assert_false(priv->signing_enabled);
	assert_false(priv->raw_rsa_enabled);
	assert_int_equal(card.algorithm_count, 1);
	assert_int_equal(card.algorithms[0].flags, SC_ALGORITHM_RSA_RAW);
	assert_true(card.caps & SC_CARD_CAP_APDU_EXT);
	assert_int_equal(card.max_send_size, 256);
	assert_int_equal(card.max_recv_size, 256);
	priv->pin_verified = 1;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	assert_int_equal(epki_compute_signature(&card, input, sizeof(input), output, sizeof(output)),
			SC_ERROR_NOT_SUPPORTED);
	env.operation = SC_SEC_OPERATION_DECIPHER;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	env.algorithm_flags = SC_ALGORITHM_RSA_PAD_NONE;
	env.key_size_bits = 1024;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_NOT_SUPPORTED);
	assert_int_equal(transmit_calls, 1);
	epki_finish(&card);
	free(card.algorithms);
	scconf_free(ctx.conf);
}

static void
decryption_uses_a_distinct_environment_and_raw_framing(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	sc_security_env_t env = valid_security_env();
	u8 ciphertext[256] = {1}, block[256] = {2}, output[256];
	prepare_raw(&card, &ctx, &priv);
	priv.decryption_enabled = priv.pin_verified = 1;
	env.algorithm_flags = SC_ALGORITHM_RSA_PAD_NONE;
	expect_mse();
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_SUCCESS);
	assert_int_equal(epki_decipher(&card, ciphertext, sizeof(ciphertext), output, sizeof(output)),
			SC_ERROR_NOT_ALLOWED);
	env.operation = SC_SEC_OPERATION_DECIPHER;
	expect_mse();
	next_apdu.p2 = 0xb8;
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_SUCCESS);
	assert_int_equal(epki_compute_signature(&card, ciphertext, sizeof(ciphertext), output, sizeof(output)),
			SC_ERROR_NOT_ALLOWED);
	assert_int_equal(epki_decipher(&card, ciphertext, 255, output, sizeof(output)), SC_ERROR_INVALID_ARGUMENTS);
	assert_int_equal(epki_decipher(&card, ciphertext, 257, output, sizeof(output)), SC_ERROR_INVALID_ARGUMENTS);
	assert_int_equal(epki_decipher(&card, ciphertext, sizeof(ciphertext), output, 255), SC_ERROR_BUFFER_TOO_SMALL);
	ctx.debug = 1;
	assert_int_equal(epki_decipher(&card, ciphertext, sizeof(ciphertext), output, sizeof(output)), SC_ERROR_NOT_ALLOWED);
	ctx.debug = 0;
	assert_int_equal(transmit_calls, 2);
	next_apdu = (struct expected_apdu){0, 0x2a, 0x80, 0x86,
			SC_APDU_CASE_4_EXT, ciphertext, sizeof(ciphertext), 65536,
			SC_APDU_FLAGS_NO_RETRY_WL, SC_APDU_FLAGS_CHAINING | SC_APDU_FLAGS_NO_GET_RESP,
			block, sizeof(block), 0x90, 0, SC_SUCCESS};
	assert_int_equal(epki_decipher(&card, ciphertext, sizeof(ciphertext), output, sizeof(output)), 256);
	assert_memory_equal(output, block, sizeof(output));
	assert_false(priv.security_env_valid);
	assert_int_equal(epki_decipher(&card, ciphertext, sizeof(ciphertext), output, sizeof(output)), SC_ERROR_NOT_ALLOWED);
	assert_int_equal(transmit_calls, 3);
}

static void
decryption_errors_do_not_release_output_or_retry(void **state)
{
	const int errors[] = {SC_ERROR_TRANSMIT_FAILED, SC_ERROR_CARD_CMD_FAILED,
			SC_ERROR_UNKNOWN_DATA_RECEIVED, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED};
	u8 ciphertext[256] = {1}, block[256] = {2}, output[256], untouched[256];
	size_t i;
	memset(untouched, 0xa5, sizeof(untouched));
	for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		sc_card_t card;
		sc_context_t ctx;
		struct epki_data priv;
		prepare_raw(&card, &ctx, &priv);
		priv.decryption_enabled = priv.pin_verified = priv.security_env_valid = 1;
		priv.security_operation = SC_SEC_OPERATION_DECIPHER;
		memcpy(output, untouched, sizeof(output));
		next_apdu = (struct expected_apdu){0, 0x2a, 0x80, 0x86,
				SC_APDU_CASE_4_EXT, ciphertext, sizeof(ciphertext), 65536,
				SC_APDU_FLAGS_NO_RETRY_WL, SC_APDU_FLAGS_CHAINING | SC_APDU_FLAGS_NO_GET_RESP,
				block, sizeof(block), 0x90, 0, SC_SUCCESS};
		if (i == 0)
			next_apdu.result = SC_ERROR_TRANSMIT_FAILED;
		else if (i == 1)
			next_apdu.sw1 = 0x6f;
		else if (i == 2)
			next_apdu.response_len = 255;
		else {
			next_apdu.sw1 = 0x69;
			next_apdu.sw2 = 0x82;
		}
		assert_int_equal(epki_decipher(&card, ciphertext, sizeof(ciphertext), output, sizeof(output)), errors[i]);
		assert_false(priv.security_env_valid);
		assert_memory_equal(output, untouched, sizeof(output));
		assert_true(epki_decipher(&card, ciphertext, sizeof(ciphertext), output, sizeof(output)) < 0);
		assert_int_equal(transmit_calls, 1);
		if (i == 0 || i == 3)
			assert_false(priv.pin_verified);
	}
}

static void
decryption_cannot_reuse_authentication_after_unlock_or_reset(void **state)
{
	u8 ciphertext[256] = {1}, output[256];
	int reset;
	for (reset = 0; reset <= 1; reset++) {
		sc_card_t card;
		sc_context_t ctx;
		struct epki_data priv;
		prepare_raw(&card, &ctx, &priv);
		card.ops = sc_get_test_epki_research_driver()->ops;
		priv.decryption_enabled = priv.pin_verified = priv.security_env_valid = 1;
		priv.security_operation = SC_SEC_OPERATION_DECIPHER;
		if (reset)
			reset_at_next_lock = 1;
		else
			new_transaction_at_next_lock = 1;
		assert_int_equal(epki_decipher(&card, ciphertext, sizeof(ciphertext), output, sizeof(output)),
				SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
		assert_int_equal(transmit_calls, 0);
		assert_false(priv.pin_verified);
		assert_false(priv.security_env_valid);
	}
}

static void
raw_rsa_failure_consumes_current_operation(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	sc_security_env_t env = valid_security_env();
	u8 encoded[256] = {0}, signature[256] = {0}, out[256];
	const int errors[] = {SC_ERROR_TRANSMIT_FAILED, SC_ERROR_CARD_CMD_FAILED,
			SC_ERROR_UNKNOWN_DATA_RECEIVED};
	size_t i;

	env.algorithm_flags = SC_ALGORITHM_RSA_PAD_NONE;
	for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		prepare_raw(&card, &ctx, &priv);
		priv.pin_verified = priv.security_env_valid = priv.raw_signature = 1;
		memset(out, 0xa5, sizeof(out));
		next_apdu = (struct expected_apdu){0, 0x2a, 0x80, 0x86,
				SC_APDU_CASE_4_EXT, encoded, sizeof(encoded), 65536,
				SC_APDU_FLAGS_NO_RETRY_WL, SC_APDU_FLAGS_CHAINING | SC_APDU_FLAGS_NO_GET_RESP,
				signature, sizeof(signature), 0x90, 0, SC_SUCCESS};
		if (i == 0)
			next_apdu.result = SC_ERROR_TRANSMIT_FAILED;
		else if (i == 1)
			next_apdu.sw1 = 0x6f;
		else
			next_apdu.response_len = 255;
		assert_int_equal(epki_compute_signature(&card, encoded, sizeof(encoded), out, sizeof(out)),
				errors[i]);
		assert_false(priv.security_env_valid);
		assert_int_equal(out[0], 0xa5);
		/* A consumed operation cannot send another PSO. A transport
		 * failure also invalidates the raw algorithm selection. */
		assert_true(epki_compute_signature(&card, encoded, sizeof(encoded), out, sizeof(out)) < 0);
		assert_int_equal(transmit_calls, 1);
		if (i == 0) {
			struct sc_pin_cmd_data pin = valid_pin_request();
			expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
			expect_pin(0x90, 0);
			assert_int_equal(epki_pin_cmd(&card, &pin), SC_SUCCESS);
		}
		expect_mse();
		assert_int_equal(epki_set_security_env(&card, &env, 0), SC_SUCCESS);
		epki_clear_selection(&priv);
	}
}

static void
sign_digest_info_once_and_validate_response(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	u8 digest_info[51] = {0x30, 0x31, 0x30, 0x0d}, signature[256], out[256];
	prepare_enabled(&card, &ctx, &priv);
	memset(signature, 0x5a, sizeof(signature));
	assert_int_equal(epki_compute_signature(&card, digest_info, sizeof(digest_info), out, sizeof(out)),
			SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	priv.pin_verified = priv.security_env_valid = 1;
	assert_int_equal(epki_compute_signature(&card, digest_info, sizeof(digest_info), out, 255), SC_ERROR_BUFFER_TOO_SMALL);
	assert_int_equal(epki_compute_signature(&card, digest_info, 246, out, sizeof(out)), SC_ERROR_INVALID_ARGUMENTS);
	assert_int_equal(transmit_calls, 0);
	next_apdu = (struct expected_apdu){0, 0x2a, 0x9e, 0x9a,
			SC_APDU_CASE_4_SHORT, digest_info, sizeof(digest_info), 256,
			SC_APDU_FLAGS_NO_RETRY_WL, SC_APDU_FLAGS_CHAINING | SC_APDU_FLAGS_NO_GET_RESP,
			signature, sizeof(signature), 0x90, 0, SC_SUCCESS};
	assert_int_equal(epki_compute_signature(&card, digest_info, sizeof(digest_info), out, sizeof(out)), 256);
	assert_memory_equal(out, signature, sizeof(out));
	assert_int_equal(epki_compute_signature(&card, digest_info, sizeof(digest_info), out, sizeof(out)),
			SC_ERROR_NOT_ALLOWED);
	assert_int_equal(transmit_calls, 1);

	prepare_enabled(&card, &ctx, &priv);
	priv.pin_verified = priv.security_env_valid = 1;
	next_apdu.response_len = 255;
	memset(out, 0, sizeof(out));
	assert_int_equal(epki_compute_signature(&card, digest_info, sizeof(digest_info), out, sizeof(out)),
			SC_ERROR_UNKNOWN_DATA_RECEIVED);
	assert_int_equal(out[0], 0);
}

static void
repeated_operations_do_not_exhaust_driver(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	sc_security_env_t env = valid_security_env();
	struct sc_pin_cmd_data pin = valid_pin_request();
	u8 digest_info[51] = {0x30, 0x31}, signature[256] = {0x5a}, out[256];
	unsigned i;
	prepare_enabled(&card, &ctx, &priv);
	card.lock_count = 1;
	enforce_model_auth = 1;
	expect_pin(0x90, 0);
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_SUCCESS);
	for (i = 0; i < 32; i++) {
		expect_mse();
		assert_int_equal(epki_set_security_env(&card, &env, 0), SC_SUCCESS);
		next_apdu = (struct expected_apdu){0, 0x2a, 0x9e, 0x9a,
				SC_APDU_CASE_4_SHORT, digest_info, sizeof(digest_info), 256,
				SC_APDU_FLAGS_NO_RETRY_WL, SC_APDU_FLAGS_CHAINING | SC_APDU_FLAGS_NO_GET_RESP,
				signature, sizeof(signature), 0x90, 0, SC_SUCCESS};
		assert_int_equal(epki_compute_signature(&card, digest_info, sizeof(digest_info),
						 out, sizeof(out)),
				256);
	}
	/* No per-connection quota; a fresh MSE is still required after each PSO. */
	assert_memory_equal(out, signature, sizeof(out));
	assert_true(priv.pin_verified);
	assert_false(priv.security_env_valid);
	assert_int_equal(epki_compute_signature(&card, digest_info, sizeof(digest_info),
					 out, sizeof(out)),
			SC_ERROR_NOT_ALLOWED);
	assert_int_equal(card.lock_count, 1);
	assert_int_equal(transmit_calls, 65); /* One VERIFY and 32 MSE/PSO pairs. */
}

static void
logout_clears_authentication_and_allows_relogin(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	struct sc_pin_cmd_data pin = valid_pin_request();
	sc_security_env_t env = valid_security_env();
	prepare_enabled(&card, &ctx, &priv);
	priv.pin_verified = priv.security_env_valid = model_pin_verified = 1;
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	assert_int_equal(epki_logout(&card), SC_SUCCESS);
	assert_false(priv.pin_verified);
	assert_false(priv.security_env_valid);
	assert_false(model_pin_verified);
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
	expect_pin(0x90, 0);
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_SUCCESS);
	assert_true(priv.pin_verified);
	expect_mse();
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_SUCCESS);
	assert_int_equal(transmit_calls, 2);
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_ERROR_TRANSMIT_FAILED);
	assert_int_equal(epki_logout(&card), SC_ERROR_TRANSMIT_FAILED);
	assert_false(priv.pin_verified);
	assert_false(priv.security_env_valid);
	assert_false(priv.app_selected);
	assert_int_equal(card.lock_count, 0);
}

static void
new_transaction_requires_fresh_authentication(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	sc_security_env_t env = valid_security_env();
	struct sc_pin_cmd_data pin = valid_pin_request();
	u8 digest_info[51] = {0x30, 0x31}, out[256];
	unsigned phase;
	for (phase = 0; phase < 2; phase++) {
		prepare_enabled(&card, &ctx, &priv);
		card.ops = sc_get_test_epki_research_driver()->ops;
		priv.pin_verified = priv.security_env_valid = 1;
		new_transaction_at_next_lock = 1;
		if (phase == 0)
			assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
		else
			assert_int_equal(epki_compute_signature(&card, digest_info, sizeof(digest_info),
							 out, sizeof(out)),
					SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);
		assert_false(priv.pin_verified);
		assert_int_equal(transmit_calls, 0);
		assert_int_equal(card.lock_count, 0);
		/* The caller, including OpenSC's bounded PIN cache, may revalidate. */
		expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
		expect_pin(0x90, 0);
		assert_int_equal(epki_pin_cmd(&card, &pin), SC_SUCCESS);
		assert_true(priv.pin_verified);
		assert_int_equal(transmit_calls, 1);
		epki_clear_selection(&priv);
	}
}

static void
preserve_login_across_public_reads_and_key_selection(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	sc_path_t app, child;
	sc_file_t *returned = NULL;
	sc_security_env_t env = valid_security_env();
	struct sc_pin_cmd_data pin = valid_pin_request();
	static const u8 fid[] = {0x54, 0x02};
	u8 digest_info[51] = {0x30, 0x31}, signature[256] = {0}, output[256];

	prepare_enabled(&card, &ctx, &priv);
	card.lock_count = 1; /* One caller-held operation transaction. */
	enforce_model_auth = 1;
	sc_format_path("3F005015", &app);
	sc_format_path("3F0050155402", &child);
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	assert_int_equal(epki_select_file(&card, &app, NULL), SC_SUCCESS);
	assert_non_null(priv.app_file);
	expect_pin(0x90, 0);
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_SUCCESS);
	assert_true(model_pin_verified);

	/* Post-login certificate reads must select only the child FID. */
	expect_selection(SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 1, SC_SUCCESS);
	assert_int_equal(epki_select_file(&card, &child, &returned), SC_SUCCESS);
	sc_file_free(returned);
	returned = NULL;
	assert_true(priv.pin_verified);
	assert_true(model_pin_verified);
	assert_int_equal(file_select_calls, 2);

	/* PKCS#15 use_key selects the bare application path; no APDU needed. */
	assert_int_equal(epki_select_file(&card, &app, NULL), SC_SUCCESS);
	assert_int_equal(epki_select_file(&card, &app, &returned), SC_SUCCESS);
	assert_non_null(returned);
	assert_ptr_not_equal(returned, priv.app_file);
	sc_file_free(returned);
	returned = NULL;
	app.type = SC_PATH_TYPE_DF_NAME;
	app.len = sizeof(epki_aid);
	memcpy(app.value, epki_aid, sizeof(epki_aid));
	assert_int_equal(epki_select_file(&card, &app, NULL), SC_SUCCESS);
	assert_int_equal(file_select_calls, 2);
	expect_mse();
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_SUCCESS);
	next_apdu = (struct expected_apdu){0, 0x2a, 0x9e, 0x9a,
			SC_APDU_CASE_4_SHORT, digest_info, sizeof(digest_info), 256,
			SC_APDU_FLAGS_NO_RETRY_WL, SC_APDU_FLAGS_CHAINING,
			signature, sizeof(signature), 0x90, 0, SC_SUCCESS};
	assert_int_equal(epki_compute_signature(&card, digest_info, sizeof(digest_info), output, sizeof(output)), 256);
	assert_int_equal(transmit_calls, 3); /* One VERIFY, MSE and PSO. */
	assert_int_equal(card.lock_count, 1);
	epki_clear_selection(&priv);
}

static void
invalidate_authenticated_cache_on_transaction_or_foreign_selection(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	sc_path_t app, foreign, child;
	static const u8 fid[] = {0x54, 0x02};
	sc_security_env_t env = valid_security_env();
	prepare_enabled(&card, &ctx, &priv);
	card.lock_count = 1;
	sc_format_path("3F005015", &app);
	sc_format_path("3F005016", &foreign);
	sc_format_path("3F0050155402", &child);
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	assert_int_equal(epki_select_file(&card, &app, NULL), SC_SUCCESS);
	priv.pin_verified = 1;
	assert_int_equal(epki_reader_lock_obtained(&card, 0), SC_SUCCESS);
	assert_false(priv.pin_verified);
	assert_false(priv.app_selected);
	assert_null(priv.app_file);
	assert_int_equal(epki_set_security_env(&card, &env, 0), SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);

	/* New transaction must select again; it cannot reuse stale state. */
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	assert_int_equal(epki_select_file(&card, &app, NULL), SC_SUCCESS);
	priv.pin_verified = 1;
	expect_selection(foreign.type, foreign.value, foreign.len, 0, SC_SUCCESS);
	assert_int_equal(epki_select_file(&card, &foreign, NULL), SC_SUCCESS);
	assert_false(priv.pin_verified);
	assert_false(priv.app_selected);
	assert_null(priv.app_file);

	/* An error selecting a same-app child also invalidates the cache. */
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	assert_int_equal(epki_select_file(&card, &app, NULL), SC_SUCCESS);
	priv.pin_verified = 1;
	expect_selection(SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 1, SC_ERROR_TRANSMIT_FAILED);
	assert_int_equal(epki_select_file(&card, &child, NULL), SC_ERROR_TRANSMIT_FAILED);
	assert_false(priv.pin_verified);
	assert_false(priv.app_selected);
	assert_null(priv.app_file);
}

static void
child_df_or_unknown_fci_cannot_preserve_authenticated_app(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	sc_path_t app, child;
	static const u8 fid[] = {0x54, 0x02};
	int types[] = {SC_FILE_TYPE_DF, SC_FILE_TYPE_UNKNOWN, SC_FILE_TYPE_BSO, -1};
	size_t i;
	prepare_enabled(&card, &ctx, &priv);
	card.lock_count = 1;
	sc_format_path("3F005015", &app);
	sc_format_path("3F0050155402", &child);
	for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
		expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
		assert_int_equal(epki_select_file(&card, &app, NULL), SC_SUCCESS);
		priv.pin_verified = 1;
		child_file_type = types[i];
		expect_selection(SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 1, SC_SUCCESS);
		assert_int_equal(epki_select_file(&card, &child, NULL), SC_SUCCESS);
		assert_false(priv.pin_verified);
		assert_false(priv.app_selected);
		assert_null(priv.app_file);
	}
	child_file_type = SC_FILE_TYPE_WORKING_EF;
}

static void
invalidate_cache_before_consulting_it_on_new_transaction(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	sc_path_t app;
	prepare_enabled(&card, &ctx, &priv);
	card.ops = sc_get_test_epki_research_driver()->ops;
	sc_format_path("3F005015", &app);
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	assert_int_equal(epki_select_file(&card, &app, NULL), SC_SUCCESS);
	priv.pin_verified = 1;
	new_transaction_at_next_lock = 1;
	/* A stale cached app is discarded during lock acquisition. */
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	assert_int_equal(epki_select_file(&card, &app, NULL), SC_SUCCESS);
	assert_int_equal(file_select_calls, 2);
	assert_false(priv.pin_verified);
	assert_true(priv.app_selected);
	assert_non_null(priv.app_file);
	epki_clear_selection(&priv);
}

static void
opensc_prepends_digest_info_without_rsa_padding(void **state)
{
	sc_context_t ctx = {0};
	u8 digest[32] = {0}, encoded[256];
	size_t encoded_len = sizeof(encoded);
	static const u8 sha256_prefix[] = {
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
			0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
	unsigned long pad = 0, security = 0;
	unsigned long caps = SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_HASH_NONE;
	assert_int_equal(sc_get_encoding_flags(&ctx,
					 SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_HASH_SHA256,
					 caps, &pad, &security),
			SC_SUCCESS);
	assert_int_equal(security, caps);
	assert_int_equal(pad, SC_ALGORITHM_RSA_HASH_SHA256);
	assert_int_equal(sc_pkcs1_encode(&ctx, pad, digest, sizeof(digest), encoded,
					 &encoded_len, 2048, NULL),
			SC_SUCCESS);
	assert_int_equal(encoded_len, 51);
	assert_memory_equal(encoded, sha256_prefix, sizeof(sha256_prefix));
	assert_memory_equal(encoded + sizeof(sha256_prefix), digest, sizeof(digest));
	assert_int_equal(sc_get_encoding_flags(&ctx, caps, caps, &pad, &security), SC_SUCCESS);
	assert_int_equal(pad, 0);
	assert_int_equal(security, caps);
}

static void
reset_requires_profile_check_before_reauthentication(void **state)
{
	sc_card_t card;
	sc_context_t ctx;
	struct epki_data priv;
	struct sc_pin_cmd_data pin = valid_pin_request();
	static const u8 good[] = {0x02, 0x82}, wrong[] = {0x02, 0x81};
	prepare_enabled(&card, &ctx, &priv);
	priv.pin_verified = priv.security_env_valid = 1;
	assert_int_equal(epki_reader_lock_obtained(&card, 1), SC_SUCCESS);
	assert_false(priv.profile_checked);
	assert_false(priv.pin_verified);
	assert_false(priv.security_env_valid);
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	expect_version(wrong, sizeof(wrong));
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_ERROR_INVALID_CARD);
	assert_false(priv.profile_checked);
	assert_int_equal(transmit_calls, 1); /* Public query only; no PIN. */

	/* A later explicit request can recover after a valid profile query. */
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	expect_pin(0x90, 0);
	following_apdu = next_apdu;
	have_following_apdu = 1;
	expect_version(good, sizeof(good));
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_SUCCESS);
	assert_true(priv.profile_checked);
	assert_true(priv.pin_verified);
	assert_int_equal(transmit_calls, 3);
	epki_clear_selection(&priv);

	/* Reset discovered by sc_lock also revalidates before any PIN I/O. */
	prepare_enabled(&card, &ctx, &priv);
	card.ops = sc_get_test_epki_research_driver()->ops;
	reset_at_next_lock = 1;
	expect_selection(SC_PATH_TYPE_DF_NAME, epki_aid, sizeof(epki_aid), 1, SC_SUCCESS);
	expect_version(wrong, sizeof(wrong));
	assert_int_equal(epki_pin_cmd(&card, &pin), SC_ERROR_INVALID_CARD);
	assert_int_equal(card.lock_count, 0);
	assert_int_equal(transmit_calls, 1);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(no_implicit_profile_probe),
			cmocka_unit_test(enabled_profile_still_requires_observed_atr),
			cmocka_unit_test(read_only_profile_rejects_unverified_versions),
			cmocka_unit_test(read_only_profile_requires_complete_successful_probe),
			cmocka_unit_test(explicit_read_only_profile_is_narrow),
			cmocka_unit_test(enabled_profile_requires_aid_selection),
			cmocka_unit_test(enable_signing_for_explicit_matching_profile),
			cmocka_unit_test(verify_once_per_request_and_preserve_retry_count),
			cmocka_unit_test(reject_unsafe_pin_requests_before_io),
			cmocka_unit_test(only_verified_signing_environment),
			cmocka_unit_test(failed_mse_allows_a_new_authenticated_operation),
			cmocka_unit_test(selected_pkcs15_key_reference_is_preserved),
			cmocka_unit_test(raw_rsa_requires_both_explicit_options),
			cmocka_unit_test(raw_rsa_remains_sign_only_and_requires_authentication),
			cmocka_unit_test(raw_rsa_uses_exact_extended_framing_and_bounded_response),
			cmocka_unit_test(raw_rsa_failure_consumes_current_operation),
			cmocka_unit_test(decryption_requires_its_own_opt_in),
			cmocka_unit_test(decryption_uses_a_distinct_environment_and_raw_framing),
			cmocka_unit_test(decryption_errors_do_not_release_output_or_retry),
			cmocka_unit_test(decryption_cannot_reuse_authentication_after_unlock_or_reset),
			cmocka_unit_test(sign_digest_info_once_and_validate_response),
			cmocka_unit_test(repeated_operations_do_not_exhaust_driver),
			cmocka_unit_test(logout_clears_authentication_and_allows_relogin),
			cmocka_unit_test(new_transaction_requires_fresh_authentication),
			cmocka_unit_test(reset_requires_profile_check_before_reauthentication),
			cmocka_unit_test(opensc_prepends_digest_info_without_rsa_padding),
			cmocka_unit_test(preserve_login_across_public_reads_and_key_selection),
			cmocka_unit_test(invalidate_authenticated_cache_on_transaction_or_foreign_selection),
			cmocka_unit_test(child_df_or_unknown_fci_cannot_preserve_authenticated_app),
			cmocka_unit_test(invalidate_cache_before_consulting_it_on_new_transaction),
			cmocka_unit_test(deny_security_operations_without_io),
			cmocka_unit_test(only_public_read_callbacks_are_inherited),
			cmocka_unit_test(map_only_observed_application_paths),
			cmocka_unit_test(preserve_other_paths_and_selection_errors),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
