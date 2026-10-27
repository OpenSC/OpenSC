/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Synthetic record fixtures only: no card data or hardware access. */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include "libopensc/internal.h"
#include "libopensc/pkcs15.h"
#include "torture.h"

static const u8 pin[] = {
		0x30, 0x21, 0x30, 0x00, 0x30, 0x03, 0x04, 0x01, 0x03,
		0xa1, 0x18, 0x30, 0x16, 0x03, 0x02, 0x02, 0xcc, 0x0a,
		0x01, 0x01, 0x02, 0x01, 0x04, 0x02, 0x01, 0x08, 0x02,
		0x01, 0x08, 0x80, 0x01, 0x01, 0x04, 0x01, 0xff};
static u8 records[3][604];
static size_t record_sizes[3], advertised_size;
static unsigned record_calls, max_records, read_offset, continuation_calls;
static int generated_records, read_error, continuation_error;

static int
mock_select_file(sc_card_t *card, const sc_path_t *path, sc_file_t **out)
{
	*out = sc_file_new();
	assert_non_null(*out);
	(*out)->ef_structure = SC_FILE_EF_LINEAR_VARIABLE_TLV;
	(*out)->size = advertised_size;
	(*out)->record_count = max_records;
	if (generated_records) {
		(*out)->record_length = 256;
	} else {
		for (unsigned i = 0; i < max_records; i++)
			(*out)->record_length = MAX((*out)->record_length, record_sizes[i]);
	}
	return SC_SUCCESS;
}
static int
mock_read_record(sc_card_t *card, unsigned rec, unsigned idx,
		u8 *out, size_t count, unsigned long flags)
{
	size_t n;
	if (idx == 0) {
		record_calls++;
		read_offset = 0;
	}
	assert_int_equal(rec, record_calls);
	assert_int_equal(idx, read_offset);
	assert_int_equal(flags, SC_RECORD_BY_REC_NR);
	assert_true(count <= 256);
	if (read_error)
		return read_error;
	if (rec > max_records)
		return SC_ERROR_RECORD_NOT_FOUND;
	if (idx >= 256) {
		continuation_calls++;
		if (continuation_error)
			return continuation_error;
	}
	if (generated_records) {
		assert_true(count >= 256);
		out[0] = rec;
		out[1] = 254;
		memset(out + 2, 0xa5, 254);
		return 256;
	}
	n = record_sizes[rec - 1];
	if (idx >= n)
		return 0;
	n -= idx;
	/* Model a successful short read when the caller's buffer is small. */
	if (n > count)
		n = count;
	memcpy(out, records[rec - 1] + idx, n);
	read_offset += n;
	return (int)n;
}
static void
reset_records(void)
{
	memset(records, 0, sizeof(records));
	memset(record_sizes, 0, sizeof(record_sizes));
	advertised_size = 3 * sizeof(pin);
	max_records = 3;
	record_calls = 0;
	read_offset = 0;
	continuation_calls = 0;
	generated_records = 0;
	read_error = 0;
	continuation_error = 0;
	for (unsigned i = 0; i < max_records; i++) {
		records[i][0] = i + 1;
		records[i][1] = sizeof(pin);
		memcpy(records[i] + 2, pin, sizeof(pin));
		record_sizes[i] = sizeof(pin) + 2;
	}
}
static void
set_long_record(void)
{
	reset_records();
	max_records = 2;
	advertised_size = 600 + sizeof(pin);
	records[0][1] = 0xff;
	records[0][2] = 0x02;
	records[0][3] = 0x58;
	for (size_t i = 0; i < 600; i++)
		records[0][i + 4] = (u8)(i % 251);
	record_sizes[0] = 604;
}
static int
read_fixture_with_transport(u8 **out, size_t *len,
		int (*transmit)(sc_reader_t *, sc_apdu_t *))
{
	sc_context_t ctx = {0};
	sc_card_t card = {0};
	sc_pkcs15_card_t p15 = {0};
	sc_path_t path = {0};
	struct sc_card_operations card_ops = {0};
	struct sc_reader_operations reader_ops = {0};
	sc_reader_t reader = {0};
	if (transmit)
		card_ops = *sc_get_iso7816_driver()->ops;
	else
		card_ops.read_record = mock_read_record;
	card_ops.select_file = mock_select_file;
	reader_ops.transmit = transmit;
	reader.ops = &reader_ops;
	reader.active_protocol = SC_PROTO_T1;
	reader.max_recv_size = 256;
	card.reader = &reader;
	card.max_recv_size = 256;
	card.ops = &card_ops;
	card.ctx = &ctx;
	p15.card = &card;
	path.count = -1;
	return sc_pkcs15_read_file(&p15, &path, out, len, 0);
}
static int
read_fixture(u8 **out, size_t *len)
{
	return read_fixture_with_transport(out, len, NULL);
}
static void
complete_values_without_counting_headers(void **state)
{
	int r;
	u8 *out = NULL;
	const u8 *p;
	size_t len = 0;
	sc_context_t ctx = {0};
	sc_card_t card = {0};
	sc_pkcs15_card_t p15 = {0};
	sc_file_t app = {0};
	reset_records();
	r = read_fixture(&out, &len);
	assert_int_equal(r, SC_SUCCESS);
	assert_int_equal(len, 3 * sizeof(pin));
	assert_int_equal(record_calls, 4);
	card.ctx = &ctx;
	p15.card = &card;
	p15.file_app = &app;
	app.path.len = 2;
	app.path.value[0] = 0x50;
	app.path.value[1] = 0x15;
	p = out;
	for (unsigned i = 0; i < 3; i++) {
		sc_pkcs15_object_t obj = {0};
		r = sc_pkcs15_decode_aodf_entry(&p15, &obj, &p, &len);
		assert_int_equal(r, SC_SUCCESS);
		assert_int_equal(obj.type, SC_PKCS15_TYPE_AUTH_PIN);
		assert_int_equal(((sc_pkcs15_auth_info_t *)obj.data)->attrs.pin.reference, 1);
		free(obj.data);
	}
	assert_int_equal(len, 0);
	free(out);
}
static void
check_padded_records(size_t header_len)
{
	int r;
	u8 *out = NULL;
	size_t len = 0;
	reset_records();
	for (unsigned i = 0; i < max_records; i++) {
		if (header_len == 4) {
			records[i][1] = 0xff;
			records[i][2] = 0;
			records[i][3] = sizeof(pin);
		}
		memcpy(records[i] + header_len, pin, sizeof(pin));
		memset(records[i] + header_len + sizeof(pin), 0, 5);
		record_sizes[i] = header_len + sizeof(pin) + 5;
	}
	r = read_fixture(&out, &len);
	assert_int_equal(r, SC_SUCCESS);
	assert_int_equal(len, max_records * sizeof(pin));
	assert_int_equal(record_calls, max_records + 1);
	for (unsigned i = 0; i < max_records; i++)
		assert_memory_equal(out + i * sizeof(pin), pin, sizeof(pin));
	free(out);
}
static void
complete_padded_short_records(void **state)
{
	check_padded_records(2);
}
static void
complete_padded_extended_records(void **state)
{
	check_padded_records(4);
}
static void
reject_incomplete_record(void **state)
{
	int r;
	u8 *out = NULL;
	size_t len = 0;
	reset_records();
	record_sizes[1]--;
	r = read_fixture(&out, &len);
	assert_int_equal(r, SC_ERROR_INVALID_TLV_OBJECT);
	assert_null(out);
}
static void
reject_partial_header(void **state)
{
	int r;
	u8 *out = NULL;
	size_t len = 0;
	reset_records();
	record_sizes[0] = 1;
	r = read_fixture(&out, &len);
	assert_int_equal(r, SC_ERROR_INVALID_TLV_OBJECT);
	assert_null(out);
	reset_records();
	records[0][1] = 0xff;
	record_sizes[0] = 3;
	r = read_fixture(&out, &len);
	assert_int_equal(r, SC_ERROR_INVALID_TLV_OBJECT);
	assert_null(out);
}
static unsigned iso_record_calls;

static int
mock_record_transmit(sc_reader_t *reader, sc_apdu_t *apdu)
{
	static const struct {
		unsigned record, offset;
	} sequence[] = {
			{1, 0		     },
			{1, 256	       },
			{1, 509	       },
			{2, 0		     },
			{2, sizeof(pin) + 2},
			{3, 0		     },
	};
	unsigned step = iso_record_calls++;
	size_t offset, n, header;

	assert_true(step < sizeof(sequence) / sizeof(sequence[0]));
	offset = sequence[step].offset;
	assert_int_equal(apdu->ins, offset ? 0xb3 : 0xb2);
	assert_int_equal(apdu->p1, sequence[step].record);
	assert_int_equal(apdu->p2, 4);
	if (offset) {
		u8 do54[] = {0x54, 0x02, (u8)(offset >> 8), (u8)offset};
		assert_int_equal(apdu->datalen, sizeof(do54));
		assert_memory_equal(apdu->data, do54, sizeof(do54));
	}
	if (apdu->p1 > max_records) {
		apdu->resplen = 0;
		apdu->sw1 = 0x6a;
		apdu->sw2 = 0x83;
		return SC_SUCCESS;
	}
	assert_true(offset <= record_sizes[apdu->p1 - 1]);
	n = record_sizes[apdu->p1 - 1] - offset;
	if (offset) {
		/* Leave room for DO53 in the 256-byte APDU response. */
		n = MIN(n, 253);
		header = n < 128 ? 2 : 3;
		assert_true(header + n <= apdu->resplen);
		apdu->resp[0] = 0x53;
		apdu->resp[1] = header == 2 ? (u8)n : 0x81;
		if (header == 3)
			apdu->resp[2] = (u8)n;
	} else {
		header = 0;
		n = MIN(n, apdu->le);
		assert_true(n <= apdu->resplen);
	}
	memcpy(apdu->resp + header, records[apdu->p1 - 1] + offset, n);
	apdu->resplen = header + n;
	apdu->sw1 = 0x90;
	apdu->sw2 = 0;
	return SC_SUCCESS;
}

static void
complete_long_record_and_following_record(void **state)
{
	int r;
	u8 *out = NULL;
	size_t len = 0;
	set_long_record();
	iso_record_calls = 0;
	r = read_fixture_with_transport(&out, &len, mock_record_transmit);
	assert_int_equal(r, SC_SUCCESS);
	assert_int_equal(len, 600 + sizeof(pin));
	assert_int_equal(iso_record_calls, 6);
	assert_memory_equal(out, records[0] + 4, 600);
	assert_memory_equal(out + 600, pin, sizeof(pin));
	free(out);
}
static void
reject_truncated_long_record(void **state)
{
	int r;
	u8 *out = NULL;
	size_t len = 0;
	set_long_record();
	record_sizes[0]--;
	r = read_fixture(&out, &len);
	assert_int_equal(r, SC_ERROR_INVALID_TLV_OBJECT);
	assert_int_equal(record_calls, 1);
	assert_true(continuation_calls > 0);
	assert_null(out);
}
static void
propagate_continuation_error(void **state)
{
	int r;
	u8 *out = NULL;
	size_t len = 0;
	set_long_record();
	continuation_error = SC_ERROR_TRANSMIT_FAILED;
	r = read_fixture(&out, &len);
	assert_int_equal(r, SC_ERROR_TRANSMIT_FAILED);
	assert_int_equal(record_calls, 1);
	assert_int_equal(continuation_calls, 1);
	assert_null(out);
}
static void
complete_maximum_record_file(void **state)
{
	int r;
	u8 *out = NULL;
	size_t len = 0;
	reset_records();
	generated_records = 1;
	max_records = 254;
	advertised_size = max_records * 254;
	r = read_fixture(&out, &len);
	assert_int_equal(r, SC_SUCCESS);
	assert_int_equal(record_calls, 255);
	assert_int_equal(len, 254 * 254);
	assert_true(len <= MAX_FILE_SIZE);
	free(out);
}
static void
reject_values_exceeding_file_size(void **state)
{
	int r;
	u8 *out = NULL;
	size_t len = 0;
	reset_records();
	advertised_size--;
	r = read_fixture(&out, &len);
	assert_int_equal(r, SC_ERROR_INVALID_TLV_OBJECT);
	assert_null(out);
	set_long_record();
	advertised_size = 599;
	r = read_fixture(&out, &len);
	assert_int_equal(r, SC_ERROR_INVALID_TLV_OBJECT);
	assert_int_equal(record_calls, 1);
	assert_int_equal(continuation_calls, 0);
	assert_null(out);
}

static unsigned apdu_calls, expected_record;

static int
mock_transmit(sc_reader_t *reader, sc_apdu_t *apdu)
{
	apdu_calls++;
	assert_int_equal(apdu->ins, 0xb2);
	assert_int_equal(apdu->p1, expected_record);
	assert_int_equal(apdu->p2, 4);
	assert_true(apdu->resplen >= 1);
	apdu->resp[0] = 0xa5;
	apdu->resplen = 1;
	apdu->sw1 = 0x90;
	apdu->sw2 = 0;
	return SC_SUCCESS;
}

static void
iso_record_number_boundary(void **state)
{
	sc_context_t ctx = {0};
	struct sc_reader_operations reader_ops = {0};
	sc_reader_t reader = {0};
	sc_card_t card = {0};
	struct sc_card_operations *iso = sc_get_iso7816_driver()->ops;
	u8 value;
	int r;

	reader_ops.transmit = mock_transmit;
	reader.ops = &reader_ops;
	reader.active_protocol = SC_PROTO_T1;
	reader.max_recv_size = 256;
	card.reader = &reader;
	card.ctx = &ctx;
	card.ops = iso;
	card.max_recv_size = 256;
	apdu_calls = 0;
	/* Current record and the last permitted record still reach transport. */
	expected_record = 0;
	r = iso->read_record(&card, expected_record, 0, &value, 1, SC_RECORD_BY_REC_NR);
	assert_int_equal(r, 1);
	assert_int_equal(value, 0xa5);
	expected_record = 254;
	r = iso->read_record(&card, expected_record, 0, &value, 1, SC_RECORD_BY_REC_NR);
	assert_int_equal(r, 1);
	assert_int_equal(apdu_calls, 2);
	/* Reserved numbers/identifiers are rejected before an APDU is sent. */
	r = iso->read_record(&card, 255, 0, &value, 1, SC_RECORD_BY_REC_NR);
	assert_int_equal(r, SC_ERROR_RECORD_NOT_FOUND);
	r = iso->read_record(&card, 255, 0, &value, 1, SC_RECORD_BY_REC_ID);
	assert_int_equal(r, SC_ERROR_RECORD_NOT_FOUND);
	r = iso->read_record(&card, 256, 0, &value, 1, SC_RECORD_BY_REC_NR);
	assert_int_equal(r, SC_ERROR_INVALID_ARGUMENTS);
	assert_int_equal(apdu_calls, 2);
}

static void
propagate_read_error(void **state)
{
	int r;
	u8 *out = NULL;
	size_t len = 0;
	reset_records();
	read_error = SC_ERROR_TRANSMIT_FAILED;
	r = read_fixture(&out, &len);
	assert_int_equal(r, SC_ERROR_TRANSMIT_FAILED);
	assert_null(out);
}
int
main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(complete_values_without_counting_headers),
			cmocka_unit_test(complete_padded_short_records),
			cmocka_unit_test(complete_padded_extended_records),
			cmocka_unit_test(reject_incomplete_record),
			cmocka_unit_test(reject_partial_header),
			cmocka_unit_test(complete_long_record_and_following_record),
			cmocka_unit_test(reject_truncated_long_record),
			cmocka_unit_test(propagate_continuation_error),
			cmocka_unit_test(complete_maximum_record_file),
			cmocka_unit_test(reject_values_exceeding_file_size),
			cmocka_unit_test(iso_record_number_boundary),
			cmocka_unit_test(propagate_read_error)};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
