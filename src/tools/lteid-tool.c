/*
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "eac/objects.h"
#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"
#include "sm/sm-eac.h"
#include "util.h"

/* win32 needs this in open(2) */
#ifndef O_BINARY
#define O_BINARY 0
#endif

static const char *app_name = "lteid-tool";

#define OP_NONE	      0 /* no operation requested */
#define OP_RESUME     1 /* resume pin entry using CAN code */
#define OP_UNBLOCK    2 /* unblock using PUK code */
#define OP_CHANGE_PIN 3

#ifdef _WIN32
#define CAN_STORE_FILE "\\lteid_can"
#else
#define CAN_STORE_FILE "/lteid_can"
#endif

static const struct option options[] = {
		{"help",	 0, NULL, 'h'},
		{"verbose",    0, NULL, 'v'},
		{"reader",	   1, NULL, 'r'},
		{"wait",	 0, NULL, 'w'},
		{"can",	1, NULL, 'c'},
		{"pin",	1, NULL, 'p'},
		{"puk",	1, NULL, 'u'},
		{"change-pin", 0, NULL, 'C'},
		{"resume",	   0, NULL, 'R'},
		{"unblock",    0, NULL, 'U'},
		{NULL,	       0, NULL, 0	 }
};

static const char *option_help[] = {
		"Display tool options",
		"Display all the information available",
		"Uses reader number <arg> [0]",
		"Wait for a card to be inserted",
		"Specify CAN",
		"Specify PIN",
		"Specify PUK",
		"Change PIN",
		"Resume authentication key PIN after 2 incorrect attempts",
		"Unblock PIN using PUK",
};

static int
get_tries_left(sc_pkcs15_card_t *p15card, u8 pin_reference, int *pin_tries_left)
{
	int rv, i;
	struct sc_pkcs15_object *objs[32];

	*pin_tries_left = -1;

	rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH, objs, 32);
	if (rv < 0) {
		fprintf(stderr, "AUTH objects enumeration failed: %s\n", sc_strerror(rv));
		return 1;
	}

	for (i = 0; i < rv; i++) {
		sc_pkcs15_get_pin_info(p15card, objs[i]);

		const struct sc_pkcs15_auth_info *auth_info = (const struct sc_pkcs15_auth_info *)objs[i]->data;

		if (auth_info->auth_id.len == 1 && auth_info->auth_id.value[0] == pin_reference) {
			*pin_tries_left = auth_info->tries_left;
			return SC_SUCCESS;
		}
	}

	return SC_ERROR_OBJECT_NOT_FOUND;
}

static int
display_pin_tries_left(sc_pkcs15_card_t *p15card)
{
	int pace_pin_tries_left, qes_pin_tries_left, puk_tries_left;

	get_tries_left(p15card, 0x04, &puk_tries_left);
	get_tries_left(p15card, 0x03, &pace_pin_tries_left);
	get_tries_left(p15card, 0x81, &qes_pin_tries_left);

	printf("\n");
	printf("PUK tries left: %i\n", puk_tries_left);
	printf("PIN (for authentication) tries left: %i\n", pace_pin_tries_left);
	printf("PIN (for electronic signatures) tries left: %i\n", qes_pin_tries_left);
	printf("\n");

	return SC_SUCCESS;
}

static int
display_basic_details(sc_pkcs15_card_t *p15card)
{
	printf("\nCard label: %s\n", p15card->tokeninfo->label);
	printf("Serial number: %s\n", p15card->tokeninfo->serial_number);

	display_pin_tries_left(p15card);

	return SC_SUCCESS;
}

static int
lteid_store_can(sc_card_t *card, const char *can)
{
	int rv;
	char path[PATH_MAX];

	sc_get_cache_dir(card->ctx, path, sizeof(path));
	strcat(path, CAN_STORE_FILE);

	unlink(path);

	FILE *fd = fopen(path, "w");

	if (!fd && errno == ENOENT) {
		if ((rv = sc_make_cache_dir(card->ctx)) < 0)
			return rv;

		fd = fopen(path, "w");
	}

	if (!fd) {
		return SC_ERROR_INTERNAL;
	}

	fwrite(can, 1, 6, fd);
	fclose(fd);

	return SC_SUCCESS;
}

char *
lteid_get_stored_can(sc_card_t *card)
{
	char path[PATH_MAX];
	char *can;

	can = calloc(7, 1);

	sc_get_cache_dir(card->ctx, path, sizeof(path));
	strcat(path, CAN_STORE_FILE);

	FILE *fd = fopen(path, "r");

	if (!fd) {
		free(can);
		return NULL;
	}

	if (6 != fread(can, 1, 6, fd)) {
		free(can);
		return NULL;
	}

	fclose(fd);

	return can;
}

int
input_number(const char *description, size_t min_len, size_t max_len, const char *provided_via_cli, char **number)
{
	size_t number_len = 0;

	if (provided_via_cli && strlen(provided_via_cli) >= min_len && strlen(provided_via_cli) <= max_len) {
		*number = strdup(provided_via_cli);

		printf("Using %s provided via command line arguments.\n", description);

		return SC_SUCCESS;
	}

	printf("Enter %s ", description);

	if (min_len == max_len) {
		printf("(%lu digits): ", min_len);
	} else {
		printf("(%lu..%lu digits): ", min_len, max_len);
	}

	number_len = util_getpass(number, NULL, stdin);

	if (number_len < min_len || number_len > max_len) {
		return SC_ERROR_INTERNAL;
	}

	for (size_t i = 0; i < number_len; i++) {
		if ((*number)[i] < '0' || (*number)[i] > '9') {
			return SC_ERROR_INTERNAL;
		}
	}

	return SC_SUCCESS;
}

int
get_and_store_pace_can(sc_card_t *card, const char *opt_can)
{
	int rv;
	struct sc_path path;
	struct establish_pace_channel_input pace_input = {0};
	struct establish_pace_channel_output pace_output = {0};
	char *can = NULL;

	rv = input_number("number from the bottom right corner of the card", 6, 6, opt_can, &can);

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "CAN number blank, too short or too long.\n");
		return SC_ERROR_PIN_CODE_INCORRECT;
	}

	sc_format_path("3F00", &path);
	sc_select_file(card, &path, NULL);

	pace_input.pin_id = PACE_PIN_ID_CAN;
	pace_input.pin = (unsigned char *)can;
	pace_input.pin_length = strlen(can);

	rv = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "CAN number verification failed: %s\nCheck the number and try again.\n", sc_strerror(rv));
		return SC_ERROR_PIN_CODE_INCORRECT;
	}

	rv = lteid_store_can(card, can);

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "Could not store the new CAN code.\n");
		return SC_ERROR_INTERNAL;
	}

	printf("\nThe new CAN code is now persisted.\n");
	printf("\nIf you are about to use the card in your web browser - you may have to remove and re-insert it.\n");

	return SC_SUCCESS;
}

/*
 * Officially card has a single PIN. But under the hood it's really two separate PINs:
 *
 *   - PACE-PIN with ID 0x03, tied to the key intended for authentication. However,
 *     when changing it reference is 0x07 (which is not listed at all in PIN objects)
 *   - PIN.QES with ID 0x81, tied to the key intended for signature
 *
 * The procedure below follows this and applies change to both PINs.
 */
int
change_pin(sc_card_t *card, const char *opt_pin)
{
	int rv;
	struct establish_pace_channel_input pace_input = {0};
	struct establish_pace_channel_output pace_output = {0};
	struct sc_path path;
	char *pin = NULL;
	char *new_pin = NULL;
	char *new_pin_repeated = NULL;
	unsigned char pace_pin_changed = 0, qes_pin_changed = 0;

	rv = input_number("Current PIN", 6, 12, opt_pin, &pin);

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "PIN number blank, too short or too long.\n");
		return SC_ERROR_PIN_CODE_INCORRECT;
	}

	sc_sm_stop(card);

	sc_format_path("3F00", &path);
	sc_select_file(card, &path, NULL);

	pace_input.pin_id = PACE_PIN_ID_PIN;
	pace_input.pin = (unsigned char *)pin;
	pace_input.pin_length = strlen(pin);

	rv = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "PIN code verification failed: %s\n", sc_strerror(rv));
		return SC_ERROR_PIN_CODE_INCORRECT;
	}

	rv = input_number("New PIN", 6, 12, NULL, &new_pin);

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "PIN number blank, too short or too long.\n");
		return SC_ERROR_PIN_CODE_INCORRECT;
	}

	input_number("New PIN (repeat)", 6, 12, NULL, &new_pin_repeated);

	if (new_pin_repeated == NULL || strcmp(new_pin, new_pin_repeated) != 0) {
		fprintf(stderr, "New PIN and repated entry do not match. PIN was not changed.\n");
		return SC_ERROR_INTERNAL;
	}

	printf("\n");

	struct sc_pin_cmd_data pace_pin_cmd = {0};
	pace_pin_cmd.cmd = SC_PIN_CMD_CHANGE;
	pace_pin_cmd.pin_type = SC_AC_CHV;
	pace_pin_cmd.pin_reference = 0x07;
	pace_pin_cmd.pin2.data = (unsigned char *)new_pin;
	pace_pin_cmd.pin2.len = strlen(new_pin);

	rv = card->ops->pin_cmd(card, &pace_pin_cmd, NULL);

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "PIN for authentication change failed: %s\n", sc_strerror(rv));
	} else {
		printf("PIN for authentication changed.\n");
		pace_pin_changed = 1;
	}

	sc_format_path("3F00DF02", &path);
	sc_select_file(card, &path, NULL);

	struct sc_pin_cmd_data qes_pin_cmd = {0};
	qes_pin_cmd.cmd = SC_PIN_CMD_CHANGE;
	qes_pin_cmd.pin_type = SC_AC_CHV;
	qes_pin_cmd.pin_reference = 0x81;
	qes_pin_cmd.pin1.data = (unsigned char *)pin;
	qes_pin_cmd.pin1.len = strlen(pin);
	qes_pin_cmd.pin2.data = (unsigned char *)new_pin;
	qes_pin_cmd.pin2.len = strlen(new_pin);

	rv = card->ops->pin_cmd(card, &qes_pin_cmd, NULL);

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "PIN for signature change failed: %s\n", sc_strerror(rv));
	} else {
		printf("PIN for signature changed.\n");
		qes_pin_changed = 1;
	}

	return (pace_pin_changed && qes_pin_changed) ? SC_SUCCESS : SC_ERROR_INTERNAL;
}

int
resume(sc_pkcs15_card_t *p15card, const char *opt_can, const char *opt_pin)
{
	int rv;
	struct sc_card *card = p15card->card;
	struct establish_pace_channel_input pace_input = {0};
	struct establish_pace_channel_output pace_output = {0};
	struct sc_path path;
	char *pin = NULL;
	int tries_left;

	rv = get_tries_left(p15card, 0x03, &tries_left);

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "Cannot get remaining tries left: %s\n", sc_strerror(rv));
		return rv;
	}

	if (tries_left > 1) {
		fprintf(stderr, "PIN for authentication is not blocked, there's %i tries remaining.\n", tries_left);
		return SC_ERROR_NOT_ALLOWED;
	} else if (tries_left == 0) {
		fprintf(stderr, "PIN for authentication is fully blocked with 0 attempts remaining. Use 'lteid-tool --unblock' instead.\n");
		return SC_ERROR_NOT_ALLOWED;
	}

	rv = input_number("PIN number", 6, 12, opt_pin, &pin);

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "PIN number blank, too short or too long.\n");
		return SC_ERROR_PIN_CODE_INCORRECT;
	}

	sc_sm_stop(card);

	pace_input.pin_id = PACE_PIN_ID_CAN;
	pace_input.pin = (unsigned char *)opt_can;
	pace_input.pin_length = strlen(opt_can);

	sc_format_path("3F00", &path);
	sc_select_file(card, &path, NULL);

	rv = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "CAN code verification failed: %s\n", sc_strerror(rv));
		return SC_ERROR_PIN_CODE_INCORRECT;
	}

	pace_input.pin_id = PACE_PIN_ID_PIN;
	pace_input.pin = (unsigned char *)pin;
	pace_input.pin_length = strlen(pin);

	rv = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "PIN code verification failed: %s\n", sc_strerror(rv));
		return SC_ERROR_PIN_CODE_INCORRECT;
	}

	printf("PIN for authentication unblocked.\n");

	return SC_SUCCESS;
}

int
unblock_using_puk(sc_pkcs15_card_t *p15card, const char *opt_puk)
{
	int rv;
	struct sc_card *card = p15card->card;
	struct establish_pace_channel_input pace_input = {0};
	struct establish_pace_channel_output pace_output = {0};
	struct sc_apdu apdu;
	struct sc_path path;
	char *puk = NULL;
	int pace_pin_tries_left, qes_pin_tries_left;

	get_tries_left(p15card, 0x03, &pace_pin_tries_left);
	get_tries_left(p15card, 0x81, &qes_pin_tries_left);

	if (pace_pin_tries_left > 0 && qes_pin_tries_left > 0) {
		fprintf(stderr, "None of the PINs require unblocking.\n");
		return SC_ERROR_INTERNAL;
	}

	rv = input_number("PUK number", 8, 12, opt_puk, &puk);

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "PIN number blank, too short or too long.\n");
		return SC_ERROR_PIN_CODE_INCORRECT;
	}

	pace_input.pin_id = PACE_PIN_ID_PUK;
	pace_input.pin = (unsigned char *)puk;
	pace_input.pin_length = strlen(puk);

	// Stop previous PACE session established with CAN code
	sc_sm_stop(card);

	sc_format_path("3F00", &path);
	sc_select_file(card, &path, NULL);

	rv = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "PUK code verification failed: %s\n", sc_strerror(rv));
		return SC_ERROR_PIN_CODE_INCORRECT;
	}

	if (pace_pin_tries_left == 0) {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2c, 0x03, 0x07);

		rv = sc_transmit_apdu(card, &apdu);

		if (rv != SC_SUCCESS) {
			fprintf(stderr, "PIN for authentication reset failed: %s\n", sc_strerror(rv));
			return rv;
		}
	}

	if (qes_pin_tries_left == 0) {
		sc_format_path("3F00DF02", &path);
		sc_select_file(card, &path, NULL);

		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2c, 0x03, 0x81);

		rv = sc_transmit_apdu(card, &apdu);

		if (rv != SC_SUCCESS) {
			fprintf(stderr, "PIN for signature reset failed: %s\n", sc_strerror(rv));
			return rv;
		}
	}

	printf("PIN unblocked.\n");

	return SC_SUCCESS;
}

int
main(int argc, char *argv[])
{
	int opt_wait = 0;
	const char *opt_can = NULL;
	const char *opt_pin = NULL;
	const char *opt_puk = NULL;
	const char *opt_reader = NULL;
	int verbose = 0;
	int opt_change_pin = 0;
	int opt_resume = 0;
	int opt_unblock = 0;

	int err = 0;
	sc_context_t *ctx = NULL;
	sc_context_param_t ctx_param;
	sc_card_t *card = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	int c, rv;

	while ((c = getopt_long(argc, argv, "hr:wc:p:u:vCRU", options, (int *)0)) != -1) {
		switch (c) {
		case 'r':
			opt_reader = optarg;
			break;
		case 'w':
			opt_wait = 1;
			break;
		case 'c':
			util_get_pin(optarg, &opt_can);
			break;
		case 'p':
			util_get_pin(optarg, &opt_pin);
			break;
		case 'u':
			util_get_pin(optarg, &opt_puk);
			break;
		case 'v':
			verbose++;
			break;
		case 'C':
			opt_change_pin = 1;
			break;
		case 'R':
			opt_resume = 1;
			break;
		case 'U':
			opt_unblock = 1;
			break;
		case 'h':
		default:
			util_print_usage_and_die(app_name, options, option_help, NULL);
		}
	}

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.app_name = app_name;
	ctx_param.debug = verbose;
	if (verbose)
		ctx_param.debug_file = stderr;
	rv = sc_context_create(&ctx, &ctx_param);
	if (rv) {
		fprintf(stderr, "Error: Failed to establish context: %s\n", sc_strerror(rv));
		err = -1;
		goto lteid_tool_end;
	}

	if (util_connect_card(ctx, &card, opt_reader, opt_wait)) {
		fprintf(stderr, "Error: Cannot connect with card\n");
		err = -1;
		goto lteid_tool_end;
	}

	if (strcmp("lteid", card->driver->short_name) != 0) {
		fprintf(stderr, "Error: Card in the reader does not appear to be Lithuanian identity card.\n");
		err = -1;
		goto lteid_tool_end;
	}

	rv = sc_pkcs15_bind(card, NULL, &p15card);

	if (rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {
		printf("\nCAN number is not set/stored.\n\n");
		err = get_and_store_pace_can(card, opt_can);
		goto lteid_tool_end;
	}

	if (rv != SC_SUCCESS) {
		fprintf(stderr, "PKCS#15 binding failed: %s\n", sc_strerror(rv));
		err = -1;
		goto lteid_tool_end;
	}

	display_basic_details(p15card);

	if (opt_change_pin) {
		err = change_pin(card, opt_pin);
	} else if (opt_resume) {
		if (!opt_can) {
			opt_can = lteid_get_stored_can(card);
		}
		err = resume(p15card, opt_can, opt_pin);
	} else if (opt_unblock) {
		err = unblock_using_puk(p15card, opt_puk);
	}

lteid_tool_end:
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	sc_release_context(ctx);
	return err;
}
