/*
 * dtrust-tool.c: tool for D-Trust cards
 *
 * Copyright (C) 2024 mario.haustein@hrz.tu-chemnitz.de
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

#include "config.h"

#include <stdio.h>
#include <string.h>

#include "libopensc/opensc.h"

#include "libopensc/card-dtrust.h"
#include "libopensc/cards.h"
#include "libopensc/errors.h"

#include "sm/sm-eac.h"
#include "util.h"

static const char *app_name = "dtrust-tool";

enum {
	OPT_CAN_VERIFY = 0x100,
};

// clang-format off
static const struct option options[] = {
	{"reader", 1, NULL, 'r'},
	{"wait", 0, NULL, 'w'},
	{"verify-can", 0, NULL, OPT_CAN_VERIFY},
	{"pin-status", 0, NULL, 's'},
	{"check-transport-protection", 0, NULL, 'c'},
	{"unlock-transport-protection", 0, NULL, 'u'},
	{"help", 0, NULL, 'h'},
	{"verbose", 0, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

static const char *option_help[] = {
	"Uses reader number <arg> [0]",
	"Wait for card insertion",
	"Verify Card Access Number (CAN)",
	"Show PIN status",
	"Check transport protection",
	"Unlock transport protection",
	"This message",
	"Verbose operation, may be used several times",
};
// clang-format on

static const char *opt_reader = NULL;
static int opt_wait = 0, verbose = 0;
static unsigned char opt_can_verify = 0;
static int opt_status = 0;
static int opt_check = 0;
static int opt_unlock = 0;

int
get_pin(char **pin, const char *label, unsigned char check)
{
	int r;
	char *pin2 = NULL;
	size_t len1 = 0;
	size_t len2 = 0;

	r = -1;

	if (pin == NULL)
		return -1;

	*pin = NULL;

	printf("Enter %s:", label);
	r = util_getpass(pin, &len1, stdin);
	if (r < 0 || *pin == NULL) {
		fprintf(stderr, "Unable to get PIN");
		goto fail;
	}

	if (!check)
		return 0;

	printf("Enter %s again:", label);
	r = util_getpass(&pin2, &len2, stdin);
	if (r < 0 || pin2 == NULL) {
		fprintf(stderr, "Unable to get PIN");
		goto fail;
	}

	r = strcmp(*pin, pin2);
	if (r)
		fprintf(stderr, "PINs doesn't match.\n");

	/* Free repeated PIN in any case. */
	if (pin2 != NULL) {
		sc_mem_clear(pin2, len2);
		free(pin2);
	}

	if (r == 0)
		return 0;

fail:
	/* Free PIN only in case of an error. */
	if (*pin != NULL) {
		sc_mem_clear(*pin, len1);
		free(*pin);
		*pin = NULL;
	}

	return -1;
}

void
pin_status(sc_card_t *card, int ref, const char *pin_label)
{
	int r;
	struct sc_pin_cmd_data data;
	int tries_left = 0;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_GET_INFO;
	data.pin_type = SC_AC_CHV;
	data.pin_reference = ref;

	r = sc_pin_cmd(card, &data, &tries_left);

	if (r == SC_SUCCESS) {
		if (tries_left < 0)
			printf("%s: usable\n", pin_label);
		else
			printf("%s: usable (%d tries left)\n", pin_label, tries_left);
	} else if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
		printf("%s: not usable (transport protection still in force)\n", pin_label);
	else if (r == SC_ERROR_AUTH_METHOD_BLOCKED)
		printf("%s: blocked (use PUK to unblock PIN)\n", pin_label);
	else if (r == SC_ERROR_REF_DATA_NOT_USABLE)
		printf("%s: not usable (transport protection already broken)\n", pin_label);
	else
		fprintf(stderr, "%s: status query failed (%s).\n", pin_label, sc_strerror(r));
}

int
check_transport_protection(sc_card_t *card)
{
	struct sc_apdu apdu;
	int r;
	u8 buf[6];
	u8 prot_intact[6] = {0xE3, 0x04, 0x90, 0x02, 0x00, 0x01};
	u8 prot_broken[6] = {0xE3, 0x04, 0x90, 0x02, 0x00, 0x00};

	sc_format_apdu_ex(&apdu, 0x80, 0xCA, 0x00, 0x0B, NULL, 0, buf, sizeof(buf));

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS) {
		fprintf(stderr, "Check transport protection: APDU transmit failed (%s)\n", sc_strerror(r));
		return -1;
	}

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS) {
		fprintf(stderr, "Check transport protection: GET_DATA failed (%s)\n", sc_strerror(r));
		return -1;
	}

	if (apdu.resplen == sizeof(prot_intact) && !memcmp(apdu.resp, prot_intact, 6)) {
		printf("Transport protection is still intact.\n");
		return 0;
	} else if (apdu.resplen == sizeof(prot_broken) && !memcmp(apdu.resp, prot_broken, 6)) {
		printf("Transport protection is broken.\n");
		return 1;
	}

	fprintf(stderr, "Check transport protection: illegal response: ");
	util_hex_dump(stderr, apdu.resp, apdu.resplen, " ");
	fprintf(stderr, "\n");

	return -1;
}

void
unlock_transport_protection(sc_card_t *card)
{
	struct sc_pin_cmd_data data;
	int r;
	char *tpin = NULL;
	char *qespin = NULL;
	int tries_left;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_CHANGE;
	data.pin_type = SC_AC_CHV;
	data.pin_reference = DTRUST4_PIN_ID_QES;
	data.pin1.min_length = 5;
	data.pin1.max_length = 5;
	data.pin2.min_length = 6;
	data.pin2.max_length = 12;

	if (card->reader->capabilities & SC_READER_CAP_PIN_PAD) {
		printf("Please enter PINs on the reader's pin pad.\n");
		data.pin1.prompt = "Enter Transport PIN";
		data.pin2.prompt = "Enter Signature PIN";
		data.flags |= SC_PIN_CMD_USE_PINPAD;
	} else {
		r = get_pin(&tpin, "Transport PIN", 0);
		if (r < 0)
			goto fail;

		r = get_pin(&qespin, "new Signature PIN", 1);
		if (r < 0)
			goto fail;

		data.pin1.data = (u8 *)tpin;
		data.pin1.len = strlen(tpin);
		data.pin2.data = (u8 *)qespin;
		data.pin2.len = strlen(qespin);
	}

	r = sc_pin_cmd(card, &data, &tries_left);

	if (r == SC_SUCCESS)
		printf("Transport protection removed. You can now use your Signature PIN.\n");
	else if (r == SC_ERROR_PIN_CODE_INCORRECT)
		printf("Wrong pin. %d attempts left.\n", tries_left);
	else
		printf("Can't change pin: %s\n", sc_strerror(r));

fail:
	if (qespin != NULL) {
		sc_mem_clear(qespin, strlen(qespin));
		free(qespin);
	}

	if (tpin != NULL) {
		sc_mem_clear(tpin, strlen(tpin));
		free(tpin);
	}
}

int
main(int argc, char *argv[])
{
	int r, c, long_optind = 0;
	char *can = NULL;
	sc_context_param_t ctx_param;
	sc_card_t *card = NULL;
	sc_context_t *ctx = NULL;
	sc_path_t path;

	while (1) {
		c = getopt_long(argc, argv, "r:wscuhv", options, &long_optind);

		if (c == -1)
			break;

		if (c == '?' || c == 'h')
			util_print_usage_and_die(app_name, options, option_help, NULL);

		switch (c) {
		case 'r':
			opt_reader = optarg;
			break;
		case 'w':
			opt_wait = 1;
			break;
		case OPT_CAN_VERIFY:
			opt_can_verify = 1;
			break;
		case 's':
			opt_status = 1;
			break;
		case 'c':
			opt_check = 1;
			break;
		case 'u':
			opt_unlock = 1;
			break;
		case 'v':
			verbose++;
			break;
		}
	}

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver = 0;
	ctx_param.app_name = argv[0];
	ctx_param.debug = verbose;
	if (verbose)
		ctx_param.debug_file = stderr;

	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		printf("Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}

	r = sc_set_card_driver(ctx, "dtrust");
	if (r) {
		printf("Driver 'dtrust' not found!\n");
		goto out;
	}

	r = util_connect_card(ctx, &card, opt_reader, opt_wait);
	if (r)
		goto out;

	if (opt_status || opt_check)
		opt_can_verify = 1;

	/* D-Trust Card 5 requires PACE authentication with CAN */
	if (opt_can_verify &&
			card->type >= SC_CARD_TYPE_DTRUST_V5_1_STD &&
			card->type <= SC_CARD_TYPE_DTRUST_V5_4_MULTI) {
		struct sc_pin_cmd_data data;

		memset(&data, 0, sizeof(data));
		data.cmd = SC_PIN_CMD_VERIFY;
		data.pin_type = SC_AC_CHV;
		data.pin_reference = PACE_PIN_ID_CAN;

		if (card->reader->capabilities & SC_READER_CAP_PACE_GENERIC) {
			data.pin1.data = NULL;
			data.pin1.len = 0;
		} else {
			r = get_pin(&can, "CAN", 0);
			if (r < 0)
				goto out;

			data.pin1.data = (const unsigned char *)can;
			data.pin1.len = strlen(can);
		}

		r = sc_select_file(card, sc_get_mf_path(), NULL);
		if (r)
			goto out;

		r = sc_pin_cmd(card, &data, NULL);
		if (r) {
			fprintf(stderr, "Error verifying CAN.\n");
			goto out;
		}
	}

	/*
	 * We have to select the QES app to verify and change the QES PIN.
	 */
	sc_format_path("3F000101", &path);
	r = sc_select_file(card, &path, NULL);
	if (r)
		goto out;

	if (opt_status) {
		if (card->type == SC_CARD_TYPE_DTRUST_V4_1_STD ||
				card->type == SC_CARD_TYPE_DTRUST_V4_1_MULTI ||
				card->type == SC_CARD_TYPE_DTRUST_V4_1_M100)
			pin_status(card, DTRUST4_PIN_ID_PIN_CH, "Card Holder PIN");
		pin_status(card, DTRUST4_PIN_ID_PUK_CH, "Card Holder PUK");
		pin_status(card, DTRUST4_PIN_ID_QES, "Signature PIN");

		/* According to the spec, the local bit has to be set. */
		pin_status(card, 0x80 | DTRUST4_PIN_ID_PIN_T, "Transport PIN");
	}

	if (opt_check)
		check_transport_protection(card);

	if (opt_unlock) {
		r = check_transport_protection(card);
		if (r)
			printf("Cannot remove transport protection.\n");
		else
			unlock_transport_protection(card);
	}

out:
	if (can != NULL) {
		sc_mem_clear(can, strlen(can));
		free(can);
	}

	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}

	sc_release_context(ctx);

	return EXIT_SUCCESS;
}
