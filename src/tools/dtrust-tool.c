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
	OPT_RESUME,
	OPT_UNBLOCK,
};

// clang-format off
static const struct option options[] = {
	{"reader", 1, NULL, 'r'},
	{"wait", 0, NULL, 'w'},
	{"verify-can", 0, NULL, OPT_CAN_VERIFY},
	{"pin-status", 0, NULL, 's'},
	{"check-transport-protection", 0, NULL, 'c'},
	{"unlock-transport-protection", 0, NULL, 'u'},
	{"resume-pin", 1, NULL, OPT_RESUME},
	{"unblock-pin", 1, NULL, OPT_UNBLOCK},
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
	"Resume suspended PIN",
	"Unblock blocked PIN",
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
static const char *opt_resume = NULL;
static const char *opt_unblock = NULL;

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

int
parse_pin(sc_card_t *card, const char *pinstr, const char *label, unsigned char *require_can)
{
	const char *valid = NULL;

	switch (card->type) {
	case SC_CARD_TYPE_DTRUST_V4_1_STD:
	case SC_CARD_TYPE_DTRUST_V4_1_MULTI:
	case SC_CARD_TYPE_DTRUST_V4_1_M100:
	case SC_CARD_TYPE_DTRUST_V4_4_STD:
	case SC_CARD_TYPE_DTRUST_V4_4_MULTI:
		valid = "PIN.CH, PUK.CH, PIN.T, PIN.QES";

		if (!strcasecmp(pinstr, "PIN.CH"))
			return DTRUST4_PIN_ID_PIN_CH;
		if (!strcasecmp(pinstr, "PUK.CH"))
			return DTRUST4_PIN_ID_PUK_CH;
		if (!strcasecmp(pinstr, "PIN.T"))
			return DTRUST4_PIN_ID_PIN_T;
		if (!strcasecmp(pinstr, "PIN.QES"))
			return DTRUST4_PIN_ID_QES;
		break;

	case SC_CARD_TYPE_DTRUST_V5_1_STD:
	case SC_CARD_TYPE_DTRUST_V5_1_MULTI:
	case SC_CARD_TYPE_DTRUST_V5_1_M100:
		valid = "PUK.CH, PIN.T, PIN.T.AUT, PIN.QES, PIN.AUT";

		if (!strcasecmp(pinstr, "PIN.T.AUT")) {
			return DTRUST5_PIN_ID_PIN_T_AUT;
		}
		if (!strcasecmp(pinstr, "PIN.AUT")) {
			if (require_can != NULL)
				*require_can = 1;
			return DTRUST5_PIN_ID_AUT;
		}
		/* fall through */

	case SC_CARD_TYPE_DTRUST_V5_4_STD:
	case SC_CARD_TYPE_DTRUST_V5_4_MULTI:
		if (valid == NULL)
			valid = "PUK.CH, PIN.T, PIN.QES";

		if (!strcasecmp(pinstr, "PUK.CH"))
			return PACE_PIN_ID_PUK;
		if (!strcasecmp(pinstr, "PIN.T"))
			return DTRUST5_PIN_ID_PIN_T;
		if (!strcasecmp(pinstr, "PIN.QES")) {
			if (require_can != NULL)
				*require_can = 1;
			return DTRUST5_PIN_ID_QES;
		}
		break;
	}

	fprintf(stderr, "%s PIN '%s' is invalid. Choose one from: %s\n", label, pinstr, valid);

	return -1;
}

void
pin_status(sc_card_t *card, int ref, const char *pin_label, unsigned char transport)
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
	else if (r == SC_ERROR_REF_DATA_NOT_USABLE) {
		if (transport)
			printf("%s: not usable (transport protection already broken)\n", pin_label);
		else
			printf("%s: not usable\n", pin_label);
	} else
		fprintf(stderr, "%s: status query failed (%s).\n", pin_label, sc_strerror(r));
}

int
check_transport_protection(sc_card_t *card, u8 ref, const char *pin_label)
{
	int r;
	struct sc_apdu apdu;
	u8 buf[6];
	u8 prot_intact[6] = {0xE3, 0x04, 0x90, 0x02, 0x00, 0x01};
	u8 prot_broken[6] = {0xE3, 0x04, 0x90, 0x02, 0x00, 0x00};

	r = sc_select_file(card, sc_get_mf_path(), NULL);
	if (r != SC_SUCCESS) {
		fprintf(stderr, "Check transport protection of %s: Unable to select master file (%s)\n", pin_label, sc_strerror(r));
		return -1;
	}

	sc_format_apdu_ex(&apdu, 0x80, 0xCA, 0x00, ref, NULL, 0, buf, sizeof(buf));

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS) {
		fprintf(stderr, "Check transport protection of %s: APDU transmit failed (%s)\n", pin_label, sc_strerror(r));
		return -1;
	}

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS) {
		/* Pin use counter may only be read out, if the retry counter
		 * is on its maximum value. In case of an error, the PIN has to
		 * be verified successfully first. */
		fprintf(stderr, "Check transport protection of %s: GET_DATA failed (%s)\n", pin_label, sc_strerror(r));
		return -1;
	}

	if (apdu.resplen == sizeof(prot_intact) && !memcmp(apdu.resp, prot_intact, 6)) {
		printf("Transport protection of %s is still intact.\n", pin_label);
		return 0;
	} else if (apdu.resplen == sizeof(prot_broken) && !memcmp(apdu.resp, prot_broken, 6)) {
		printf("Transport protection of %s is broken.\n", pin_label);
		return 1;
	}

	fprintf(stderr, "Check transport protection of %s: illegal response: ", pin_label);
	util_hex_dump(stderr, apdu.resp, apdu.resplen, " ");
	fprintf(stderr, "\n");

	return -1;
}

void
unlock_transport_protection4(sc_card_t *card)
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

void
unlock_transport_protection5(sc_card_t *card, int ref_pace, int ref_pin, const char *pathstr, const char *pin_label)
{
	int r;
	sc_path_t path;
	struct sc_pin_cmd_data data;
	char *tpin = NULL;
	char *newpin = NULL;
	int tries_left;

	printf("Unlocking %s\n", pin_label);

	/* Query all PINs at once */
	if (!(card->reader->capabilities & SC_READER_CAP_PACE_GENERIC)) {
		r = get_pin(&tpin, "Transport PIN", 0);
		if (r < 0)
			goto fail;
	}

	if (!(card->reader->capabilities & SC_READER_CAP_PIN_PAD)) {
		r = get_pin(&newpin, pin_label, 1);
		if (r < 0)
			goto fail;

		if (strlen(newpin) != 8) {
			fprintf(stderr, "Error. New PIN must be exactly 8 characters long.\n");
			goto fail;
		}
	}

	/* Authenticate via PACE */
	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_VERIFY;
	data.pin_type = SC_AC_CHV;
	data.pin_reference = ref_pace;

	if (card->reader->capabilities & SC_READER_CAP_PACE_GENERIC)
		printf("Enter Transport PIN on the readers pin pad now.\n");
	else {
		data.pin1.data = (u8 *)tpin;
		data.pin1.len = strlen(tpin);
	}

	r = sc_pin_cmd(card, &data, &tries_left);
	if (r) {
		fprintf(stderr, "Error verifying Transport PIN: %s\n", sc_strerror(r));
		if (tries_left >= 0)
			fprintf(stderr, "%d attempts left.\n", tries_left);
		goto fail;
	}

	/* Select application of the PIN */
	sc_format_path(pathstr, &path);
	r = sc_select_file(card, &path, NULL);
	if (r)
		goto fail;

	/* Change PIN */
	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_CHANGE;
	data.flags = SC_PIN_CMD_IMPLICIT_CHANGE;
	data.pin_type = SC_AC_CHV;
	data.pin_reference = ref_pin;
	data.pin2.min_length = 8;
	data.pin2.max_length = 8;

	if (card->reader->capabilities & SC_READER_CAP_PIN_PAD) {
		printf("Enter new %s on the readers pin pad now.\n", pin_label);
		data.pin2.prompt = pin_label;
		data.flags |= SC_PIN_CMD_USE_PINPAD;
	} else {
		data.pin2.data = (u8 *)newpin;
		data.pin2.len = strlen(newpin);
	}

	/* We only have one chance to set the new PIN. Once the Transport PIN
	 * is verified, it is not usable anymore. For pin pad readers we
	 * continue as long as the new PIN is set successfully or the user
	 * aborts the program and renders its card unusable as a consequence. */
	do {
		r = sc_pin_cmd(card, &data, NULL);
		if (r == SC_SUCCESS) {
			printf("Transport protection removed. You can now use your %s.\n", pin_label);
			break;
		}

		printf("Can't change pin: %s\n", sc_strerror(r));
	} while (card->reader->capabilities & SC_READER_CAP_PIN_PAD);

fail:
	if (newpin != NULL) {
		sc_mem_clear(newpin, strlen(newpin));
		free(newpin);
	}

	if (tpin != NULL) {
		sc_mem_clear(tpin, strlen(tpin));
		free(tpin);
	}
}

void
resume_pin(sc_card_t *card, int ref_pin)
{
	struct sc_pin_cmd_data data;
	char *pin = NULL;
	int r;

	memset(&data, 0, sizeof(struct sc_pin_cmd_data));

	data.cmd = SC_PIN_CMD_VERIFY;
	data.pin_type = SC_AC_CHV;
	data.pin_reference = ref_pin;

	switch (card->type) {
	case SC_CARD_TYPE_DTRUST_V5_1_STD:
	case SC_CARD_TYPE_DTRUST_V5_1_MULTI:
	case SC_CARD_TYPE_DTRUST_V5_1_M100:
	case SC_CARD_TYPE_DTRUST_V5_4_STD:
	case SC_CARD_TYPE_DTRUST_V5_4_MULTI:
		data.pin1.min_length = 8;
		data.pin1.max_length = 8;

		if (ref_pin == PACE_PIN_ID_PUK)
			break;

		/* Resuming a transport PIN leads to decreasing its use
		 * counter. Not performing the signature PIN changing procedure
		 * irectly after transport PIN verification would render the
		 * card useless. Thus we enforce the user to resume the PIN
		 * during the regular unlock procedure. */
		fprintf(stderr, "Invalid PIN to resume. Only the PUK can be resumed with this command.\n");
		fprintf(stderr, "To resume a transport PIN call this tool with --can and --unlock-transport-protection parameter.\n");
		return;

	default:
		fprintf(stderr, "This card does not support PINs which can be resumed.\n");
		return;
	}

	/* Suspended PIN always require a PACE authentication. */
	if (!(card->reader->capabilities & SC_READER_CAP_PACE_GENERIC)) {
		r = get_pin(&pin, "PIN to resume", 0);
		if (r < 0)
			goto fail;

		data.pin1.data = (const unsigned char *)pin;
		data.pin1.len = strlen(pin);
	}

	/* CAN was already verified by the caller at this point. We can
	 * directly verify the resumed PIN. */

	r = sc_select_file(card, sc_get_mf_path(), NULL);
	if (r) {
		fprintf(stderr, "Error selecting master application: %s\n", sc_strerror(r));
		goto fail;
	}

	r = sc_pin_cmd(card, &data, NULL);
	if (r) {
		fprintf(stderr, "Error resuming PIN: %s\n", sc_strerror(r));
		goto fail;
	}

fail:
	free(pin);
}

void
unblock_pin(sc_card_t *card, int ref_pin)
{
	struct sc_pin_cmd_data data_verify, data_unblock;
	const char *pathstr = "3F00";
	unsigned char pace = 0;
	char *puk = NULL;
	sc_path_t path;
	int r;
	int tries_left;

	memset(&data_verify, 0, sizeof(struct sc_pin_cmd_data));
	memset(&data_unblock, 0, sizeof(struct sc_pin_cmd_data));

	data_verify.cmd = SC_PIN_CMD_VERIFY;
	data_verify.pin_type = SC_AC_CHV;

	data_unblock.cmd = SC_PIN_CMD_UNBLOCK;
	data_unblock.pin_type = SC_AC_CHV;
	data_unblock.pin_reference = ref_pin;

	switch (card->type) {
	case SC_CARD_TYPE_DTRUST_V4_1_STD:
	case SC_CARD_TYPE_DTRUST_V4_1_MULTI:
	case SC_CARD_TYPE_DTRUST_V4_1_M100:
	case SC_CARD_TYPE_DTRUST_V4_4_STD:
	case SC_CARD_TYPE_DTRUST_V4_4_MULTI:
		data_verify.pin_reference = DTRUST4_PIN_ID_PUK_CH;
		data_verify.pin1.min_length = 8;
		data_verify.pin1.max_length = 12;

		if (ref_pin == DTRUST4_PIN_ID_QES)
			pathstr = "3F000101";

		if (ref_pin == DTRUST4_PIN_ID_PIN_CH ||
				ref_pin == DTRUST4_PIN_ID_PIN_T ||
				ref_pin == DTRUST4_PIN_ID_QES) {
			break;
		}

		fprintf(stderr, "Invalid unblock PIN. Only PIN.CH, PIN.T or PIN.QES may be unblocked.\n");
		return;

	case SC_CARD_TYPE_DTRUST_V5_1_STD:
	case SC_CARD_TYPE_DTRUST_V5_1_MULTI:
	case SC_CARD_TYPE_DTRUST_V5_1_M100:
	case SC_CARD_TYPE_DTRUST_V5_4_STD:
	case SC_CARD_TYPE_DTRUST_V5_4_MULTI:
		pace = 1;
		data_verify.pin_reference = PACE_PIN_ID_PUK;
		data_verify.pin1.min_length = 8;
		data_verify.pin1.max_length = 8;

		if (ref_pin == DTRUST5_PIN_ID_QES)
			pathstr = "3F000101";
		else if (ref_pin == DTRUST5_PIN_ID_AUT)
			pathstr = "3F000102";

		if (ref_pin == DTRUST5_PIN_ID_PIN_T ||
				ref_pin == DTRUST5_PIN_ID_PIN_T_AUT ||
				ref_pin == DTRUST5_PIN_ID_QES ||
				ref_pin == DTRUST5_PIN_ID_AUT) {
			break;
		}

		fprintf(stderr, "Invalid unblock PIN. Only PIN.T, PIN.T.AUT, PIN.QES or PIN.AUT may be unblocked.\n");
		return;

	default:
		return;
	}

	if ((card->reader->capabilities & SC_READER_CAP_PIN_PAD) && !pace) {
		data_verify.flags |= SC_PIN_CMD_USE_PINPAD;
	} else if (!(card->reader->capabilities & SC_READER_CAP_PACE_GENERIC) || !pace) {
		r = get_pin(&puk, "PUK", 0);
		if (r < 0)
			goto fail;

		data_verify.pin1.data = (const unsigned char *)puk;
		data_verify.pin1.len = strlen(puk);
	}

	sc_format_path(pathstr, &path);

	r = sc_select_file(card, pace ? sc_get_mf_path() : &path, NULL);
	if (r) {
		fprintf(stderr, "Error selecting application: %s\n", sc_strerror(r));
		goto fail;
	}

	r = sc_pin_cmd(card, &data_verify, &tries_left);
	if (r) {
		fprintf(stderr, "Error verifying PUK: %s\n", sc_strerror(r));
		if (tries_left >= 0)
			fprintf(stderr, "%d attempts left.\n", tries_left);
		goto fail;
	}

	if (!pace) {
		r = sc_select_file(card, &path, NULL);
		if (r) {
			fprintf(stderr, "Error selecting application: %s\n", sc_strerror(r));
			goto fail;
		}
	}

	r = sc_pin_cmd(card, &data_unblock, NULL);
	if (r) {
		fprintf(stderr, "Error unblocking PIN: %s\n", sc_strerror(r));
		goto fail;
	}

fail:
	free(puk);
}

int
main(int argc, char *argv[])
{
	int r, c, long_optind = 0;
	char *can = NULL;
	sc_context_param_t ctx_param;
	sc_card_t *card = NULL;
	sc_context_t *ctx = NULL;
	int pin_resume = -1;
	int pin_unblock = -1;
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
		case OPT_RESUME:
			opt_resume = optarg;
			break;
		case OPT_UNBLOCK:
			opt_unblock = optarg;
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
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}

	r = sc_set_card_driver(ctx, "dtrust");
	if (r) {
		fprintf(stderr, "Driver 'dtrust' not found!\n");
		goto out;
	}

	r = util_connect_card(ctx, &card, opt_reader, opt_wait);
	if (r)
		goto out;

	if (opt_status || opt_check)
		opt_can_verify = 1;

	if (opt_resume != NULL) {
		opt_can_verify = 1;
		pin_resume = parse_pin(card, opt_resume, "Resume", NULL);
		if (pin_resume < 0)
			goto out;
	}

	if (opt_unblock != NULL) {
		pin_unblock = parse_pin(card, opt_unblock, "Unblock", NULL);
		if (pin_unblock < 0)
			goto out;
	}

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

	if (opt_status) {
		switch (card->type) {
		case SC_CARD_TYPE_DTRUST_V4_1_STD:
		case SC_CARD_TYPE_DTRUST_V4_1_MULTI:
		case SC_CARD_TYPE_DTRUST_V4_1_M100:
			pin_status(card, DTRUST4_PIN_ID_PIN_CH, "Card Holder PIN", 0);
			/* fall through */

		case SC_CARD_TYPE_DTRUST_V4_4_STD:
		case SC_CARD_TYPE_DTRUST_V4_4_MULTI:
			/* We have to select the QES app to verify and change the Signature PIN. */
			sc_format_path("3F000101", &path);
			r = sc_select_file(card, &path, NULL);
			if (r)
				goto out;

			pin_status(card, DTRUST4_PIN_ID_PUK_CH, "Card Holder PUK", 0);
			pin_status(card, DTRUST4_PIN_ID_QES, "Signature PIN", 0);

			/* According to the spec, the local bit has to be set. */
			pin_status(card, 0x80 | DTRUST4_PIN_ID_PIN_T, "Transport PIN", 1);
			break;

		case SC_CARD_TYPE_DTRUST_V5_1_STD:
		case SC_CARD_TYPE_DTRUST_V5_1_MULTI:
		case SC_CARD_TYPE_DTRUST_V5_1_M100:
			r = sc_select_file(card, sc_get_mf_path(), NULL);
			if (r)
				goto out;

			pin_status(card, DTRUST5_PIN_ID_PIN_T_AUT, "Transport PIN (Authentication)", 1);

			/* We have to select the eSign app to verify and change the Authentication PIN. */
			sc_format_path("3F000102", &path);
			r = sc_select_file(card, &path, NULL);
			if (r)
				goto out;

			pin_status(card, DTRUST5_PIN_ID_AUT, "Authentication PIN", 0);
			/* fall through */

		case SC_CARD_TYPE_DTRUST_V5_4_STD:
		case SC_CARD_TYPE_DTRUST_V5_4_MULTI:
			r = sc_select_file(card, sc_get_mf_path(), NULL);
			if (r)
				goto out;

			pin_status(card, PACE_PIN_ID_PUK, "Card Holder PUK", 0);
			pin_status(card, DTRUST5_PIN_ID_PIN_T, "Transport PIN (Signature)", 1);

			/* We have to select the QES app to verify and change the Signature PIN. */
			sc_format_path("3F000101", &path);
			r = sc_select_file(card, &path, NULL);
			if (r)
				goto out;

			pin_status(card, DTRUST5_PIN_ID_QES, "Signature PIN", 0);
			break;
		}
	}

	if (opt_check) {
		switch (card->type) {
		case SC_CARD_TYPE_DTRUST_V4_1_STD:
		case SC_CARD_TYPE_DTRUST_V4_1_MULTI:
		case SC_CARD_TYPE_DTRUST_V4_1_M100:
		case SC_CARD_TYPE_DTRUST_V4_4_STD:
		case SC_CARD_TYPE_DTRUST_V4_4_MULTI:
			check_transport_protection(card, DTRUST4_PIN_ID_PIN_T, "Signature PIN");
			break;

		case SC_CARD_TYPE_DTRUST_V5_1_STD:
		case SC_CARD_TYPE_DTRUST_V5_1_MULTI:
		case SC_CARD_TYPE_DTRUST_V5_1_M100:
			check_transport_protection(card, DTRUST5_PIN_ID_PIN_T_AUT, "Authentication PIN");
			/* fall through */

		case SC_CARD_TYPE_DTRUST_V5_4_STD:
		case SC_CARD_TYPE_DTRUST_V5_4_MULTI:
			check_transport_protection(card, DTRUST5_PIN_ID_PIN_T_AUT, "Signature PIN");
			break;
		}
	}

	if (opt_unlock) {
		/* Warn the user he must not abort the unlocking process on
		 * pin pad readers, as the transport pin has already been used
		 * and there is no next attempt. */
		if (card->reader->capabilities & SC_READER_CAP_PIN_PAD &&
				card->type >= SC_CARD_TYPE_DTRUST_V5_1_STD &&
				card->type <= SC_CARD_TYPE_DTRUST_V5_4_MULTI) {
			printf("\n");
			printf("CAUTION.\n");
			printf("\n");
			printf("You are about to remove the transport protection. After entering the transport\n");
			printf("PIN, don't abort the program! Otherwise your card becomes irrecoverably unusable.\n");
			printf("In case of an error, continue to enter your PIN as long as you reader accepts\n");
			printf("it. The new PIN must be exactly 8 characters long.\n");
			printf("\n");
			printf("If in doubt, cancel now and try to unlock your card in a card reader without a\n");
			printf("pin pad. Then all, your inputs will be validated before unlocking the card.\n");
			printf("\n");
			printf("Enter 'yes' to continue.\n");

#ifndef _WIN32
			ssize_t ret;
			char *str = NULL;
			size_t len = 0;

			ret = getline(&str, &len, stdin);
			if (ret >= 0)
				ret = strcmp(str, "yes\n");
			free(str);

			if (ret)
				goto out;
#else
			char str[8];
			char *ret;

			ret = fgets(str, 8, stdin);
			if (ret == NULL || strcmp(ret, "yes\n"))
				goto out;
#endif
		}

		switch (card->type) {
		case SC_CARD_TYPE_DTRUST_V4_1_STD:
		case SC_CARD_TYPE_DTRUST_V4_1_MULTI:
		case SC_CARD_TYPE_DTRUST_V4_1_M100:
		case SC_CARD_TYPE_DTRUST_V4_4_STD:
		case SC_CARD_TYPE_DTRUST_V4_4_MULTI:
			r = check_transport_protection(card, DTRUST4_PIN_ID_PIN_T, "Signature PIN");
			if (r)
				printf("Cannot remove transport protection of Signature PIN.\n");
			else
				unlock_transport_protection4(card);
			break;

		case SC_CARD_TYPE_DTRUST_V5_1_STD:
		case SC_CARD_TYPE_DTRUST_V5_1_MULTI:
		case SC_CARD_TYPE_DTRUST_V5_1_M100:
			r = check_transport_protection(card, DTRUST5_PIN_ID_PIN_T_AUT, "Authentication PIN");
			if (r)
				printf("Cannot remove transport protection of Authentication PIN.\n");
			else {
				unlock_transport_protection5(card, DTRUST5_PIN_ID_PIN_T_AUT, DTRUST5_PIN_ID_AUT, "3F000102", "Authentication PIN");
			}
			/* fall through */

		case SC_CARD_TYPE_DTRUST_V5_4_STD:
		case SC_CARD_TYPE_DTRUST_V5_4_MULTI:
			r = check_transport_protection(card, DTRUST5_PIN_ID_PIN_T, "Signature PIN");
			if (r)
				printf("Cannot remove transport protection of Signature PIN.\n");
			else {
				unlock_transport_protection5(card, DTRUST5_PIN_ID_PIN_T, DTRUST5_PIN_ID_QES, "3F000101", "Signature PIN");
			}
			break;
		}
	} else if (opt_resume != NULL) {
		resume_pin(card, pin_resume);
	} else if (opt_unblock != NULL) {
		unblock_pin(card, pin_unblock);
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
