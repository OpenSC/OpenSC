/*
 * Copyright (C) 2010-2018 Frank Morgner <frankmorgner@gmail.com>
 *
 * This file is part of OpenSC.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_OPENPACE
#include "fread_to_eof.h"
#include "npa-tool-cmdline.h"
#include "sm/sm-eac.h"
#include "sm/sslutil.h"
#include "util.h"
#include <eac/pace.h>
#include <libopensc/card-npa.h>
#include <libopensc/log.h>
#include <libopensc/opensc.h>
#include <libopensc/sm.h>
#include <sm/sm-eac.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
/* only implement what we are using in this file */
struct timeval {
	unsigned int tv_sec;
	unsigned int tv_usec;
};
int gettimeofday(struct timeval *tv, struct timezone *tz)
{
#ifdef _WIN32
	SYSTEMTIME st;
	GetLocalTime(&st);
	if (!tv)
		return -1;
	tv->tv_sec = st.wSecond;
	tv->tv_usec = st.wMilliseconds*1000;
#else
	tv->tv_sec = 0;
	tv->tv_usec = 0;
#endif
	return 0;
}
#endif

#ifndef HAVE_GETLINE
static int getline(char **lineptr, size_t *n, FILE *stream)
{
	char *p;

	if (!lineptr)
		return -1;

	p = realloc(*lineptr, SC_MAX_EXT_APDU_BUFFER_SIZE*3);
	if (!p)
		return -1;
	*lineptr = p;

	if (fgets(p, SC_MAX_EXT_APDU_BUFFER_SIZE*3, stream) == NULL)
		return -1;

	return strlen(p);
}
#endif

/* we don't want to export this from libopensc so we implement it here, again */
#include <openssl/asn1t.h>

#define ASN1_APP_IMP_OPT(stname, field, type, tag) ASN1_EX_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION|ASN1_TFLG_OPTIONAL, tag, stname, field, type)
#define ASN1_APP_IMP(stname, field, type, tag) ASN1_EX_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION, tag, stname, field, type)

typedef ASN1_AUXILIARY_DATA ASN1_AUXILIARY_DATA_NPA_TOOL;
/* 0x67
 * Auxiliary authenticated data */
ASN1_ITEM_TEMPLATE(ASN1_AUXILIARY_DATA_NPA_TOOL) = 
	ASN1_EX_TEMPLATE_TYPE(
			ASN1_TFLG_SEQUENCE_OF|ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
			7, AuxiliaryAuthenticatedData, CVC_DISCRETIONARY_DATA_TEMPLATE)
ASN1_ITEM_TEMPLATE_END(ASN1_AUXILIARY_DATA_NPA_TOOL)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_AUXILIARY_DATA_NPA_TOOL)

/** 
 * @brief Print binary data to a file stream
 * 
 * @param[in] file  File for printing
 * @param[in] label Label to prepend to the buffer
 * @param[in] data  Binary data
 * @param[in] len   Length of \a data
 */
#define bin_print(file, label, data, len) { \
	fprintf(file, "%s (%u byte%s)%s%s\n", \
			label, (unsigned int) len, len==1?"":"s", len==0?"":":\n", sc_dump_hex(data, len)); \
	}

static const char *app_name = "npa-tool";

static void read_dg(sc_card_t *card, unsigned char sfid, const char *dg_str,
		unsigned char **dg, size_t *dg_len)
{
	int r = iso7816_read_binary_sfid(card, sfid, dg, dg_len);
	if (r < 0)
		fprintf(stderr, "Coult not read DG %02u %s (%s)\n",
				sfid, dg_str, sc_strerror(r));
	else {
		char buf[0x200];
		sc_hex_dump(*dg, *dg_len, buf, sizeof buf);
		fprintf(stdout, "Read %s", buf);
	}
}

static void write_dg(sc_card_t *card, unsigned char sfid, const char *dg_str,
		const char *dg_hex)
{
	unsigned char dg[0xff];
	size_t dg_len = sizeof dg;
	int r;

	r = sc_hex_to_bin(dg_hex, dg, &dg_len);
	if (r < 0) {
		fprintf(stderr, "Could not parse DG %02u %s (%s)\n",
				sfid, dg_str, sc_strerror(r));
	} else {
		r = iso7816_write_binary_sfid(card, sfid, dg, dg_len);
		if (r < 0)
			fprintf(stderr, "Could not write DG %02u %s (%s)\n",
					sfid, dg_str, sc_strerror(r));
		else
			printf("Wrote DG %02u %s\n", sfid, dg_str);
	}
}

#define ISO_VERIFY 0x20
static void verify(sc_card_t *card, const char *verify_str,
		unsigned char *data, size_t data_len)
{
	sc_apdu_t apdu;
	int r;

	sc_format_apdu_ex(&apdu, 0x00, ISO_VERIFY, 0x80, 0, data, data_len, NULL, 0);
	apdu.cla = 0x80;

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		fprintf(stderr, "Coult not verify %s (%s)\n",
				verify_str, sc_strerror(r));
	else
		printf("Verified %s\n", verify_str);
}

int npa_translate_apdus(sc_card_t *card, FILE *input)
{
	u8 buf[4 + 3 + 0xffff + 3];
	char *read = NULL;
	size_t readlen = 0, apdulen;
	sc_apdu_t apdu;
	int linelen;
	int r;

	memset(&apdu, 0, sizeof apdu);

	while (1) {
		if (input == stdin)
			printf("Enter unencrypted C-APDU (empty line to exit)\n");

		linelen = getline(&read, &readlen, input);
		if (linelen <= 1) {
			if (linelen < 0) {
				r = SC_ERROR_INTERNAL;
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
						"Could not read line");
			} else {
				r = SC_SUCCESS;
				printf("Thanks for flying with ccid\n");
			}
			break;
		}
		read[linelen - 1] = 0;

		apdulen = sizeof buf;
		if (sc_hex_to_bin(read, buf, &apdulen) < 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
					"Could not format binary string");
			continue;
		}
		if (input != stdin)
			bin_print(stdout, "Unencrypted C-APDU", buf, apdulen);

		r = sc_bytes2apdu(card->ctx, buf, apdulen, &apdu);
		if (r < 0) {
			sc_log_hex(card->ctx, "Invalid C-APDU", buf, apdulen);
			continue;
		}

		apdu.resp = buf;
		apdu.resplen = sizeof buf;

		r = sc_transmit_apdu(card, &apdu);
		if (r < 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
					"Could not send C-APDU: %s", sc_strerror(r));
			continue;
		}

		printf("Decrypted R-APDU sw1=%02x sw2=%02x\n", apdu.sw1, apdu.sw2);
		bin_print(stdout, "Decrypted R-APDU response data", apdu.resp, apdu.resplen);
		printf("======================================================================\n");
	}

	if (read)
		free(read);

	return r;
}

static int add_to_ASN1_AUXILIARY_DATA_NPA_TOOL(
		ASN1_AUXILIARY_DATA_NPA_TOOL **auxiliary_data,
		int nid, const unsigned char *data, size_t data_len)
{
	int r;
	CVC_DISCRETIONARY_DATA_TEMPLATE *template = NULL;

	if (!auxiliary_data) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	if (!*auxiliary_data) {
		*auxiliary_data = ASN1_AUXILIARY_DATA_NPA_TOOL_new();
		if (!*auxiliary_data) {
			r = SC_ERROR_INTERNAL;
			goto err;
		}
	}

	template = CVC_DISCRETIONARY_DATA_TEMPLATE_new();
	if (!template) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	template->type = OBJ_nid2obj(nid);
	if (!template->type) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	if (data && data_len) {
		template->discretionary_data3 = ASN1_OCTET_STRING_new();
		if (!template->discretionary_data3
				|| !ASN1_OCTET_STRING_set(
					template->discretionary_data3, data, data_len)) {
			r = SC_ERROR_INTERNAL;
			goto err;
		}
	}

	if (!sk_push((_STACK*) (*auxiliary_data), template)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	r = SC_SUCCESS;

err:
	return r;
}

int
main (int argc, char **argv)
{
	const char *newpin = NULL;
	const char *pin = NULL;
	const char *puk = NULL;
	const char *can = NULL;
	const char *mrz = NULL;

	unsigned char chat[0xff];
	unsigned char desc[0xffff];
	unsigned char **certs = NULL;
	size_t *certs_lens = NULL;
	unsigned char *privkey = NULL;
	size_t privkey_len = 0;
	unsigned char auxiliary_data[0xff];
	size_t auxiliary_data_len = 0;
	unsigned char community_id[0xf];
	size_t community_id_len = 0;

	sc_context_t *ctx = NULL;
	sc_card_t *card = NULL;
	sc_context_param_t ctx_param;

	int r, tr_version = EAC_TR_VERSION_2_02;
	struct establish_pace_channel_input pace_input;
	struct establish_pace_channel_output pace_output;
	struct timeval tv;
	size_t i;
	FILE *input = NULL;
	CVC_CERT *cvc_cert = NULL;
	unsigned char *certs_chat = NULL;
	unsigned char *dg = NULL;
	size_t dg_len = 0;
	ASN1_AUXILIARY_DATA_NPA_TOOL *templates = NULL;
	unsigned char *ef_cardsecurity = NULL;
	size_t ef_cardsecurity_len = 0;

	struct gengetopt_args_info cmdline;

	memset(&pace_input, 0, sizeof pace_input);
	memset(&pace_output, 0, sizeof pace_output);


	/* Parse command line */
	if (cmdline_parser (argc, argv, &cmdline) != 0)
		exit(1);
	if (cmdline.env_flag) {
		can = getenv("CAN");
		mrz = getenv("MRZ");
		pin = getenv("PIN");
		puk = getenv("PUK");
		newpin = getenv("NEWPIN");
	} else {
		can = cmdline.can_arg;
		mrz = cmdline.mrz_arg;
		pin = cmdline.pin_arg;
		puk = cmdline.puk_arg;
		newpin = cmdline.new_pin_arg;
	}
	if (cmdline.chat_given) {
		pace_input.chat = chat;
		pace_input.chat_length = sizeof chat;
		if (sc_hex_to_bin(cmdline.chat_arg, (u8 *) pace_input.chat,
					&pace_input.chat_length) < 0) {
			fprintf(stderr, "Could not parse CHAT.\n");
			exit(2);
		}
	}
	if (cmdline.cert_desc_given) {
		pace_input.certificate_description = desc;
		pace_input.certificate_description_length = sizeof desc;
		if (sc_hex_to_bin(cmdline.cert_desc_arg,
					(u8 *) pace_input.certificate_description,
					&pace_input.certificate_description_length) < 0) {
			fprintf(stderr, "Could not parse certificate description.\n");
			exit(2);
		}
	}
	if (cmdline.tr_03110v201_flag)
		tr_version = EAC_TR_VERSION_2_01;
	if (cmdline.disable_all_checks_flag)
		eac_default_flags |= EAC_FLAG_DISABLE_CHECK_ALL;
	if (cmdline.disable_ta_checks_flag)
		eac_default_flags |= EAC_FLAG_DISABLE_CHECK_TA;
	if (cmdline.disable_ca_checks_flag)
		eac_default_flags |= EAC_FLAG_DISABLE_CHECK_CA;


	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;

	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		exit(1);
	}

    r = sc_set_card_driver(ctx, "default");
	if (r)
		goto err;

	r = util_connect_card_ex(ctx, &card, cmdline.reader_arg, 0, 0, cmdline.verbose_given);
	if (r)
		goto err;

	EAC_init();
	if (cmdline.cvc_dir_given)
		EAC_set_cvc_default_dir(cmdline.cvc_dir_arg);
	if (cmdline.x509_dir_given)
		EAC_set_x509_default_dir(cmdline.x509_dir_arg);

	if (cmdline.break_flag) {
		/* The biggest number sprintf could write with "%llu is 18446744073709551615 */
		char secretbuf[21];
		unsigned long long secret = 0;
		unsigned long long maxsecret = 0;

		if (cmdline.pin_given) {
			pace_input.pin_id = PACE_PIN;
			pace_input.pin_length = 6;
			maxsecret = 999999;
			if (pin) {
				if (sscanf(pin, "%llu", &secret) != 1) {
					fprintf(stderr, "%s is not an unsigned long long.\n",
							eac_secret_name(pace_input.pin_id));
					exit(2);
				}
				if (strlen(pin) > pace_input.pin_length) {
					fprintf(stderr, "%s too big, only %u digits allowed.\n",
							eac_secret_name(pace_input.pin_id),
							(unsigned int) pace_input.pin_length);
					exit(2);
				}
			}
		} else if (cmdline.can_given) {
			pace_input.pin_id = PACE_CAN;
			pace_input.pin_length = 6;
			maxsecret = 999999;
			if (can) {
				if (sscanf(can, "%llu", &secret) != 1) {
					fprintf(stderr, "%s is not an unsigned long long.\n",
							eac_secret_name(pace_input.pin_id));
					exit(2);
				}
				if (strlen(can) > pace_input.pin_length) {
					fprintf(stderr, "%s too big, only %u digits allowed.\n",
							eac_secret_name(pace_input.pin_id),
							(unsigned int) pace_input.pin_length);
					exit(2);
				}
			}
		} else if (cmdline.puk_given) {
			pace_input.pin_id = PACE_PUK;
			pace_input.pin_length = 10;
			maxsecret = 9999999999;
			if (puk) {
				if (sscanf(puk, "%llu", &secret) != 1) {
					fprintf(stderr, "%s is not an unsigned long long.\n",
							eac_secret_name(pace_input.pin_id));
					exit(2);
				}
				if (strlen(puk) > pace_input.pin_length) {
					fprintf(stderr, "%s too big, only %u digits allowed.\n",
							eac_secret_name(pace_input.pin_id),
							(unsigned int) pace_input.pin_length);
					exit(2);
				}
			}
		} else {
			fprintf(stderr, "Please specify whether to do PACE with "
					"PIN, CAN or PUK.\n");
			exit(1);
		}

		pace_input.pin = (unsigned char *) secretbuf;

		do {
			sprintf(secretbuf, "%0*llu", (unsigned int) pace_input.pin_length, secret);

			gettimeofday(&tv, NULL);
			printf("%u,%06u: Trying %s=%s\n",
					(unsigned int) tv.tv_sec, (unsigned int) tv.tv_usec,
					eac_secret_name(pace_input.pin_id), pace_input.pin);

			r = perform_pace(card, pace_input, &pace_output, tr_version);

			secret++;
		} while (0 > r && secret <= maxsecret);

		gettimeofday(&tv, NULL);
		if (0 > r) {
			printf("%u,%06u: Tried breaking %s without success.\n",
					(unsigned int) tv.tv_sec, (unsigned int) tv.tv_usec,
					eac_secret_name(pace_input.pin_id));
			goto err;
		} else {
			printf("%u,%06u: Tried breaking %s with success (=%s).\n",
					(unsigned int) tv.tv_sec, (unsigned int) tv.tv_usec,
					eac_secret_name(pace_input.pin_id),
					pace_input.pin);
		}
	}

	if (cmdline.resume_flag) {
		pace_input.pin_id = PACE_CAN;
		if (can) {
			pace_input.pin = (unsigned char *) can;
			pace_input.pin_length = strlen(can);
		} else {
			pace_input.pin = NULL;
			pace_input.pin_length = 0;
		}
		r = perform_pace(card, pace_input, &pace_output, tr_version);
		if (r < 0)
			goto err;
		printf("Established PACE channel with CAN.\n");

		pace_input.pin_id = PACE_PIN;
		if (pin) {
			pace_input.pin = (unsigned char *) pin;
			pace_input.pin_length = strlen(pin);
		} else {
			pace_input.pin = NULL;
			pace_input.pin_length = 0;
		}
		r = perform_pace(card, pace_input, &pace_output, tr_version);
		if (r < 0)
			goto err;
		printf("Established PACE channel with PIN. PIN resumed.\n");
	}

	if (cmdline.unblock_flag) {
		pace_input.pin_id = PACE_PUK;
		if (puk) {
			pace_input.pin = (unsigned char *) puk;
			pace_input.pin_length = strlen(puk);
		} else {
			pace_input.pin = NULL;
			pace_input.pin_length = 0;
		}
		r = perform_pace(card, pace_input, &pace_output, tr_version);
		if (r < 0)
			goto err;
		printf("Established PACE channel with PUK.\n");

		r = npa_unblock_pin(card);
		if (r < 0)
			goto err;
		printf("Unblocked PIN.\n");
	}

	if (cmdline.new_pin_given) {
		pace_input.pin_id = PACE_PIN;
		if (pin) {
			pace_input.pin = (unsigned char *) pin;
			pace_input.pin_length = strlen(pin);
		} else {
			pace_input.pin = NULL;
			pace_input.pin_length = 0;
		}
		r = perform_pace(card, pace_input, &pace_output, tr_version);
		if (r < 0)
			goto err;
		printf("Established PACE channel with PIN.\n");

		r = npa_change_pin(card, newpin, newpin ? strlen(newpin) : 0);
		if (r < 0)
			goto err;
		printf("Changed PIN.\n");
	}

	if (cmdline.translate_given
			|| (!cmdline.resume_flag && !cmdline.new_pin_given
				&& !cmdline.unblock_flag && !cmdline.break_given)) {

		if (cmdline.cv_certificate_given || cmdline.private_key_given
				|| cmdline.auxiliary_data_given) {
			if (!cmdline.cv_certificate_given || !cmdline.private_key_given) {
				fprintf(stderr, "Need at least the terminal's certificate "
						"and its private key to perform terminal authentication.\n");
				exit(1);
			}

			certs = calloc(sizeof *certs, cmdline.cv_certificate_given + 1);
			certs_lens = calloc(sizeof *certs_lens,
					cmdline.cv_certificate_given + 1);
			if (!certs || !certs_lens) {
				r = SC_ERROR_OUT_OF_MEMORY;
				goto err;
			}
			for (i = 0; i < cmdline.cv_certificate_given; i++) {
				if (!fread_to_eof(cmdline.cv_certificate_arg[i],
							(unsigned char **) &certs[i], &certs_lens[i])) {
					fprintf(stderr, "Could not read certificate.\n");
					r = SC_ERROR_INVALID_DATA;
					goto err;
				}
			}

			if (!pace_input.chat_length) {
				const unsigned char *p = certs[cmdline.cv_certificate_given-1];
				if (!CVC_d2i_CVC_CERT(&cvc_cert, &p, certs_lens[cmdline.cv_certificate_given-1])
						|| !cvc_cert || !cvc_cert->body
						|| !cvc_cert->body->certificate_authority_reference
						|| !cvc_cert->body->chat) {
					fprintf(stderr, "Could not parse certificate.\n");
					ssl_error(ctx);
					r = SC_ERROR_INVALID_DATA;
					goto err;
				}
				pace_input.chat_length = i2d_CVC_CHAT(cvc_cert->body->chat, &certs_chat);
				if (0 >= (int) pace_input.chat_length) {
					fprintf(stderr, "Could not parse CHAT.\n");
					r = SC_ERROR_INVALID_DATA;
					ssl_error(ctx);
					goto err;
				}
				pace_input.chat = certs_chat;
			}

			if (!fread_to_eof(cmdline.private_key_arg,
						&privkey, &privkey_len)) {
				fprintf(stderr, "Could not parse private key.\n");
				r = SC_ERROR_INVALID_DATA;
				goto err;
			}

			if (cmdline.auxiliary_data_given) {
				auxiliary_data_len = sizeof auxiliary_data;
				if (sc_hex_to_bin(cmdline.auxiliary_data_arg, auxiliary_data,
							&auxiliary_data_len) < 0) {
					fprintf(stderr, "Could not parse auxiliary data.\n");
					r = SC_ERROR_INVALID_DATA;
					goto err;
				}
			} else {
				if (cmdline.older_than_given) {
					r = add_to_ASN1_AUXILIARY_DATA_NPA_TOOL(&templates,
							NID_id_DateOfBirth,
							(unsigned char *) cmdline.older_than_arg,
							strlen(cmdline.older_than_arg));
					if (r < 0)
						goto err;
				}
				if (cmdline.verify_validity_given) {
					r = add_to_ASN1_AUXILIARY_DATA_NPA_TOOL(&templates,
							NID_id_DateOfExpiry,
							(unsigned char *) cmdline.verify_validity_arg,
							strlen(cmdline.verify_validity_arg));
					if (r < 0)
						goto err;
				}
				if (cmdline.verify_community_given) {
					community_id_len = sizeof community_id;
					if (sc_hex_to_bin(cmdline.verify_community_arg, community_id,
								&community_id_len) < 0) {
						fprintf(stderr, "Could not parse community ID.\n");
						exit(2);
					}
					r = add_to_ASN1_AUXILIARY_DATA_NPA_TOOL(&templates,
							NID_id_CommunityID,
							community_id, community_id_len);
					if (r < 0)
						goto err;
				}
				if (templates) {
					unsigned char *p = NULL;
					auxiliary_data_len = i2d_ASN1_AUXILIARY_DATA_NPA_TOOL(
							templates, &p);
					if (0 > (int) auxiliary_data_len
							|| auxiliary_data_len > sizeof auxiliary_data) {
						free(p);
						fprintf(stderr, "Auxiliary data too big.\n");
						r = SC_ERROR_OUT_OF_MEMORY;
						goto err;
					}
					memcpy(auxiliary_data, p, auxiliary_data_len);
					free(p);
				}
			}
		}

		pace_input.pin = NULL;
		pace_input.pin_length = 0;
		if (cmdline.pin_given) {
			pace_input.pin_id = PACE_PIN;
			if (pin) {
				pace_input.pin = (unsigned char *) pin;
				pace_input.pin_length = strlen(pin);
			}
		} else if (cmdline.can_given) {
			pace_input.pin_id = PACE_CAN;
			if (can) {
				pace_input.pin = (unsigned char *) can;
				pace_input.pin_length = strlen(can);
			}
		} else if (cmdline.mrz_given) {
			pace_input.pin_id = PACE_MRZ;
			if (mrz) {
				pace_input.pin = (unsigned char *) mrz;
				pace_input.pin_length = strlen(mrz);
			}
		} else if (cmdline.puk_given) {
			pace_input.pin_id = PACE_PUK;
			if (puk) {
				pace_input.pin = (unsigned char *) puk;
				pace_input.pin_length = strlen(puk);
			}
		} else {
			fprintf(stderr, "Skipping PIN verification\n");
			goto nopace;
		}

		r = perform_pace(card, pace_input, &pace_output, tr_version);
		if (r < 0)
			goto err;
		printf("Established PACE channel with %s.\n",
				eac_secret_name(pace_input.pin_id));

nopace:
		if (cmdline.cv_certificate_given || cmdline.private_key_given) {
			unsigned char eid_aid[] = { 0xE8, 0x07, 0x04, 0x00, 0x7f, 0x00, 0x07, 0x03, 0x02};
			sc_path_t path;

			r = perform_terminal_authentication(card,
					(const unsigned char **) certs, certs_lens,
					privkey, privkey_len, auxiliary_data, auxiliary_data_len);
			if (r < 0)
				goto err;
			printf("Performed Terminal Authentication.\n");

			r = perform_chip_authentication(card, &ef_cardsecurity, &ef_cardsecurity_len);
			if (r < 0)
				goto err;
			printf("Performed Chip Authentication.\n");

			sc_path_set(&path, SC_PATH_TYPE_DF_NAME, eid_aid, sizeof eid_aid, 0, 0);
			r = sc_select_file(card, &path, NULL);
			if (r < 0)
				goto err;
			printf("Selected eID application.\n");
		}

		if (cmdline.read_dg1_flag)
			read_dg(card, 1, "Document Type", &dg, &dg_len);
		if (cmdline.read_dg2_flag)
			read_dg(card, 2, "Issuing State", &dg, &dg_len);
		if (cmdline.read_dg3_flag)
			read_dg(card, 3, "Date of Expiry", &dg, &dg_len);
		if (cmdline.read_dg4_flag)
			read_dg(card, 4, "Given Names", &dg, &dg_len);
		if (cmdline.read_dg5_flag)
			read_dg(card, 5, "Family Names", &dg, &dg_len);
		if (cmdline.read_dg6_flag)
			read_dg(card, 6, "Religious/Artistic Name", &dg, &dg_len);
		if (cmdline.read_dg7_flag)
			read_dg(card, 7, "Academic Title", &dg, &dg_len);
		if (cmdline.read_dg8_flag)
			read_dg(card, 8, "Date of Birth", &dg, &dg_len);
		if (cmdline.read_dg9_flag)
			read_dg(card, 9, "Place of Birth", &dg, &dg_len);
		if (cmdline.read_dg10_flag)
			read_dg(card, 10, "Nationality", &dg, &dg_len);
		if (cmdline.read_dg11_flag)
			read_dg(card, 11, "Sex", &dg, &dg_len);
		if (cmdline.read_dg12_flag)
			read_dg(card, 12, "Optional Data", &dg, &dg_len);
		if (cmdline.read_dg13_flag)
			read_dg(card, 13, "Birth Name", &dg, &dg_len);
		if (cmdline.read_dg14_flag)
			read_dg(card, 14, "DG 14", &dg, &dg_len);
		if (cmdline.read_dg15_flag)
			read_dg(card, 15, "DG 15", &dg, &dg_len);
		if (cmdline.read_dg16_flag)
			read_dg(card, 16, "DG 16", &dg, &dg_len);
		if (cmdline.read_dg17_flag)
			read_dg(card, 17, "Normal Place of Residence", &dg, &dg_len);
		if (cmdline.read_dg18_flag)
			read_dg(card, 18, "Community ID", &dg, &dg_len);
		if (cmdline.read_dg19_flag)
			read_dg(card, 19, "Residence Permit I", &dg, &dg_len);
		if (cmdline.read_dg20_flag)
			read_dg(card, 20, "Residence Permit II", &dg, &dg_len);
		if (cmdline.read_dg21_flag)
			read_dg(card, 21, "Optional Data", &dg, &dg_len);

		if (cmdline.write_dg17_given)
			write_dg(card, 17, "Normal Place of Residence", cmdline.write_dg17_arg);
		if (cmdline.write_dg18_given)
			write_dg(card, 18, "Community ID", cmdline.write_dg18_arg);
		if (cmdline.write_dg19_given)
			write_dg(card, 19, "Residence Permit I", cmdline.write_dg19_arg);
		if (cmdline.write_dg20_given)
			write_dg(card, 20, "Residence Permit II", cmdline.write_dg20_arg);
		if (cmdline.write_dg21_given)
			write_dg(card, 21, "Optional Data", cmdline.write_dg21_arg);

		if (cmdline.older_than_given) {
			unsigned char id_DateOfBirth[]  = {6, 9, 4, 0, 127, 0, 7, 3, 1, 4, 1};
			verify(card, "age", id_DateOfBirth, sizeof id_DateOfBirth);
		}
		if (cmdline.verify_validity_given) {
			unsigned char id_DateOfExpiry[] = {6, 9, 4, 0, 127, 0, 7, 3, 1, 4, 2};
			verify(card, "validity", id_DateOfExpiry, sizeof id_DateOfExpiry);
		}
		if (cmdline.verify_community_given) {
			unsigned char id_CommunityID[]  = {6, 9, 4, 0, 127, 0, 7, 3, 1, 4, 3};
			verify(card, "community ID", id_CommunityID, sizeof id_CommunityID);
		}

		if (cmdline.translate_given) {
			if (strncmp(cmdline.translate_arg, "stdin", strlen("stdin")) == 0)
				input = stdin;
			else {
				input = fopen(cmdline.translate_arg, "r");
				if (!input) {
					perror("Opening file with APDUs");
					r = SC_ERROR_INVALID_DATA;
					goto err;
				}
			}

			r = npa_translate_apdus(card, input);
			if (r < 0)
				goto err;
			fclose(input);
			input = NULL;
		}
	}

err:
	cmdline_parser_free(&cmdline);
	free(pace_output.ef_cardaccess);
	free(pace_output.recent_car);
	free(pace_output.previous_car);
	free(pace_output.id_icc);
	free(pace_output.id_pcd);
	if (ef_cardsecurity) {
		OPENSSL_cleanse(ef_cardsecurity, ef_cardsecurity_len);
		free(ef_cardsecurity);
	}
	if (input)
		fclose(input);
	if (certs) {
		i = 0;
		while (certs[i]) {
			free((unsigned char *) certs[i]);
			i++;
		}
		free(certs);
	}
	free(certs_lens);
	free(certs_chat);
	if (cvc_cert)
		CVC_CERT_free(cvc_cert);
	free(privkey);
	free(dg);
	if (templates)
		ASN1_AUXILIARY_DATA_NPA_TOOL_free(templates);

	sc_sm_stop(card);
	sc_reset(card, 1);
	sc_disconnect_card(card);
	sc_release_context(ctx);
	EAC_cleanup();

	if (r < 0)
		fprintf(stderr, "Error: %s\n", sc_strerror(r));

	return -r;
}
#else
int
main (int argc, char **argv)
{
	return 1;
}
#endif
