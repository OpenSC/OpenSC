/*
 * Copyright (C) 2010-2012 Frank Morgner <morgner@informatik.hu-berlin.de>
 *
 * This file is part of npa.
 *
 * npa is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * npa is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * npa.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "cmdline.h"
#include "config.h"
#include "util.h"
#include "libopensc/log.h"
#include "libopensc/opensc.h"
#include <openssl/pace.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#ifndef HAVE_GETLINE
static ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
    if (!lineptr)
        return -1;

    char *p = realloc(*lineptr, SC_MAX_EXT_APDU_BUFFER_SIZE*3);
    if (!p)
        return -1;
    *lineptr = p;

    if (fgets(p, SC_MAX_EXT_APDU_BUFFER_SIZE*3, stream) == NULL)
        return -1;

    return strlen(p);
}
#endif

/** Maximum length of PIN */
#define MAX_PIN_LEN       6
/** Minimum length of PIN */
#define MIN_PIN_LEN       6

/** 
 * @brief Sends a reset retry counter APDU
 *
 * According to TR-03110 the reset retry counter APDU is used to set a new PIN
 * or to reset the retry counter of the PIN. The standard requires this
 * operation to be authorized either by an established PACE channel or by the
 * effective authorization of the terminal's certificate.
 * 
 * @param[in] card
 * @param[in] pin_id         Type of secret (usually PIN or CAN). You may use <tt>enum s_type</tt> from \c <openssl/pace.h>.
 * @param[in] ask_for_secret whether to ask the user for the secret (\c 1) or not (\c 0)
 * @param[in] new            (optional) new secret
 * @param[in] new_len        (optional) length of \a new
 * 
 * @return \c SC_SUCCESS or error code if an error occurred
 */
int npa_reset_retry_counter(sc_card_t *card,
        enum s_type pin_id, int ask_for_secret,
        const char *new, size_t new_len);
/** 
 * @brief Send APDU to unblock the PIN
 *
 * @param[in] card
 */
#define npa_unblock_pin(card) \
    npa_reset_retry_counter(card, PACE_PIN, 0, NULL, 0)
/** Send APDU to set a new PIN
 *
 * @param[in] card
 * @param[in] newp           (optional) new PIN
 * @param[in] newplen        (optional) length of \a new
 */
#define npa_change_pin(card, newp, newplen) \
    npa_reset_retry_counter(card, PACE_PIN, 1, newp, newplen)

int
npa_reset_retry_counter(sc_card_t *card,
        enum s_type pin_id, int ask_for_secret,
        const char *new, size_t new_len)
{
    sc_apdu_t apdu;
    char *p = NULL;
    int r;

    if (ask_for_secret && (!new || !new_len)) {
        p = malloc(MAX_PIN_LEN+1);
        if (!p) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Not enough memory for new PIN.\n");
            return SC_ERROR_OUT_OF_MEMORY;
        }
        if (0 > EVP_read_pw_string_min(p,
                    MIN_PIN_LEN, MAX_PIN_LEN+1,
                    "Please enter your new PIN: ", 0)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not read new PIN.\n");
            free(p);
            return SC_ERROR_INTERNAL;
        }
        new_len = strlen(p);
        if (new_len > MAX_PIN_LEN)
            return SC_ERROR_INVALID_PIN_LENGTH;
        new = p;
    }

    memset(&apdu, 0, sizeof apdu);
    apdu.ins = 0x2C;
    apdu.p2 = pin_id;
    apdu.data = (u8 *) new;
    apdu.datalen = new_len;
    apdu.lc = apdu.datalen;
    apdu.flags = SC_APDU_FLAGS_NO_GET_RESP|SC_APDU_FLAGS_NO_RETRY_WL;

    if (new_len) {
        apdu.p1 = 0x02;
        apdu.cse = SC_APDU_CASE_3_SHORT;
    } else {
        apdu.p1 = 0x03;
        apdu.cse = SC_APDU_CASE_1;
    }

    r = sc_transmit_apdu(card, &apdu);

    if (p) {
        OPENSSL_cleanse(p, new_len);
        free(p);
    }

    return r;
}

static const char *newpin = NULL;
static const char *pin = NULL;
static const char *puk = NULL;
static const char *can = NULL;
static const char *mrz = NULL;
static u8 chat[0xff];
static u8 desc[0xffff];

static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;
static sc_reader_t *reader;

int npa_translate_apdus(sc_card_t *card, FILE *input)
{
    u8 buf[4 + 3 + 0xffff + 3];
    char *read = NULL;
    size_t readlen = 0, apdulen;
    sc_apdu_t apdu;
    ssize_t linelen;
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
        if (input != stdin) {
            puts("Unencrypted C-APDU");
            util_hex_dump_asc(stdout, buf, apdulen, 0);
        }

        r = sc_bytes2apdu(card->ctx, buf, apdulen, &apdu);
        if (r < 0) {
            sc_debug_hex(ctx, SC_LOG_DEBUG_NORMAL, "Invalid C-APDU", buf, apdulen);
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
        util_hex_dump_asc(stdout, apdu.resp, apdu.resplen, 0);
        printf("======================================================================\n");
    }

    if (read)
        free(read);

    return r;
}

extern enum eac_tr_version tr_version;
int
main (int argc, char **argv)
{
    int r, oindex = 0;
    size_t channeldatalen;
    struct establish_pace_channel_input pace_input;
    struct establish_pace_channel_output pace_output;
    struct timeval tv;
    size_t outlen;

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
    }
    can = cmdline.can_arg;
    mrz = cmdline.mrz_arg;
    pin = cmdline.pin_arg;
    puk = cmdline.puk_arg;
    newpin = cmdline.new_pin_arg;
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
#ifdef ENABLE_OPENPACE
    if (cmdline.tr_03110v201_flag)
        tr_version = EAC_TR_VERSION_2_01;
#endif


    /*if (cmdline.info_flag)*/
        /*return print_avail(cmdline.verbose_given);*/


    r = sc_establish_context(&ctx, "npa-tool");
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		exit(1);
	}

    if (cmdline.verbose_given > 1) {
        ctx->debug = cmdline.verbose_given;
        ctx->debug_file = stderr;
    }


	r = util_connect_card(ctx, &card, cmdline.reader_orig, 0, 0);
    if (r < 0) {
        fprintf(stderr, "Can't initialize reader\n");
        exit(1);
    }

    if (cmdline.break_flag) {
        /* The biggest buffer sprintf could write with "%llu" */
        char secretbuf[strlen("18446744073709551615")+1];
        unsigned long long secret = 0;
        unsigned long long maxsecret = 0;

        if (cmdline.pin_given) {
            pace_input.pin_id = PACE_PIN;
            pace_input.pin_length = 6;
            maxsecret = 999999;
            if (pin) {
                if (sscanf(pin, "%llu", &secret) != 1) {
                    fprintf(stderr, "%s is not an unsigned long long.\n",
                            pace_secret_name(pace_input.pin_id));
                    exit(2);
                }
                if (strlen(can) > pace_input.pin_length) {
                    fprintf(stderr, "%s too big, only %u digits allowed.\n",
                            pace_secret_name(pace_input.pin_id),
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
                            pace_secret_name(pace_input.pin_id));
                    exit(2);
                }
                if (strlen(can) > pace_input.pin_length) {
                    fprintf(stderr, "%s too big, only %u digits allowed.\n",
                            pace_secret_name(pace_input.pin_id),
                            (unsigned int) pace_input.pin_length);
                    exit(2);
                }
            }
        } else if (cmdline.puk_given) {
            pace_input.pin_id = PACE_PUK;
            pace_input.pin_length = 10;
            maxsecret = 9999999999LLU;
            if (puk) {
                if (sscanf(puk, "%llu", &secret) != 1) {
                    fprintf(stderr, "%s is not an unsigned long long.\n",
                            pace_secret_name(pace_input.pin_id));
                    exit(2);
                }
                if (strlen(puk) > pace_input.pin_length) {
                    fprintf(stderr, "%s too big, only %u digits allowed.\n",
                            pace_secret_name(pace_input.pin_id),
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
                    pace_secret_name(pace_input.pin_id), pace_input.pin);

            r = sc_perform_pace(card, &pace_input, &pace_output);

            secret++;
        } while (0 > r && secret <= maxsecret);

        gettimeofday(&tv, NULL);
        if (0 > r) {
            printf("%u,%06u: Tried breaking %s without success.\n",
                    (unsigned int) tv.tv_sec, (unsigned int) tv.tv_usec,
                    pace_secret_name(pace_input.pin_id));
            goto err;
        } else {
            printf("%u,%06u: Tried breaking %s with success (=%s).\n",
                    (unsigned int) tv.tv_sec, (unsigned int) tv.tv_usec,
                    pace_secret_name(pace_input.pin_id),
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
        r = sc_perform_pace(card, &pace_input, &pace_output);
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
        r = sc_perform_pace(card, &pace_input, &pace_output);
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
        r = sc_perform_pace(card, &pace_input, &pace_output);
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
        r = sc_perform_pace(card, &pace_input, &pace_output);
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
            fprintf(stderr, "Please specify whether to do PACE with "
                    "PIN, CAN, MRZ or PUK.\n");
            exit(1);
        }

        r = sc_perform_pace(card, &pace_input, &pace_output);
        if (r < 0)
            goto err;
        printf("Established PACE channel with %s.\n",
                pace_secret_name(pace_input.pin_id));

        if (cmdline.translate_given) {
            FILE *input;
            if (strncmp(cmdline.translate_arg, "stdin", strlen("stdin")) == 0)
                input = stdin;
            else {
                input = fopen(cmdline.translate_arg, "r");
                if (!input) {
                    perror("Opening file with APDUs");
                    goto err;
                }
            }

            r = npa_translate_apdus(card, input);
            fclose(input);
            if (r < 0)
                goto err;
        }
    }

err:
    if (pace_output.ef_cardaccess)
        free(pace_output.ef_cardaccess);
    if (pace_output.recent_car)
        free(pace_output.recent_car);
    if (pace_output.previous_car)
        free(pace_output.previous_car);
    if (pace_output.id_icc)
        free(pace_output.id_icc);
    if (pace_output.id_pcd)
        free(pace_output.id_pcd);

    sc_reset(card, 1);
    sc_unlock(card);
    sc_disconnect_card(card);
    sc_release_context(ctx);

    if (r < 0)
        fprintf(stderr, "Error: %s\n", sc_strerror(r));

    return -r;
}
