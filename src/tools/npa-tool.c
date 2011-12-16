/*
 * Copyright (C) 2011 Frank Morgner
 *
 * derived from npa-tool from the virtual smart card architecture
 * http://vsmartcard.sourceforge.net/npa/README.html
 */
#include "config.h"
#include "libopensc/log.h"
#include "libopensc/opensc.h"
#include "common/compat_getopt.h"
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

void print_usage(const char *app_name, const struct option options[],
	const char *option_help[])
{
    int i = 0;
    printf("Usage: %s [OPTIONS]\nOptions:\n", app_name);

    while (options[i].name) {
        /* Flawfinder: ignore */
        char buf[40], tmp[5];
        const char *arg_str;

        /* Skip "hidden" options */
        if (option_help[i] == NULL) {
            i++;
            continue;
        }

        if (options[i].val > 0 && options[i].val < 128)
            /* Flawfinder: ignore */
            sprintf(tmp, "-%c", options[i].val);
        else
            tmp[0] = 0;
        switch (options[i].has_arg) {
            case 1:
                arg_str = " <arg>";
                break;
            case 2:
                arg_str = " [arg]";
                break;
            default:
                arg_str = "";
                break;
        }
        snprintf(buf, sizeof buf, "--%-13s%s%s", options[i].name, tmp, arg_str);
        if (strlen(buf) > 24) {
            printf("  %s\n", buf);
            buf[0] = '\0';
        }
        printf("  %-24s %s\n", buf, option_help[i]);
        i++;
    }
}

void parse_error(const char *app_name, const struct option options[],
        const char *option_help[], const char *optarg, int opt_ind)
{
    printf("Could not parse %s ('%s').\n", options[opt_ind].name, optarg);
    print_usage(app_name , options, option_help);
}

int initialize(int reader_id, const char *cdriver, int verbose,
        sc_context_t **ctx, sc_reader_t **reader)
{
    unsigned int i, reader_count;

    if (!ctx || !reader)
        return SC_ERROR_INVALID_ARGUMENTS;

    int r = sc_establish_context(ctx, "");
    if (r < 0) {
        fprintf(stderr, "Failed to create initial context: %s", sc_strerror(r));
        return r;
    }

    if (cdriver != NULL) {
        r = sc_set_card_driver(*ctx, cdriver);
        if (r < 0) {
            sc_debug(*ctx, SC_LOG_DEBUG_VERBOSE, "Card driver '%s' not found.\n", cdriver);
            return r;
        }
    }

    (*ctx)->debug = verbose;

    reader_count = sc_ctx_get_reader_count(*ctx);

    if (reader_count == 0) {
        sc_debug(*ctx, SC_LOG_DEBUG_NORMAL, "No reader not found.\n");
        return SC_ERROR_NO_READERS_FOUND;
    }

    if (reader_id < 0) {
        /* Automatically try to skip to a reader with a card if reader not specified */
        for (i = 0; i < reader_count; i++) {
            *reader = sc_ctx_get_reader(*ctx, i);
            if (sc_detect_card_presence(*reader) & SC_READER_CARD_PRESENT) {
                reader_id = i;
                sc_debug(*ctx, SC_LOG_DEBUG_NORMAL, "Using the first reader"
                        " with a card: %s", (*reader)->name);
                break;
            }
        }
        if (reader_id >= reader_count) {
            sc_debug(*ctx, SC_LOG_DEBUG_NORMAL, "No card found, using the first reader.");
            reader_id = 0;
        }
    }

    if (reader_id >= reader_count) {
        sc_debug(*ctx, SC_LOG_DEBUG_NORMAL, "Invalid reader number "
                "(%d), only %d available.\n", reader_id, reader_count);
        return SC_ERROR_NO_READERS_FOUND;
    }

    *reader = sc_ctx_get_reader(*ctx, reader_id);

    return SC_SUCCESS;
}

void _bin_log(sc_context_t *ctx, int type, const char *file, int line,
        const char *func, const char *label, const u8 *data, size_t len,
        FILE *f)
{
    if (!f) {
        char buf[1800];
        if (data)
            sc_hex_dump(ctx, SC_LOG_DEBUG_NORMAL, data, len, buf, sizeof buf);
        else
            buf[0] = 0;
        sc_do_log(ctx, type, file, line, func,
                "\n%s (%u byte%s):\n%s",
                label, len, len==1?"":"s", buf);
    } else {
        fprintf(f, "%s (%u byte%s):\n%s\n",
                label, len, len==1?"":"s", sc_dump_hex(data, len));
    }
}

#define bin_print(file, label, data, len) \
    _bin_log(NULL, 0, NULL, 0, NULL, label, data, len, file)

#define bin_log(ctx, level, label, data, len) \
    _bin_log(ctx, level, __FILE__, __LINE__, __FUNCTION__, label, data, len, NULL)

static int list_drivers(sc_context_t *ctx)
{
	int i;
	
	if (ctx->card_drivers[0] == NULL) {
		printf("No card drivers installed!\n");
		return 0;
	}
	printf("Configured card drivers:\n");
	for (i = 0; ctx->card_drivers[i] != NULL; i++) {
		printf("  %-16s %s\n", ctx->card_drivers[i]->short_name,
		       ctx->card_drivers[i]->name);
	}

	return 0;
}

static int list_readers(sc_context_t *ctx)
{
	unsigned int i, rcount = sc_ctx_get_reader_count(ctx);
	
	if (rcount == 0) {
		printf("No smart card readers found.\n");
		return 0;
	}
	printf("Readers known about:\n");
	printf("Nr.    Driver     Name\n");
	for (i = 0; i < rcount; i++) {
		sc_reader_t *screader = sc_ctx_get_reader(ctx, i);
		printf("%-7d%-11s%s\n", i, screader->driver->short_name,
		       screader->name);
	}

	return 0;
}

int print_avail(int verbose)
{
    sc_context_t *ctx = NULL;

    int r;
    r = sc_establish_context(&ctx, "");
    if (r) {
        fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
        return 1;
    }
    ctx->debug = verbose;

    r = list_readers(ctx)|list_drivers(ctx);

    if (ctx)
        sc_release_context(ctx);

    return r;
}

#define MIN_PIN_LEN       6
#define MAX_PIN_LEN       6
int npa_reset_retry_counter(sc_card_t *card, unsigned char pin_id,
        int ask_for_secret, const char *new, size_t new_len)
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

#define npa_unblock_pin(card) \
    npa_reset_retry_counter(card, 0x03, 0, NULL, 0)

#define npa_change_pin(card, newp, newplen) \
    npa_reset_retry_counter(card, 0x03, 1, newp, newplen)

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

static int verbose    = 0;
static int doinfo     = 0;
static u8  dobreak = 0;
static u8  dochangepin = 0;
static u8  doresumepin = 0;
static u8  dounblock = 0;
static u8  dotranslate = 0;
static const char *newpin = NULL;
static int usb_reader_num = -1;
static const char *pin = NULL;
static u8 usepin = 0;
static const char *puk = NULL;
static u8 usepuk = 0;
static const char *can = NULL;
static u8 usecan = 0;
static const char *mrz = NULL;
static u8 usemrz = 0;
static u8 chat[0xff];
static u8 desc[0xffff];
static const char *cdriver = NULL;
static char *file = NULL;

static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;
static sc_reader_t *reader;

#define OPT_HELP        'h'
#define OPT_READER      'r'
#define OPT_PIN         'i'
#define OPT_PUK         'u'
#define OPT_CAN         'a'
#define OPT_MRZ         'z'
#define OPT_BREAK       'b'
#define OPT_CHAT        'C'
#define OPT_CERTDESC    'D'
#define OPT_CHANGE_PIN  'N'
#define OPT_RESUME_PIN  'R'
#define OPT_UNBLOCK_PIN 'U'
#define OPT_TRANSLATE   't'
#define OPT_VERBOSE     'v'
#define OPT_INFO        'o'
#define OPT_CARD        'c'
#define OPT_TRVERSION   'n'

static const struct option options[] = {
    { "help", no_argument, NULL, OPT_HELP },
    { "reader",	required_argument, NULL, OPT_READER },
    { "card-driver", required_argument, NULL, OPT_CARD },
    { "pin", optional_argument, NULL, OPT_PIN },
    { "puk", optional_argument, NULL, OPT_PUK },
    { "can", optional_argument, NULL, OPT_CAN },
    { "mrz", optional_argument, NULL, OPT_MRZ },
    { "break", no_argument, NULL, OPT_BREAK },
    { "chat", required_argument, NULL, OPT_CHAT },
    { "cert-desc", required_argument, NULL, OPT_CERTDESC },
    { "new-pin", optional_argument, NULL, OPT_CHANGE_PIN },
    { "resume-pin", no_argument, NULL, OPT_RESUME_PIN },
    { "unblock-pin", no_argument, NULL, OPT_UNBLOCK_PIN },
    { "translate", optional_argument, NULL, OPT_TRANSLATE },
    { "tr-03110v20", required_argument, NULL, OPT_TRVERSION },
    { "verbose", no_argument, NULL, OPT_VERBOSE },
    { "info", no_argument, NULL, OPT_INFO },
    { NULL, 0, NULL, 0 }
};
static const char *option_help[] = {
    "Print help and exit",
    "Number of reader to use          (default: auto-detect)",
    "Which card driver to use         (default: auto-detect)",
    "Run PACE with (transport) PIN",
    "Run PACE with PUK",
    "Run PACE with CAN",
    "Run PACE with MRZ (insert MRZ without newlines)",
    "Brute force the secret (only for PIN, CAN, PUK)",
    "Card holder authorization template to use (hex string)",
    "Certificate description to use (hex string)",
    "Install a new PIN",
    "Resume PIN (uses CAN to activate last retry)",
    "Unblock PIN (uses PUK to activate three more retries)",
    "APDUs to send through SM channel (default: stdin)",
    "Version of TR-03110 (default: 2, for v2.02 and later)",
    "Use (several times) to be more verbose",
    "Print version, available readers and drivers.",
};

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
        if (input != stdin)
            bin_print(stdout, "Unencrypted C-APDU", buf, apdulen);

        r = sc_bytes2apdu(card->ctx, buf, apdulen, &apdu);
        if (r < 0) {
            bin_log(ctx, SC_LOG_DEBUG_NORMAL, "Invalid C-APDU", buf, apdulen);
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

static const char *MRZ_name = "MRZ";
static const char *PIN_name = "PIN";
static const char *PUK_name = "PUK";
static const char *CAN_name = "CAN";
static const char *UNDEF_name = "UNDEF";
const char *npa_secret_name(unsigned char pin_id) {
    switch (pin_id) {
        case 0x01:
            return MRZ_name;
        case 0x04:
            return PUK_name;
        case 0x03:
            return PIN_name;
        case 0x02:
            return CAN_name;
        default:
            return UNDEF_name;
    }
}

int
main (int argc, char **argv)
{
    int r, oindex = 0;
    size_t channeldatalen;
    struct establish_pace_channel_input pace_input;
    struct establish_pace_channel_output pace_output;
    struct timeval tv;
    size_t outlen;

    memset(&pace_input, 0, sizeof pace_input);
    memset(&pace_output, 0, sizeof pace_output);

    while (1) {
        r = getopt_long(argc, argv, "hr:i::u::a::z::bC:D:N::RUt::voc:n:", options, &oindex);
        if (r == -1)
            break;
        switch (r) {
            case OPT_HELP:
                print_usage(argv[0] , options, option_help);
                exit(0);
                break;
            case OPT_READER:
                if (sscanf(optarg, "%d", &usb_reader_num) != 1) {
                    parse_error(argv[0], options, option_help, optarg, oindex);
                    exit(2);
                }
                break;
            case OPT_CARD:
                cdriver = optarg;
                break;
            case OPT_VERBOSE:
                verbose++;
                break;
            case OPT_INFO:
                doinfo = 1;
                break;
            case OPT_PUK:
                usepuk = 1;
                puk = optarg;
                if (!puk)
                    pin = getenv("PUK");
                break;
            case OPT_PIN:
                usepin = 1;
                pin = optarg;
                if (!pin)
                    pin = getenv("PIN");
                break;
            case OPT_CAN:
                usecan = 1;
                can = optarg;
                if (!can)
                    can = getenv("CAN");
                break;
            case OPT_MRZ:
                usemrz = 1;
                mrz = optarg;
                if (!mrz)
                    can = getenv("MRZ");
                break;
            case OPT_BREAK:
                dobreak = 1;
                break;
            case OPT_CHAT:
                pace_input.chat = chat;
                pace_input.chat_length = sizeof chat;
                if (sc_hex_to_bin(optarg, (u8 *) pace_input.chat,
                            &pace_input.chat_length) < 0) {
                    parse_error(argv[0], options, option_help, optarg, oindex);
                    exit(2);
                }
                break;
            case OPT_CERTDESC:
                pace_input.certificate_description = desc;
                pace_input.certificate_description_length = sizeof desc;
                if (sc_hex_to_bin(optarg, (u8 *) pace_input.certificate_description,
                            &pace_input.certificate_description_length) < 0) {
                    parse_error(argv[0], options, option_help, optarg, oindex);
                    exit(2);
                }
                break;
            case OPT_CHANGE_PIN:
                dochangepin = 1;
                newpin = optarg;
                if (!newpin)
                    pin = getenv("NEWPIN");
                break;
            case OPT_RESUME_PIN:
                doresumepin = 1;
                break;
            case OPT_UNBLOCK_PIN:
                dounblock = 1;
                break;
            case OPT_TRANSLATE:
                dotranslate = 1;
                if (optarg) {
                    file = optarg;
                }
                break;
#ifdef TR_VERSION_DONE
            case OPT_TRVERSION:
                if (sscanf(optarg, "%d", (int *) &pace_input.tr_version) != 1) {
                    parse_error(argv[0], options, option_help, optarg, oindex);
                    exit(2);
                }
                break;
#endif
            case '?':
                /* fall through */
            default:
                exit(1);
                break;
        }
    }

    if (optind < argc) {
        fprintf (stderr, "Unknown argument%s:", optind+1 == argc ? "" : "s");
        while (optind < argc) {
            fprintf(stderr, " \"%s\"", argv[optind++]);
            fprintf(stderr, "%c", optind == argc ? '\n' : ',');
        }
        exit(1);
    }


    if (doinfo) {
        fprintf(stderr, "%s %s  written by Frank Morgner.\n\n" ,
                argv[0], VERSION);
        return print_avail(verbose);
    }

    r = initialize(usb_reader_num, cdriver, verbose, &ctx, &reader);
    if (r < 0) {
        fprintf(stderr, "Can't initialize reader\n");
        exit(1);
    }

    if (sc_connect_card(reader, &card) < 0) {
        fprintf(stderr, "Could not connect to card\n");
        sc_release_context(ctx);
        exit(1);
    }

    if (dobreak) {
        /* The biggest buffer sprintf could write with "%llu" */
        char secretbuf[strlen("18446744073709551615")+1];
        unsigned long long secret = 0;
        unsigned long long maxsecret = 0;

        if (usepin) {
            pace_input.pin_id = 0x03;
            pace_input.pin_length = 6;
            maxsecret = 999999;
            if (pin) {
                if (sscanf(pin, "%llu", &secret) != 1) {
                    fprintf(stderr, "%s is not an unsigned long long.\n",
                            npa_secret_name(pace_input.pin_id));
                    exit(2);
                }
                if (strlen(can) > pace_input.pin_length) {
                    fprintf(stderr, "%s too big, only %d digits allowed.\n",
                            npa_secret_name(pace_input.pin_id),
                            pace_input.pin_length);
                    exit(2);
                }
            }
        } else if (usecan) {
            pace_input.pin_id = 0x02;
            pace_input.pin_length = 6;
            maxsecret = 999999;
            if (can) {
                if (sscanf(can, "%llu", &secret) != 1) {
                    fprintf(stderr, "%s is not an unsigned long long.\n",
                            npa_secret_name(pace_input.pin_id));
                    exit(2);
                }
                if (strlen(can) > pace_input.pin_length) {
                    fprintf(stderr, "%s too big, only %d digits allowed.\n",
                            npa_secret_name(pace_input.pin_id),
                            pace_input.pin_length);
                    exit(2);
                }
            }
        } else if (usepuk) {
            pace_input.pin_id = 0x04;
            pace_input.pin_length = 10;
            maxsecret = 9999999999LLU;
            if (puk) {
                if (sscanf(puk, "%llu", &secret) != 1) {
                    fprintf(stderr, "%s is not an unsigned long long.\n",
                            npa_secret_name(pace_input.pin_id));
                    exit(2);
                }
                if (strlen(puk) > pace_input.pin_length) {
                    fprintf(stderr, "%s too big, only %d digits allowed.\n",
                            npa_secret_name(pace_input.pin_id),
                            pace_input.pin_length);
                    exit(2);
                }
            }
        } else {
            fprintf(stderr, "Please specify whether to do PACE with "
                    "PIN, CAN or PUK.\n");
            exit(1);
        }

        pace_input.pin = secretbuf;

        do {
            sprintf(secretbuf, "%0*llu", pace_input.pin_length, secret);

            gettimeofday(&tv, NULL);
            printf("%u,%06u: Trying %s=%s\n",
                    (unsigned int) tv.tv_sec, (unsigned int) tv.tv_usec,
                    npa_secret_name(pace_input.pin_id), pace_input.pin);

            r = sc_perform_pace(card, &pace_input, &pace_output);

            secret++;
        } while (0 > r && secret <= maxsecret);

        gettimeofday(&tv, NULL);
        if (0 > r) {
            printf("%u,%06u: Tried breaking %s without success.\n",
                    (unsigned int) tv.tv_sec, (unsigned int) tv.tv_usec,
                    npa_secret_name(pace_input.pin_id));
            goto err;
        } else {
            printf("%u,%06u: Tried breaking %s with success (=%s).\n",
                    (unsigned int) tv.tv_sec, (unsigned int) tv.tv_usec,
                    npa_secret_name(pace_input.pin_id),
                    pace_input.pin);
        }
    }

    if (doresumepin) {
        pace_input.pin_id = 0x02;
        if (can) {
            pace_input.pin = can;
            pace_input.pin_length = strlen(can);
        } else {
            pace_input.pin = NULL;
            pace_input.pin_length = 0;
        }
        r = sc_perform_pace(card, &pace_input, &pace_output);
        if (r < 0)
            goto err;
        printf("Established PACE channel with CAN.\n");

        pace_input.pin_id = 0x03;
        if (pin) {
            pace_input.pin = pin;
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

    if (dounblock) {
        pace_input.pin_id = 0x04;
        if (puk) {
            pace_input.pin = puk;
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

    if (dochangepin) {
        pace_input.pin_id = 0x03;
        if (pin) {
            pace_input.pin = pin;
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

    if (dotranslate || (!doresumepin && !dochangepin && !dounblock && !dobreak)) {
        pace_input.pin = NULL;
        pace_input.pin_length = 0;
        if (usepin) {
            pace_input.pin_id = 0x03;
            if (pin) {
                pace_input.pin = pin;
                pace_input.pin_length = strlen(pin);
            }
        } else if (usecan) {
            pace_input.pin_id = 0x02;
            if (can) {
                pace_input.pin = can;
                pace_input.pin_length = strlen(can);
            }
        } else if (usemrz) {
            pace_input.pin_id = 0x01;
            if (mrz) {
                pace_input.pin = mrz;
                pace_input.pin_length = strlen(mrz);
            }
        } else if (usepuk) {
            pace_input.pin_id = 0x04;
            if (puk) {
                pace_input.pin = puk;
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
                npa_secret_name(pace_input.pin_id), file);

        if (dotranslate) {
            FILE *input;
            if (!file || strncmp(file, "stdin", strlen("stdin")) == 0)
                input = stdin;
            else {
                input = fopen(file, "r");
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
    sc_disconnect_card(card);
    sc_release_context(ctx);

    return -r;
}
