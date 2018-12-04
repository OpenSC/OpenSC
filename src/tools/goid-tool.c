/*
 * Copyright (C) 2018 Frank Morgner <frankmorgner@gmail.com>
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

#include "fread_to_eof.h"
#include <string.h>
#include "goid-tool-cmdline.h"
#include "libopensc/asn1.h"
#include "libopensc/log.h"
#include "libopensc/opensc.h"
#include "sm/sm-eac.h"
#ifdef ENABLE_OPENPACE
#include <eac/eac.h>
#endif
#include <stdlib.h>
#include "util.h"
#include <ctype.h>

const unsigned char aid_soc_manager[] = {
    0xD2, 0x76, 0x00, 0x01, 0x72, 0x53, 0x6F, 0x43, 0x4D, 0x01
};
static const unsigned char paccess_aid[] = {
    0xD2, 0x76, 0x00, 0x01, 0x72, 0x50, 0x41, 0x63, 0x63, 0x01,
};
static const char *app_name = "goid-tool";

void
print_permissions(u8 permissions)
{
    size_t perms_printed = 0;
    if (permissions & 0x80) {
        printf("%s PIN", perms_printed ? " or" : "verification of");
        perms_printed++;
    }
    if (permissions & 0x40) {
        printf("%s BIO", perms_printed ? " or" : "verification of");
        perms_printed++;
    }
    if (permissions & 0x20) {
        printf("%s GP key", perms_printed ? " or" : "verification of");
        perms_printed++;
    }
    printf("\n");
}

void
soc_info(sc_context_t *ctx, sc_card_t *card)
{
    sc_apdu_t apdu;
    unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
    u8 information_applets[SC_MAX_APDU_BUFFER_SIZE];
    size_t information_applets_len = sizeof information_applets;
    int pin_initialized = 0, bio_initialized = 0;
    int pin_max_retries = 0, pin_cur_retries = 0, bio_max_retries = 0, bio_cur_retries = 0;
    int pin_length = 0;
    u8 pin_unblock = 0, pin_change = 0, bio_unblock = 0, bio_change = 0;
    size_t pin_change_len = sizeof pin_change, pin_unblock_len = sizeof pin_unblock,
           bio_change_len = sizeof bio_change, bio_unblock_len = sizeof bio_unblock;
    int bio_count = 0;
    u8 bio_initialized_templates[2];
    size_t bio_initialized_templates_len = sizeof bio_initialized_templates;

    struct sc_asn1_entry rapdu_get_information[] = {
        { "Sequence of (applet register)", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_SEQUENCE|SC_ASN1_CONS, 0, NULL, NULL },
        { "Initialized PIN",               SC_ASN1_STRUCT, SC_ASN1_APP|SC_ASN1_CONS|0x02, SC_ASN1_OPTIONAL, NULL, NULL },
        { "Initialized BIO",               SC_ASN1_STRUCT, SC_ASN1_APP|SC_ASN1_CONS|0x03, SC_ASN1_OPTIONAL, NULL, NULL },
        { NULL , 0 , 0 , 0 , NULL , NULL }
    };

    struct sc_asn1_entry rapdu_get_information_pin[] = {
        { "Initialization state of the PIN", SC_ASN1_BOOLEAN, SC_ASN1_TAG_BOOLEAN, 0, NULL, NULL },
        { "maximum remaining tries",         SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
        { "current remaining tries",         SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
        { "Unblock requirements Mask",       SC_ASN1_OCTET_STRING, SC_ASN1_APP|0x1, 0, NULL, NULL },
        { "Change requirements Mask",        SC_ASN1_OCTET_STRING, SC_ASN1_APP|0x2, 0, NULL, NULL },
        { "PIN size",                        SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
        { NULL , 0 , 0 , 0 , NULL , NULL }
    };

    struct sc_asn1_entry rapdu_get_information_bio[] = {
        { "Initialization state of the BIO",           SC_ASN1_BOOLEAN, SC_ASN1_TAG_BOOLEAN, 0, NULL, NULL },
        { "maximum remaining tries",                   SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
        { "current remaining tries",                   SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
        { "Unblock requirements Mask",                 SC_ASN1_OCTET_STRING, SC_ASN1_APP|0x1, 0, NULL, NULL },
        { "Change requirements Mask",                  SC_ASN1_OCTET_STRING, SC_ASN1_APP|0x2, 0, NULL, NULL },
        { "Min minutiae",                              SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
        { "Max minutiae",                              SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
        { "number of templates",                       SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
        { "Bitmap of initialized templates",           SC_ASN1_BIT_STRING, SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
        { "Algorithm parameters, allocation strategy", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
        { NULL , 0 , 0 , 0 , NULL , NULL }
    };

    sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0x61, 0x00, 0x00);

    apdu.cla = 0x80;
    apdu.resp = rbuf;
    apdu.resplen = sizeof rbuf;

    if (sc_transmit_apdu(card, &apdu) != SC_SUCCESS) {
        return;
    }

    sc_format_asn1_entry(rapdu_get_information + 0, information_applets, &information_applets_len, 0);
    sc_format_asn1_entry(rapdu_get_information + 1, rapdu_get_information_pin, NULL, 0);
    sc_format_asn1_entry(rapdu_get_information + 2, rapdu_get_information_bio, NULL, 0);

    sc_format_asn1_entry(rapdu_get_information_pin + 0, &pin_initialized, NULL, 0);
    sc_format_asn1_entry(rapdu_get_information_pin + 1, &pin_max_retries, NULL, 0);
    sc_format_asn1_entry(rapdu_get_information_pin + 2, &pin_cur_retries, NULL, 0);
    sc_format_asn1_entry(rapdu_get_information_pin + 3, &pin_unblock, &pin_unblock_len, 0);
    sc_format_asn1_entry(rapdu_get_information_pin + 4, &pin_change, &pin_change_len, 0);
    sc_format_asn1_entry(rapdu_get_information_pin + 5, &pin_length, NULL, 0);

    sc_format_asn1_entry(rapdu_get_information_bio + 0, &bio_initialized, NULL, 0);
    sc_format_asn1_entry(rapdu_get_information_bio + 1, &bio_max_retries, NULL, 0);
    sc_format_asn1_entry(rapdu_get_information_bio + 2, &bio_cur_retries, NULL, 0);
    sc_format_asn1_entry(rapdu_get_information_bio + 3, &bio_unblock, &bio_unblock_len, 0);
    sc_format_asn1_entry(rapdu_get_information_bio + 4, &bio_change, &bio_change_len, 0);
    sc_format_asn1_entry(rapdu_get_information_bio + 7, &bio_count, NULL, 0);
    sc_format_asn1_entry(rapdu_get_information_bio + 8, bio_initialized_templates, &bio_initialized_templates_len, 0);

    if (sc_asn1_decode(ctx, rapdu_get_information,
                apdu.resp, apdu.resplen, NULL, NULL) != SC_SUCCESS) {
        return;
    }

    if (rapdu_get_information[0].flags & SC_ASN1_PRESENT && information_applets_len > 0) {
        const unsigned char *p = information_applets, *end = information_applets + information_applets_len;
        unsigned int cla = 0, tag = 0;
        size_t length = information_applets_len;

        if (SC_SUCCESS == sc_asn1_read_tag(&p, length, &cla, &tag, &length)
                && cla == SC_ASN1_TAG_UNIVERSAL && tag == SC_ASN1_TAG_INTEGER) {
            int applet_count = 0;
            /* number of applets */
            if (SC_SUCCESS == sc_asn1_decode_integer(p, length, &applet_count)) {
                printf("SoCManager knows %d applet%s%s\n", applet_count,
                        applet_count == 1 ? "" : "s", applet_count == 0 ? "" : ":");
                /* AID of client applet #x */
                for (p += length, length = end - p;
                        p < end;
                        p += length, length = end - p) {
                    size_t i;
                    if (SC_SUCCESS != sc_asn1_read_tag(&p, length, &cla, &tag, &length)
                            || p == NULL || cla != SC_ASN1_TAG_CONTEXT) {
                        break;
                    }
                    putchar('\t');
                    util_hex_dump(stdout, p, length, "");
                    /* align with the maximum lenght of an AID */
                    for (i = length; i < 0x10 + 1; i++)
                        printf("  ");

                    /* i now counts the number of flags that were printed */
                    i = 0;
                    if (tag & 0x02) {
                        printf("%sdefault selected", i ? ", " : "");
                        i++;
                    }
                    if (tag & 0x01) {
                        printf("%sinteracts with SoCManager", i ? ", " : "");
                        i++;
                    }
                    if (tag & 0x04) {
                        printf("%sBIO enabled", i ? ", " : "");
                        i++;
                    }
                    if (tag & 0x08) {
                        printf("%sPIN enabled", i ? ", " : "");
                        i++;
                    }
                    printf("\n");
                }
            }
        }
    }

    if (rapdu_get_information[1].flags & SC_ASN1_PRESENT) {
        if (pin_initialized) {
            printf("PIN is initialized with %d digits (%d of %d tries left).\n",
                    pin_length, pin_cur_retries, pin_max_retries);
        } else {
            printf("PIN is not initialized.\n");
        }
        printf("\tChanging PIN requires ");
        print_permissions(pin_change);
        printf("\tUnblocking PIN requires ");
        print_permissions(pin_unblock);
    }

    if (rapdu_get_information[2].flags & SC_ASN1_PRESENT) {
        if (bio_initialized) {
            int bio_used = 0;
            size_t i, j;
            for (i = 0; i < sizeof bio_initialized_templates; i++) {
                for (j = 0; j < 8; j++) {
                    if (bio_initialized_templates[i] >> j & 0x1)
                        bio_used++;
                }
            }
            printf("BIO is initialized with %d of %d templates (%d of %d tries left).\n",
                    bio_used, bio_count, bio_cur_retries, bio_max_retries);
        } else {
            printf("BIO is not initialized.\n");
        }
        printf("\tChanging BIO requires ");
        print_permissions(bio_change);
        printf("\tUnblocking BIO requires ");
        print_permissions(bio_unblock);
    }
}

void
soc_verify(sc_card_t *card, unsigned char p2)
{
    sc_apdu_t apdu;

    sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, p2);

    if (sc_transmit_apdu(card, &apdu) != SC_SUCCESS) {
        return;
    }
}

void
soc_change(sc_card_t *card, unsigned char p1, unsigned char p2)
{
    sc_apdu_t apdu;

    sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x24, 0x00, p2);

    if (sc_transmit_apdu(card, &apdu) != SC_SUCCESS) {
        return;
    }
}

int soc_main(struct sc_context *ctx, sc_card_t *card, struct gengetopt_args_info *cmdline)
{
    int ok = 0;
    sc_file_t *file = NULL;
    struct sc_path path;
    unsigned char soc_manager_minor = 0;
    unsigned char soc_manager_major = 0;

    sc_path_set(&path, SC_PATH_TYPE_DF_NAME, aid_soc_manager, sizeof aid_soc_manager, 0, 0);
    SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
            sc_select_file(card, &path, &file), "SoCManager not found.");
    if (file && file->prop_attr && file->prop_attr_len) {
        size_t prop_len = 0;
        const u8 *prop = sc_asn1_find_tag(ctx, file->prop_attr,
                file->prop_attr_len, 0xA5, &prop_len);
        if (prop && prop_len) {
            prop = sc_asn1_find_tag(ctx, prop,
                    prop_len, 0x81, &prop_len);
            if (prop && prop_len == 2) {
                soc_manager_major = prop[0];
                soc_manager_minor = prop[1];
                sc_debug(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                        "SoCManager version %u.%u",
                        soc_manager_major, soc_manager_minor);
            }
        }
    }

    if (cmdline->info_given) {
        if ((soc_manager_major == 2 && soc_manager_minor < 7)
                || soc_manager_major < 2)
            SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                    SC_ERROR_NOT_SUPPORTED, "Get Information only supported with version 2.07 and later.");
        soc_info(ctx, card);
    }
    if (cmdline->verify_pin_given) {
        sc_debug(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                "Verify finger print or PIN on the card.");
        soc_verify(card, 0x80);
    }
    if (cmdline->verify_bio_given) {
        sc_debug(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                "Verify finger print on the card.");
        soc_verify(card, 0x40);
    }
    if (cmdline->verify_pin_or_bio_given) {
        sc_debug(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                "Verify finger print or PIN on the card.");
        soc_verify(card, 0xC0);
    }

    if (cmdline->new_pin_given) {
        sc_debug(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                "Initialize the PIN on the card.");
        soc_change(card, 0x00, 0x80);
    }
    if (cmdline->new_bio_given) {
        size_t i = 0;
        while (i < cmdline->new_bio_given) {
            sc_debug(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                    "Initialize finger print template %u on the card.",
                    (unsigned char) i);
            soc_change(card, (unsigned char) i, 0x40);
            i++;
        }
    }

    ok = 1;

err:
    return ok;
}

static int
paccess_construct_fci(struct sc_card *card, const sc_file_t *file,
		u8 *out, size_t *outlen)
{
	u8 *p = out;
	u8 buf[64];

	if (*outlen < 2)
		return SC_ERROR_BUFFER_TOO_SMALL;
	*p++ = 0x62;
	p++;

	buf[0] = (file->size >> 8) & 0xFF;
	buf[1] = file->size & 0xFF;
	sc_asn1_put_tag(0x80, buf, 2, p, *outlen - (p - out), &p);

	buf[0] = (file->id >> 8) & 0xFF;
	buf[1] = file->id & 0xFF;
	sc_asn1_put_tag(0x83, buf, 2, p, *outlen - (p - out), &p);

    memcpy(buf, file->sec_attr, file->sec_attr_len);
    sc_asn1_put_tag(0x86, buf, file->sec_attr_len,
            p, *outlen - (p - out), &p);

    buf[0] = file->sid & 0xFF;
	sc_asn1_put_tag(0x88, buf, 1, p, *outlen - (p - out), &p);

	out[1] = p - out - 2;

	*outlen = p - out;
	return 0;
}

int
paccess_create_file(struct sc_card *card, size_t size, int fid, u8 *sec_attr, size_t sec_attr_len, int sfid)
{
    int ok = 0;
    sc_file_t *file = sc_file_new();
    if (!file)
        goto err;

    file->size = size;
    file->id = fid;
    file->sid = sfid;
	file->sec_attr = sec_attr;
	file->sec_attr_len = sec_attr_len;

    card->ops->construct_fci = paccess_construct_fci;
    SC_TEST_GOTO_ERR(card->ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
            sc_create_file(card, file), "Create file failed.");

    ok = 1;
err:
    return ok;
}

int
paccess_delete_file(struct sc_card *card, int fid)
{
    int ok = 0;
    u8 buf[2];
    struct sc_path path;
	buf[0] = (fid >> 8) & 0xFF;
	buf[1] = fid & 0xFF;
    sc_path_set(&path, SC_PATH_TYPE_FILE_ID, buf, sizeof buf, 0, 0);
    SC_TEST_GOTO_ERR(card->ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
            sc_delete_file(card, &path), "Delete file failed.");
    ok = 1;
err:
    return ok;
}

int
paccess_get_security_attributes(struct sc_context *ctx, const char *ac, int* chatbits, size_t chatbits_len, u8 sec_attr[2])
{
    int ok = 0;
    memset(sec_attr, 0, 2);
    if (!ac || 0 == strcmp(ac, "never")) {
        /* nothing else to do */
    } else if (0 == strcmp(ac, "always")) {
        sec_attr[0] |= 0xFF;
    } else {
        size_t i;
        if (0 == strcmp(ac, "ta")) {
            sec_attr[0] |= 0xA0;
        } else if (0 == strcmp(ac, "sm")) {
            sec_attr[0] |= 0xC0;
        } else {
            SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                    SC_ERROR_INVALID_ARGUMENTS, "unknown access condition.");
        }
        for (i = 0; i < chatbits_len; i++) {
            u8 byte = chatbits[i] / 8;
            u8 bit = chatbits[i] % 8 + 1;
            if (byte > 5)
                SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                        SC_ERROR_INVALID_ARGUMENTS, "Only CHAT bits with index 0..39 are available.");
            sec_attr[0] |= 0x8 | byte;
            sec_attr[1] |= bit;
        }
    }
    ok = 1;
err:
    return ok;
}

int paccess_main(struct sc_context *ctx, sc_card_t *card, struct gengetopt_args_info *cmdline)
{
    int ok = 0, r;
    sc_file_t *file = NULL;
    struct sc_path path;
    size_t i, ef_cardsecurity_len = 0, privkey_len = 0, *certs_lens = NULL;
    unsigned char *ef_cardsecurity = NULL, *privkey = NULL,
                  **certs = NULL;
    unsigned char auxiliary_data[] = {0x67, 0x00};
    unsigned char paccess_minor = 0;
    unsigned char paccess_major = 0;

    sc_path_set(&path, SC_PATH_TYPE_DF_NAME, paccess_aid, sizeof paccess_aid, 0, 0);
    SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
            sc_select_file(card, &path, &file), "PAccess not found.");
    if (file && file->prop_attr && file->prop_attr_len) {
        const unsigned char *p, *end;
        unsigned int cla = 0, tag = 0;
        size_t length;

        for (p = file->prop_attr, length = file->prop_attr_len, end = file->prop_attr + file->prop_attr_len;
                p < end;
                p += length, length = end - p) {
            if (SC_SUCCESS != sc_asn1_read_tag(&p, length, &cla, &tag, &length)
                    || p == NULL) {
                break;
            }
            switch (cla | tag) {
                case 0x81:
                    if (p && length == 2) {
                        paccess_major = p[0];
                        paccess_minor = p[1];
                        sc_debug(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                                "PAccess version %u.%u",
                                paccess_major, paccess_minor);
                    }
                    break;
                case 0x82:
                    if (p && length == 1) {
                        sc_debug(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                                "Number of Session Contexts %u",
                                p[0]);
                    }
                    break;
                case 0x87:
                    sc_debug_hex(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                            "Certificate Authority Reference of the primary CVCA trust anchor",
                            p, length);
                    break;
                case 0x88:
                    sc_debug_hex(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                            "Certificate Authority Reference of the secondary CVCA trust anchor",
                            p, length);
                    break;
                case 0x1fe5:
                case 0x9F65:
                    if (p && length == 2) {
                        size_t max_command_size = (p[0]<<8)|p[1];
                        card->max_recv_size = max_command_size;
                        card->max_send_size = max_command_size;
                        sc_debug(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                                "Maximum data length in command message %"SC_FORMAT_LEN_SIZE_T"u bytes",
                                max_command_size);
                    }
                    break;
            }
        }
    }

    if (cmdline->certificate_given || cmdline->key_given) {
        if (!fread_to_eof(cmdline->key_arg,
                    &privkey, &privkey_len)) {
            SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                    SC_ERROR_INVALID_ARGUMENTS, "Could not parse private key.\n");
        }

        certs = calloc(sizeof *certs, cmdline->certificate_given + 1);
        certs_lens = calloc(sizeof *certs_lens,
                cmdline->certificate_given + 1);
        if (!certs || !certs_lens) {
            SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL, SC_ERROR_NOT_ENOUGH_MEMORY,
                    "Internal error.");
        }
        for (i = 0; i < cmdline->certificate_given; i++) {
            if (!fread_to_eof(cmdline->certificate_arg[i],
                        (unsigned char **) &certs[i], &certs_lens[i])) {
                SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                        SC_ERROR_INVALID_ARGUMENTS, "Could not read certificate.\n");
            }
        }

#ifdef ENABLE_OPENPACE
        EAC_init();
#endif
        SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                perform_terminal_authentication(card,
                    (const unsigned char **) certs, certs_lens,
                    privkey, privkey_len,
                    auxiliary_data, sizeof auxiliary_data),
                "Terminal authentication failed.");

        SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                perform_chip_authentication(card,
                    &ef_cardsecurity, &ef_cardsecurity_len),
                "Chip authentication failed.");
    }

    for (i = 0; i < cmdline->delete_dg_given; i++) {
        int fid = 0x0100 | cmdline->delete_dg_arg[i];

        if ((paccess_major == 2 && paccess_minor < 6)
                || paccess_major < 2)
            SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                    SC_ERROR_NOT_SUPPORTED, "Create File only supported with version 2.06 and later.");
        if (!paccess_delete_file(card, fid))
            goto err;
    }

    for (i = 0; i < cmdline->create_dg_given; i++) {
        u8 sec_attr[4];
        int fid = 0x0100 | cmdline->create_dg_arg[i];

        if ((paccess_major == 2 && paccess_minor < 6)
                || paccess_major < 2)
            SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                    SC_ERROR_NOT_SUPPORTED, "Create File only supported with version 2.06 and later.");

        if (cmdline->new_size_arg < 0)
            SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                    SC_ERROR_INVALID_ARGUMENTS, "`--new-size' needs a positive size.\n");
        if (!paccess_get_security_attributes(ctx, cmdline->new_read_ac_arg,
                    cmdline->new_read_ac_chatbit_arg,
                    cmdline->new_read_ac_chatbit_given, sec_attr + 0)
                || !paccess_get_security_attributes(ctx, cmdline->new_write_ac_arg,
                    cmdline->new_write_ac_chatbit_arg,
                    cmdline->new_write_ac_chatbit_given, sec_attr + 2)
                || !paccess_create_file(card, cmdline->new_size_arg, fid,
                    sec_attr, sizeof sec_attr, cmdline->create_dg_arg[i]))
            goto err;
    }

    if (cmdline->out_file_given > 0 && cmdline->out_file_given != cmdline->read_dg_given) {
        SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                SC_ERROR_INVALID_ARGUMENTS, "If `--out-file' is specified, it must be used as many times as `--read-dg'.\n");
    }

    for (i = 0; i < cmdline->read_dg_given; i++) {
        u8 *ef = NULL;
        size_t ef_len = 0;
        r = iso7816_read_binary_sfid(card, cmdline->read_dg_arg[i],
                &ef, &ef_len);
        if (r >= 0) {
            if (cmdline->out_file_given == cmdline->read_dg_given) {
                FILE *f = fopen(cmdline->out_file_arg[i], "wb");
                if (f) {
                    fwrite(ef, ef_len, 1, f);
                    fclose(f);
                } else {
                    sc_debug(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                            "Error opening %s: %s\n",
                            cmdline->out_file_arg[i], strerror(errno));
                    r = SC_ERROR_FILE_NOT_FOUND;
                }
            } else {
                char label[32];
                snprintf(label, sizeof label, "Data Group %u", (unsigned char) cmdline->read_dg_arg[i]);
                sc_debug_hex(ctx, SC_LOG_DEBUG_VERBOSE_TOOL, label, ef, ef_len);
            }
            free(ef);
        }
        SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL, r,
                "Error reading data group.");
    }

    if (cmdline->print_cardid_given) {
        u8 *ef = NULL;
        size_t ef_len = 0;
        r = iso7816_read_binary_sfid(card, 0x1E, &ef, &ef_len);
        if (r >= 0) {
            const u8 *p = ef;
            unsigned int cla = 0, tag = 0;
            if (SC_SUCCESS == sc_asn1_read_tag(&p, ef_len,
                        &cla, &tag, &ef_len)
                    && (tag | cla) == 0x7E
                    && SC_SUCCESS == sc_asn1_read_tag(&p, ef_len,
                        &cla, &tag, &ef_len)
                    && (tag | cla) == 0x13) {
                const char *cardid = (const char *) p;
                while (cardid && ef_len) {
                    if (isprint(*cardid)) {
                        printf("%c", *cardid);
                    } else {
                        printf(".");
                    }
                    cardid++;
                    ef_len--;
                }
                if (cardid)
                    printf("\n");
            } else {
                r = SC_ERROR_INVALID_DATA;
            }
        }
        free(ef);
        SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL, r,
                "Error reading card ID.");
    }

    if (cmdline->print_paccessid_given) {
        u8 *ef = NULL;
        size_t ef_len = 0;
        r = iso7816_read_binary_sfid(card, 0x06, &ef, &ef_len);
        if (r >= 0) {
            const u8 *p = ef;
            unsigned int cla = 0, tag = 0;
            if (SC_SUCCESS == sc_asn1_read_tag(&p, ef_len,
                        &cla, &tag, &ef_len)
                    && (tag | cla) == 0x66
                    && SC_SUCCESS == sc_asn1_read_tag((const u8 **) &p, ef_len,
                        &cla, &tag, &ef_len)
                    && (tag | cla) == 0x13) {
                const char *paccessid = (const char *) p;
                while (paccessid && ef_len) {
                    if (isprint(*paccessid)) {
                        printf("%c", *paccessid);
                    } else {
                        printf(".");
                    }
                    paccessid++;
                    ef_len--;
                }
                if (paccessid)
                    printf("\n");
            } else {
                r = SC_ERROR_INVALID_DATA;
            }
        }
        free(ef);
        SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL, r,
                "Error reading card ID.");
    }

    if (cmdline->in_file_given != cmdline->write_dg_given) {
        SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                SC_ERROR_INVALID_ARGUMENTS, "If `--in-file' is specified, it must be used as many times as `--write-dg'.\n");
    }

    for (i = 0; i < cmdline->write_dg_given; i++) {
        u8 *ef = NULL;
        size_t ef_len = 0;
        if (!fread_to_eof(cmdline->in_file_arg[i],
                    &ef, &ef_len)) {
            SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
                    SC_ERROR_INVALID_ARGUMENTS, "Could not read input file.\n");
        }
        r = iso7816_update_binary_sfid(card, cmdline->write_dg_arg[i], ef, ef_len);
        free(ef);
        SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL, r,
                "Error writing data group.");
    }

    if (cmdline->write_cardid_arg) {
        size_t cardid_len = strlen(cmdline->write_cardid_arg);
        u8 ef[256];
        if (cardid_len > (sizeof ef) - 4) {
            SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL, SC_ERROR_INVALID_ARGUMENTS,
                    "Card ID too long.");
        }
        ef[0] = 0x7E;
        ef[1] = 2 + cardid_len;
        ef[2] = 0x13;
        ef[3] = cardid_len;
        memcpy(ef + 4, cmdline->write_cardid_arg, cardid_len);
        r = iso7816_update_binary_sfid(card, 0x1E, ef, 4 + cardid_len);
        SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL, r,
                "Error writing card ID.");
    }

    if (cmdline->write_paccessid_arg) {
        size_t paccessid_len = strlen(cmdline->write_paccessid_arg);
        u8 ef[256];
        if (paccessid_len > (sizeof ef) - 4) {
            SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL, SC_ERROR_INVALID_ARGUMENTS,
                    "Card ID too long.");
        }
        ef[0] = 0x66;
        ef[1] = 2 + paccessid_len;
        ef[2] = 0x13;
        ef[3] = paccessid_len;
        memcpy(ef + 4, cmdline->write_paccessid_arg, paccessid_len);
        r = iso7816_update_binary_sfid(card, 0x06, ef, 4 + paccessid_len);
        SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL, r,
                "Error writing PAccess ID.");
    }

    ok = 1;

err:
    if (certs) {
        for (i = 0; certs[i]; i++) {
            free((unsigned char *) certs[i]);
        }
        free(certs);
    }
    free(ef_cardsecurity);
    free(certs_lens);
    free(privkey);
    sc_file_free(file);

    return ok;
}

int
main(int argc, char **argv)
{
    struct gengetopt_args_info cmdline;
    struct sc_context *ctx = NULL;
    struct sc_card *card = NULL;
    int r, fail = 1;
    sc_context_param_t ctx_param;

    if (cmdline_parser(argc, argv, &cmdline) != 0)
        exit(1);

    memset(&ctx_param, 0, sizeof(ctx_param));
    ctx_param.ver      = 0;
    ctx_param.app_name = app_name;

    r = sc_context_create(&ctx, &ctx_param);
    if (r) {
        fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
        exit(1);
    }

    if (cmdline.verbose_given > 1) {
        ctx->debug = cmdline.verbose_given;
        sc_ctx_log_to_file(ctx, "stderr");
    }

    r = sc_set_card_driver(ctx, "default");
    SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL, r,
            "Error selecting card driver.");

    r = util_connect_card_ex(ctx, &card, cmdline.reader_arg, 0, 0, cmdline.verbose_given);
    SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_VERBOSE_TOOL, r,
            "Error connecting to card.");

    if (!soc_main(ctx, card, &cmdline) || !paccess_main(ctx, card, &cmdline))
        goto err;

    fail = 0;

err:
    sc_disconnect_card(card);
    sc_release_context(ctx);
    cmdline_parser_free (&cmdline);

    return fail;
}
/*printf("%s:%d\n", __FILE__, __LINE__);*/
