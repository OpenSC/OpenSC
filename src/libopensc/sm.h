/*
 * sm.h: Support of Secure Messaging
 *
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@opentrust.com>
 *                      OpenTrust <www.opentrust.com>
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

#ifndef _SM_H
#define _SM_H

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <libopensc/errors.h>
#include <libopensc/types.h>
#include <common/libscdl.h>

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH	20
#define SHA1_DIGEST_LENGTH	20
#define SHA256_DIGEST_LENGTH	32
#endif

#define SM_TYPE_GP_SCP01	0x100
#define SM_TYPE_CWA14890	0x400
#define SM_TYPE_DH_RSA		0x500

#define SM_MODE_NONE		0x0
#define SM_MODE_ACL		0x100
#define SM_MODE_TRANSMIT	0x200

#define SM_CMD_INITIALIZE		0x10
#define SM_CMD_MUTUAL_AUTHENTICATION	0x20
#define SM_CMD_RSA			0x100
#define SM_CMD_RSA_GENERATE		0x101
#define SM_CMD_RSA_UPDATE		0x102
#define SM_CMD_RSA_READ_PUBLIC		0x103
#define SM_CMD_FILE			0x200
#define SM_CMD_FILE_READ		0x201
#define SM_CMD_FILE_UPDATE		0x202
#define SM_CMD_FILE_CREATE		0x203
#define SM_CMD_FILE_DELETE		0x204
#define SM_CMD_PIN			0x300
#define SM_CMD_PIN_VERIFY		0x301
#define SM_CMD_PIN_RESET		0x302
#define SM_CMD_PIN_SET_PIN		0x303
#define SM_CMD_PSO			0x400
#define SM_CMD_PSO_DST			0x401
#define SM_CMD_APDU			0x500
#define SM_CMD_APDU_TRANSMIT		0x501
#define SM_CMD_APDU_RAW			0x502
#define SM_CMD_APPLET			0x600
#define SM_CMD_APPLET_DELETE		0x601
#define SM_CMD_APPLET_LOAD		0x602
#define SM_CMD_APPLET_INSTALL		0x603
#define SM_CMD_EXTERNAL_AUTH		0x700
#define SM_CMD_EXTERNAL_AUTH_INIT	0x701
#define SM_CMD_EXTERNAL_AUTH_CHALLENGE	0x702
#define SM_CMD_EXTERNAL_AUTH_DOIT	0x703
#define SM_CMD_SDO_UPDATE		0x800
#define SM_CMD_FINALIZE			0x900

#define SM_RESPONSE_CONTEXT_TAG		0xA1
#define SM_RESPONSE_CONTEXT_DATA_TAG	0xA2

#define SM_MAX_DATA_SIZE    0xE0

#define SM_SMALL_CHALLENGE_LEN	8

#define SM_GP_SECURITY_NO		0x00
#define SM_GP_SECURITY_MAC		0x01
#define SM_GP_SECURITY_ENC		0x03

/* Global Platform (SCP01) data types */
/*
 * @struct sm_type_params_gp
 *	Global Platform SM channel parameters
 */
struct sm_type_params_gp {
	unsigned level;
	unsigned index;
	unsigned version;

	struct sc_cplc cplc;
};

/*
 * @struct sm_gp_keyset
 *	Global Platform keyset:
 *	- version, index;
 *	- keyset presented in three parts: 'ENC', 'MAC' and 'KEK';
 *	- keyset presented in continuous manner - raw or 'to be diversified'.
 */
struct sm_gp_keyset {
        int version;
        int index;
        unsigned char enc[16];
        unsigned char mac[16];
        unsigned char kek[16];

        unsigned char kmc[48];
        unsigned kmc_len;
};

/*
 * @struct sm_gp_session
 *	Global Platform SM session data
 */
struct sm_gp_session {
	struct sm_gp_keyset gp_keyset;

	struct sm_type_params_gp params;

	unsigned char host_challenge[SM_SMALL_CHALLENGE_LEN];
	unsigned char card_challenge[SM_SMALL_CHALLENGE_LEN];

	unsigned char *session_enc, *session_mac, *session_kek;
	unsigned char mac_icv[8];
};


/* CWA, IAS/ECC data types */

/*
 * @struct sm_type_params_cwa
 */
struct sm_type_params_cwa {
	struct sc_crt crt_at;
};

/*
 * @struct sm_cwa_keyset
 *	CWA keyset:
 *	- SDO reference;
 *	- 'ENC' and 'MAC' 3DES keys.
 */
struct sm_cwa_keyset {
	unsigned sdo_reference;
	unsigned char enc[16];
	unsigned char mac[16];
};

/*
 * @struct sm_cwa_token_data
 *	CWA token data:
 *	- serial;
 *	- 'small' random;
 *	- 'big' random.
 */
struct sm_cwa_token_data  {
	unsigned char sn[8];
	unsigned char rnd[8];
	unsigned char k[32];
};

/*
 * @struct sm_cwa_session
 *	CWA working SM session data:
 *	- ICC and IFD token data;
 *	- ENC and MAC session keys;
 *	- SSC (SM Sequence Counter);
 *	- 'mutual authentication' data.
 */
struct sm_cwa_session {
	struct sm_cwa_keyset cwa_keyset;

	struct sm_type_params_cwa params;

	struct sm_cwa_token_data icc;
	struct sm_cwa_token_data ifd;

	unsigned char session_enc[16];
	unsigned char session_mac[16];

	unsigned char ssc[8];

	unsigned char host_challenge[SM_SMALL_CHALLENGE_LEN];
	unsigned char card_challenge[SM_SMALL_CHALLENGE_LEN];

	unsigned char mdata[0x48];
	size_t mdata_len;
};

/*
 * @struct sm_dh_session
 *	DH SM session data:
 */
struct sm_dh_session {
	struct sc_tlv_data g;
	struct sc_tlv_data N;
	struct sc_tlv_data ifd_p;
	struct sc_tlv_data ifd_y;
	struct sc_tlv_data icc_p;
	struct sc_tlv_data shared_secret;

	unsigned char session_enc[16];
	unsigned char session_mac[16];

	unsigned char card_challenge[32];

	unsigned char ssc[8];
};

/*
 * @struct sc_info is the
 *	placehold for the secure messaging working data:
 *	- SM type;
 *	- SM session state;
 *	- command to execute by external SM module;
 *	- data related to the current card context.
 */
struct sm_info   {
	char config_section[64];
	unsigned card_type;

	unsigned cmd;
	void *cmd_data;

	unsigned sm_type;
	union {
		struct sm_gp_session gp;
		struct sm_cwa_session cwa;
		struct sm_dh_session dh;
	} session;

	struct sc_serial_number serialnr;

	unsigned security_condition;

	struct sc_path current_path_df;
	struct sc_path current_path_ef;
	struct sc_aid current_aid;

	unsigned char *rdata;
	size_t rdata_len;
};

/*
 * @struct sm_card_response
 *	data type to return card response.
 */
typedef struct sm_card_response   {
	int num;

	unsigned char data[SC_MAX_APDU_BUFFER_SIZE];
	size_t data_len;

	unsigned char mac[8];
	size_t mac_len;

	unsigned char sw1, sw2;

	struct sm_card_response *next;
	struct sm_card_response *prev;
} sm_card_response_t;

struct sc_context;
struct sc_card;

/*
 * @struct sm_card_operations
 *	card driver handlers related to secure messaging (in 'APDU TRANSMIT' mode)
 *	- 'open' - initialize SM session;
 *	- 'encode apdu' - SM encoding of the raw APDU;
 *	- 'decrypt response' - decode card answer;
 *	- 'close' - close SM session.
 */
struct sm_card_operations {
	int (*open)(struct sc_card *card);
	int (*get_sm_apdu)(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu **sm_apdu);
	int (*free_sm_apdu)(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu **sm_apdu);
	int (*close)(struct sc_card *card);

	int (*read_binary)(struct sc_card *card, unsigned int idx,
			unsigned char * buf, size_t count);
	int (*update_binary)(struct sc_card *card, unsigned int idx,
			const unsigned char * buf, size_t count);
};

/*
 * @struct sm_module_operations
 *	API to use external SM modules:
 *	- 'initiliaze' - get APDU(s) to initialize SM session;
 *	- 'get apdus' - get secured APDUs to execute particular command;
 *	- 'finalize' - get APDU(s) to finalize SM session;
 *	- 'module init' - initialize external module (allocate data, read configuration, ...);
 *	- 'module cleanup' - free resources allocated by external module.
 */
struct sm_module_operations {
	int (*initialize)(struct sc_context *ctx, struct sm_info *info,
			struct sc_remote_data *out);
	int (*get_apdus)(struct sc_context *ctx, struct sm_info *sm_info,
			unsigned char *init_data, size_t init_len,
	                struct sc_remote_data *out);
	int (*finalize)(struct sc_context *ctx, struct sm_info *info, struct sc_remote_data *rdata,
			unsigned char *out, size_t out_len);
	int (*module_init)(struct sc_context *ctx, const char *data);
	int (*module_cleanup)(struct sc_context *ctx);

	int (*test)(struct sc_context *ctx, struct sm_info *info, char *out);
};

typedef struct sm_module {
	char filename[128];
	void *handle;

	struct sm_module_operations ops;
} sm_module_t;

/* @struct sm_context
 *	SM context -- top level of the SM data type
 *	- SM mode ('ACL' or 'APDU TRANSMIT'), flags;
 *	- working SM data;
 *	- card operations related to SM in 'APDU TRANSMIT' mode;
 *	- external SM module;
 *	- 'lock'/'unlock' handlers to allow SM transfer in the locked card session.
 */
typedef struct sm_context   {
	char config_section[64];
	unsigned sm_mode, sm_flags;

	struct sm_info info;

	struct sm_card_operations ops;

	struct sm_module module;

	unsigned long (*app_lock)(void);
	void (*app_unlock)(void);
} sm_context_t;

int sc_sm_parse_answer(struct sc_card *, unsigned char *, size_t, struct sm_card_response *);
int sc_sm_update_apdu_response(struct sc_card *, unsigned char *, size_t, int, struct sc_apdu *);
int sc_sm_single_transmit(struct sc_card *, struct sc_apdu *);

/**
 * @brief Stops SM and frees allocated ressources.
 *
 * Calls \a card->sm_ctx.ops.close() if available and \c card->sm_ctx.sm_mode
 * is \c SM_MODE_TRANSMIT
 *
 * @param[in] card
 *
 * @return \c SC_SUCCESS or error code if an error occurred
 */
int sc_sm_stop(struct sc_card *card);

#ifdef __cplusplus
}
#endif

#endif
