/*
 * opensc.h: OpenSC library header file
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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

#ifndef _OPENSC_H
#define _OPENSC_H

#include <pthread.h>
#include <winscard.h>
#ifndef NDEBUG
#include <assert.h>
#endif
#include <stdio.h>

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef __GNUC__
#undef inline
#define inline
#endif

#define SC_ERROR_MIN				-1000
#define SC_ERROR_UNKNOWN			-1000
#define SC_ERROR_CMD_TOO_SHORT			-1001
#define SC_ERROR_CMD_TOO_LONG			-1002
#define SC_ERROR_NOT_SUPPORTED			-1003
#define SC_ERROR_TRANSMIT_FAILED		-1004
#define SC_ERROR_FILE_NOT_FOUND			-1005
#define SC_ERROR_INVALID_ARGUMENTS		-1006
#define SC_ERROR_PKCS15_CARD_NOT_FOUND		-1007
#define SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND	-1008
#define SC_ERROR_OUT_OF_MEMORY			-1009
#define SC_ERROR_NO_READERS_FOUND		-1010
#define SC_ERROR_OBJECT_NOT_VALID		-1011
#define SC_ERROR_ILLEGAL_RESPONSE		-1012
#define SC_ERROR_PIN_CODE_INCORRECT		-1013
#define SC_ERROR_SECURITY_STATUS_NOT_SATISFIED	-1014
#define SC_ERROR_CONNECTING_TO_RES_MGR		-1015
#define SC_ERROR_INVALID_ASN1_OBJECT		-1016
#define SC_ERROR_BUFFER_TOO_SMALL		-1017
#define SC_ERROR_CARD_NOT_PRESENT		-1018
#define SC_ERROR_RESOURCE_MANAGER		-1019
#define SC_ERROR_CARD_REMOVED			-1020
#define SC_ERROR_INVALID_PIN_LENGTH		-1021
#define SC_ERROR_UNKNOWN_SMARTCARD		-1022
#define SC_ERROR_UNKNOWN_REPLY			-1023
#define SC_ERROR_OBJECT_NOT_FOUND		-1024
#define SC_ERROR_CARD_RESET			-1025
#define SC_ERROR_ASN1_OBJECT_NOT_FOUND		-1026
#define SC_ERROR_ASN1_END_OF_CONTENTS		-1027
#define SC_ERROR_TOO_MANY_OBJECTS		-1028
#define SC_ERROR_INVALID_CARD			-1029
#define SC_ERROR_WRONG_LENGTH			-1030
#define SC_ERROR_RECORD_NOT_FOUND		-1031

/* Different APDU cases */
#define SC_APDU_CASE_NONE		0
#define SC_APDU_CASE_1                  1
#define SC_APDU_CASE_2_SHORT            2
#define SC_APDU_CASE_3_SHORT            3
#define SC_APDU_CASE_4_SHORT            4
#define SC_APDU_CASE_2_EXT              5
#define SC_APDU_CASE_3_EXT              6
#define SC_APDU_CASE_4_EXT              7

/* File types */
#define SC_FILE_TYPE_DF			0x04
#define SC_FILE_TYPE_INTERNAL_EF	0x03
#define SC_FILE_TYPE_WORKING_EF		0x01

/* EF structures */
#define SC_FILE_EF_UNKNOWN		0x00
#define SC_FILE_EF_TRANSPARENT		0x01
#define SC_FILE_EF_LINEAR_FIXED		0x02
#define SC_FILE_EF_LINEAR_FIXED_TLV	0x03
#define SC_FILE_EF_LINEAR_VARIABLE	0x04
#define SC_FILE_EF_LINEAR_VARIABLE_TLV	0x05
#define SC_FILE_EF_CYCLIC		0x06
#define SC_FILE_EF_CYCLIC_TLV		0x07

/* File status flags */
#define SC_FILE_STATUS_ACTIVATED	0x00
#define SC_FILE_STATUS_INVALIDATED	0x01

/* Access Control flags */
#define SC_AC_NONE			0x00000000 
#define SC_AC_CHV1			0x00000001 /* Card Holder Verif. */
#define SC_AC_CHV2			0x00000002 
#define SC_AC_TERM			0x00000004 /* Terminal auth. */
#define SC_AC_PRO			0x00000008 /* Secure Messaging */
#define SC_AC_AUT			0x00000010 /* Key auth. */
#define SC_AC_NEVER		        0xFFFFFFFE
#define SC_AC_UNKNOWN			0xFFFFFFFF

/* Operations relating to access control (in case of DF) */
#define SC_AC_OP_SELECT			0
#define SC_AC_OP_LOCK			1
#define SC_AC_OP_DELETE			2
#define SC_AC_OP_CREATE			3
#define SC_AC_OP_REHABILITATE		4
#define SC_AC_OP_INVALIDATE		5
#define SC_AC_OP_LIST_FILES		6

/* Operations relating to access control (in case of EF) */
#define SC_AC_OP_READ			0
#define SC_AC_OP_UPDATE			1
#define SC_AC_OP_WRITE			2
#define SC_AC_OP_ERASE			3
/* rehab and invalidate are the same as in DF case */

#define SC_MAX_AC_OPS			7

/* sc_read_record() flags */
#define SC_READ_RECORD_EF_ID_MASK	0x0001F
#define SC_READ_RECORD_BY_REC_ID	0x00000
#define SC_READ_RECORD_BY_REC_NR	0x00100

/* various maximum values */
#define SC_MAX_CARD_DRIVERS		16
#define SC_MAX_CARD_DRIVER_SNAME_SIZE	16
#define SC_MAX_READERS			4
#define SC_MAX_APDU_BUFFER_SIZE		255
#define SC_MAX_PATH_SIZE		16
#define SC_MAX_PIN_SIZE			16
#define SC_MAX_ATR_SIZE			33
#define SC_MAX_SEC_ATTR_SIZE		16
#define SC_MAX_PROP_ATTR_SIZE		16
#define SC_MAX_OBJECT_ID_OCTETS		16
#define SC_APDU_CHOP_SIZE		250

typedef unsigned char u8;

struct sc_object_id {
	int value[SC_MAX_OBJECT_ID_OCTETS];
};

#define SC_PATH_TYPE_FILE_ID	0
#define SC_PATH_TYPE_DF_NAME	1
#define SC_PATH_TYPE_PATH	2

struct sc_path {
	u8 value[SC_MAX_PATH_SIZE];
	size_t len;
	int index;

	int type;
};

struct sc_file {
	struct sc_path path;
	u8 name[16];	/* DF name */
	size_t namelen; /* length of DF name */

	int type, shareable, ef_structure;
	size_t size;	/* Size of file (in bytes) */
	int id;		/* Short file id (2 bytes) */
	int status;	/* Status flags */
	unsigned int acl[SC_MAX_AC_OPS]; /* Access Control List */

	u8 sec_attr[SC_MAX_SEC_ATTR_SIZE];
	size_t sec_attr_len;
	u8 prop_attr[SC_MAX_PROP_ATTR_SIZE];
	size_t prop_attr_len;
	unsigned int magic;
};

#define SC_SEC_OPERATION_DECIPHER	0
#define SC_SEC_OPERATION_SIGN		1


struct sc_security_env {
	int algorithm_ref;
	struct sc_path key_file_id;
	int operation;
	int key_ref;
};

/*
 * Card capabilities 
 */

/* SC_CARD_APDU_EXT: Card can handle large (> 256 bytes) buffers in
 * calls to read_binary, write_binary and update_binary; if not,
 * several successive calls to the corresponding function is made. */
#define SC_CARD_CAP_APDU_EXT		0x00000001

/* SC_CARD_CAP_EMV: Card can handle operations specified in the
 * EMV 4.0 standard. */
#define SC_CARD_CAP_EMV			0x00000002

/*
 * Card flags
 */
/* none yet */

struct sc_card {
	struct sc_context *ctx;

	SCARDHANDLE pcsc_card;
	int reader;
	unsigned long caps, flags;
	int cla;
	u8 atr[SC_MAX_ATR_SIZE];
	size_t atr_len;
	
	pthread_mutex_t mutex;
	int lock_count;
	const struct sc_card_driver *driver;
	struct sc_card_operations *ops;
	void *ops_data;
	
	unsigned int magic;
};

struct sc_card_operations {
	/* Called in sc_connect_card().  Must return 1, if the current
	 * card can be handled with this driver, or 0 otherwise.  ATR
	 * field of the sc_card struct is filled in before calling
	 * this function. */
	int (*match_card)(struct sc_card *card);

	/* Called when ATR of the inserted card matches an entry in ATR
	 * table.  May return SC_ERROR_INVALID_CARD to indicate that
	 * the card cannot be handled with this driver. */
	int (*init)(struct sc_card *card);
	/* Called when the card object is being freed.  finish() has to
	 * deallocate all possible private data. */
	int (*finish)(struct sc_card *card);
	
	/* ISO 7816-4 functions */

	int (*read_binary)(struct sc_card *card, unsigned int idx,
			   u8 * buf, size_t count, unsigned long flags);
	int (*write_binary)(struct sc_card *card, unsigned int idx,
			    const u8 * buf, size_t count, unsigned long flags);
	int (*update_binary)(struct sc_card *card, unsigned int idx,
			     const u8 * buf, size_t count, unsigned long flags);
	int (*erase_binary)(struct sc_card *card, unsigned int idx,
			    size_t count, unsigned long flags);
	int (*read_record)(struct sc_card *card, unsigned int rec_nr,
			   u8 * buf, size_t count, unsigned long flags);

	/* select_file: Does the equivalent of SELECT FILE command specified
	 *   in ISO7816-4. Stores information about the selected file to
	 *   <file>, if not NULL. */
	int (*select_file)(struct sc_card *card, const struct sc_path *path,
			   struct sc_file *file_out);
	int (*get_response)(struct sc_card *card, u8 * buf, size_t count);
	int (*get_challenge)(struct sc_card *card, u8 * buf, size_t count);

	/*
	 * ISO 7816-8 functions
	 */

	/* verify:  Verifies reference data identified by <ref_qualifier>.
	 *   If <tries_left> is not NULL, number of verify tries left is
	 *   saved in case of verification failure. */
	int (*verify)(struct sc_card *card, int ref_qualifier,
		      const u8 *data, size_t data_len, int *tries_left);

	/* restore_security_env:  Restores a previously saved security
	 *   environment, and stores information about the environment to
	 *   <env_out>, if not NULL. */
	int (*restore_security_env)(struct sc_card *card, int se_num,
				    struct sc_security_env *env_out);

	/* set_security_env:  Initializes the security environment on card
	 *   according to <env>, and stores the environment as <se_num> on the
	 *   card. If se_num <= 0, the environment will not be stored. */
	int (*set_security_env)(struct sc_card *card,
			        const struct sc_security_env *env, int se_num);
	/* decipher:  Engages the deciphering operation.  Card will use the
	 *   security environment set in a call to set_security_env or
	 *   restore_security_env. */
	int (*decipher)(struct sc_card *card, const u8 * crgram,
		        size_t crgram_len, u8 * out, size_t outlen);
	/* compute_signature:  Generates a digital signature on the card.  Similiar
	 *   to the function decipher. */
	int (*compute_signature)(struct sc_card *card, const u8 * data,
				 size_t data_len, u8 * out, size_t outlen);
	int (*change_reference_data)(struct sc_card *card, int ref_qualifier,
				     const u8 *old, size_t oldlen,
				     const u8 *newref, size_t newlen,
				     int *tries_left);
	int (*reset_retry_counter)(struct sc_card *card, int ref_qualifier,
				   const u8 *puk, size_t puklen,
				   const u8 *newref, size_t newlen);
	/*
	 * ISO 7816-9 functions
	 */
	int (*create_file)(struct sc_card *card, const struct sc_file *file);
	int (*delete_file)(struct sc_card *card, const struct sc_path *path);
	/* list_files:  Enumerates all the files in the current DF, and
	 *   writes the corresponding file identifiers to <buf>.  Returns
	 *   the number of bytes stored. */
	int (*list_files)(struct sc_card *card, u8 *buf, size_t buflen);
};

struct sc_card_driver {
	char *libpath; /* NULL, if compiled in */
	const char *name;
	const char *short_name;
	struct sc_card_operations *ops;
};

struct sc_context {
	SCARDCONTEXT pcsc_ctx;
	char *readers[SC_MAX_READERS];
	int reader_count;

	int debug;

	int use_std_output, use_cache;
	const struct sc_card_driver *card_drivers[SC_MAX_CARD_DRIVERS+1];
	const struct sc_card_driver *default_driver;
	pthread_mutex_t mutex;
};

struct sc_apdu {
	int cse;		/* APDU case */
	u8 cla, ins, p1, p2;	/* CLA, INS, P1 and P2 bytes */
	size_t lc, le;		/* Lc and Le bytes */
	const u8 *data;		/* C-APDU data */
	size_t datalen;		/* length of data in C-APDU */
	u8 *resp;		/* R-APDU data buffer */
	size_t resplen;		/* in: size of R-APDU buffer,
				 * out: length of data returned in R-APDU */

	unsigned int sw1, sw2;	/* Status words returned in R-APDU */
};

/* Base64 encoding/decoding functions */
int sc_base64_encode(const u8 *in, size_t inlen, u8 *out, size_t outlen,
		     size_t linelength);
int sc_base64_decode(const char *in, u8 *out, size_t outlen);

/* APDU handling functions */
int sc_transmit_apdu(struct sc_card *card, struct sc_apdu *apdu);
void sc_format_apdu(struct sc_card *card, struct sc_apdu *apdu, int cse, int ins,
		    int p1, int p2);

int sc_establish_context(struct sc_context **ctx);
int sc_destroy_context(struct sc_context *ctx);
int sc_set_default_card_driver(struct sc_context *ctx, const char *short_name);
int sc_connect_card(struct sc_context *ctx,
		    int reader, struct sc_card **card);
int sc_disconnect_card(struct sc_card *card);
inline int sc_card_valid(const struct sc_card *card);

/* Checks if a card is present on the supplied reader
 * Returns: 1 if card present, 0 if card absent and < 0 in case of an error */
int sc_detect_card(struct sc_context *ctx, int reader);

/* Waits for card insertion on the supplied reader
 * timeout of -1 means forever, reader of -1 means all readers
 * Returns: 1 if a card was found, 0 if timeout occured
 *          and < 0 in case of an error */
int sc_wait_for_card(struct sc_context *ctx, int reader, int timeout);

int sc_lock(struct sc_card *card);
int sc_unlock(struct sc_card *card);

/* ISO 7816-4 related functions */

int sc_select_file(struct sc_card *card, const struct sc_path *path,
		   struct sc_file *file);
int sc_read_binary(struct sc_card *card, unsigned int idx, u8 * buf,
		   size_t count, unsigned long flags);
int sc_write_binary(struct sc_card *card, unsigned int idx, const u8 * buf,
		    size_t count, unsigned long flags);
int sc_read_record(struct sc_card *card, unsigned int rec_nr, u8 * buf,
		   size_t count, unsigned long flags);
int sc_get_challenge(struct sc_card *card, u8 * rndout, size_t len);

/* ISO 7816-8 related functions */
int sc_restore_security_env(struct sc_card *card, int se_num);
int sc_set_security_env(struct sc_card *card,
			const struct sc_security_env *env);
int sc_decipher(struct sc_card *card, const u8 * crgram, size_t crgram_len,
		u8 * out, size_t outlen);
int sc_compute_signature(struct sc_card *card, const u8 * data,
			 size_t data_len, u8 * out, size_t outlen);
int sc_verify(struct sc_card *card, int ref, const u8 *buf, size_t buflen,
	      int *tries_left);
int sc_change_reference_data(struct sc_card *card, int ref, const u8 *old,
			     size_t oldlen, const u8 *newref, size_t newlen,
			     int *tries_left);
int sc_reset_retry_counter(struct sc_card *card, int ref, const u8 *puk,
			   size_t puklen, const u8 *newref, size_t newlen);

/* ISO 7816-9 */
int sc_create_file(struct sc_card *card, const struct sc_file *file);
int sc_delete_file(struct sc_card *card, const struct sc_path *path);

inline int sc_file_valid(const struct sc_file *file);
void sc_format_path(const char *path_in, struct sc_path *path_out);
int sc_hex_to_bin(const char *in, u8 *out, size_t *outlen);

/* Possibly only valid on Setec cards */
int sc_list_files(struct sc_card *card, u8 * buf, size_t buflen);

const char *sc_strerror(int error);

extern const char *sc_version;

extern const struct sc_card_driver *sc_get_iso7816_driver(void);
extern const struct sc_card_driver *sc_get_emv_driver(void);
extern const struct sc_card_driver *sc_get_setec_driver(void);
extern const struct sc_card_driver *sc_get_mflex_driver(void);
extern const struct sc_card_driver *sc_get_default_driver(void);

#ifdef  __cplusplus
}
#endif

#endif
