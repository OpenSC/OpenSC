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

/** 
 * @file opensc.h
 * @brief OpenSC library core header file
 */
 
#ifndef _OPENSC_H
#define _OPENSC_H

#include <stdio.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#include <scconf.h>

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef __GNUC__
#undef inline
#define inline
#endif

#define SC_SUCCESS				0
#define SC_NO_ERROR				0

#define SC_ERROR_MIN				-1000
#define SC_ERROR_UNKNOWN			-1000
#define SC_ERROR_CMD_TOO_SHORT			-1001
#define SC_ERROR_CMD_TOO_LONG			-1002
#define SC_ERROR_NOT_SUPPORTED			-1003
#define SC_ERROR_TRANSMIT_FAILED		-1004
#define SC_ERROR_FILE_NOT_FOUND			-1005
#define SC_ERROR_INVALID_ARGUMENTS		-1006
#define SC_ERROR_PKCS15_APP_NOT_FOUND		-1007
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
#define SC_ERROR_INTERNAL			-1032
#define SC_ERROR_CLASS_NOT_SUPPORTED		-1033
#define SC_ERROR_SLOT_NOT_FOUND			-1034
#define SC_ERROR_SLOT_ALREADY_CONNECTED		-1035
#define SC_ERROR_AUTH_METHOD_BLOCKED		-1036

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
#define SC_AC_CHV			0x00000001 /* Card Holder Verif. */
#define SC_AC_TERM			0x00000002 /* Terminal auth. */
#define SC_AC_PRO			0x00000004 /* Secure Messaging */
#define SC_AC_AUT			0x00000008 /* Key auth. */

#define SC_AC_UNKNOWN			0xFFFFFFFE
#define SC_AC_NEVER			0xFFFFFFFF

/* Operations relating to access control (in case of DF) */
#define SC_AC_OP_SELECT			0
#define SC_AC_OP_LOCK			1
#define SC_AC_OP_DELETE			2
#define SC_AC_OP_CREATE			3
#define SC_AC_OP_REHABILITATE		4
#define SC_AC_OP_INVALIDATE		5
#define SC_AC_OP_LIST_FILES		6
#define SC_AC_OP_CRYPTO			7

/* Operations relating to access control (in case of EF) */
#define SC_AC_OP_READ			0
#define SC_AC_OP_UPDATE			1
#define SC_AC_OP_WRITE			2
#define SC_AC_OP_ERASE			3
/* rehab and invalidate are the same as in DF case */

#define SC_MAX_AC_OPS			8

/* sc_*_record() flags */
#define SC_RECORD_EF_ID_MASK		0x0001F
#define SC_RECORD_BY_REC_ID		0x00000
#define SC_RECORD_BY_REC_NR		0x00100
#define SC_RECORD_CURRENT		0

/* various maximum values */
#define SC_MAX_CARD_DRIVERS		16
#define SC_MAX_READER_DRIVERS		4
#define SC_MAX_CARD_DRIVER_SNAME_SIZE	16
#define SC_MAX_READERS			4
#define SC_MAX_SLOTS			4
#define SC_MAX_CARD_APPS		4
#define SC_MAX_APDU_BUFFER_SIZE		258
#define SC_MAX_PATH_SIZE		16
#define SC_MAX_PIN_SIZE			16
#define SC_MAX_ATR_SIZE			33
#define SC_MAX_OBJECT_ID_OCTETS		16
#define SC_MAX_AID_SIZE			16
/* Beware: the following needs to be a mutiple of 4
 * or else sc_update_binary will not work on GPK */
#define SC_APDU_CHOP_SIZE		248

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

#define SC_AC_KEY_REF_NONE	0xFFFFFFFF

struct sc_acl_entry {
	unsigned int method;
	unsigned int key_ref;

	struct sc_acl_entry *next;
};
typedef struct sc_acl_entry sc_acl_entry_t;

struct sc_file {
	struct sc_path path;
	u8 name[16];	/* DF name */
	size_t namelen; /* length of DF name */

	int type, shareable, ef_structure;
	size_t size;	/* Size of file (in bytes) */
	int id;		/* Short file id (2 bytes) */
	int status;	/* Status flags */
	struct sc_acl_entry *acl[SC_MAX_AC_OPS]; /* Access Control List */

	int record_length; /* In case of fixed-length or cyclic EF */
	int record_count;  /* Valid, if not transparent EF or DF */

	u8 *sec_attr;
	size_t sec_attr_len;
	u8 *prop_attr;
	size_t prop_attr_len;
	unsigned int magic;
};
typedef struct sc_file sc_file_t;

#define SC_SEC_OPERATION_DECIPHER	0x0001
#define SC_SEC_OPERATION_SIGN		0x0002

/* sc_security_env flags */
#define SC_SEC_ENV_ALG_REF_PRESENT	0x0001
#define SC_SEC_ENV_FILE_REF_PRESENT	0x0002
#define SC_SEC_ENV_KEY_REF_PRESENT	0x0004
/* FIXME: the flag below is misleading */
#define SC_SEC_ENV_KEY_REF_ASYMMETRIC	0x0008
#define SC_SEC_ENV_ALG_PRESENT		0x0010

/* PK algorithms */
#define SC_ALGORITHM_RSA		0
#define SC_ALGORITHM_DSA		1
#define SC_ALGORITHM_EC			2

/* Symmetric algorithms */
#define SC_ALGORITHM_DES		64
#define SC_ALGORITHM_3DES		65

#define SC_ALGORITHM_ONBOARD_KEY_GEN	0x80000000
#define SC_ALGORITHM_SPECIFIC_FLAGS	0x0000FFFF

#define SC_ALGORITHM_RSA_RAW		0x00000001
/* If the card is willing to produce a cryptogram padded with the following 
 * methods, set these flags accordingly. */
#define SC_ALGORITHM_RSA_PADS		0x0000000E
#define SC_ALGORITHM_RSA_PAD_PKCS1	0x00000002
#define SC_ALGORITHM_RSA_PAD_ANSI	0x00000004
#define SC_ALGORITHM_RSA_PAD_ISO9796	0x00000008

/* If the card is willing to produce a cryptogram with the following 
 * hash values, set these flags accordingly. */
#define SC_ALGORITHM_RSA_HASH_NONE	0x00000010
#define SC_ALGORITHM_RSA_HASHES		0x000000E0
#define SC_ALGORITHM_RSA_HASH_SHA1	0x00000020
#define SC_ALGORITHM_RSA_HASH_MD5	0x00000040
#define SC_ALGORITHM_RSA_HASH_MD5_SHA1	0x00000080

struct sc_security_env {
	unsigned long flags;
	int operation;
	unsigned int algorithm, algorithm_flags;
	
	unsigned int algorithm_ref;
	struct sc_path file_ref;
	u8 key_ref[8];
	size_t key_ref_len;
};
typedef struct sc_security_env sc_security_env_t;

struct sc_algorithm_id {
	unsigned int algorithm;
	struct sc_object_id obj_id;
};

struct sc_algorithm_info {
	unsigned int algorithm;
	unsigned int key_length;
	unsigned long flags;

	union {
		struct sc_rsa_info {
			long exponent;
		} _rsa;
	} u;
};
typedef struct sc_algorithm_info sc_algorithm_info_t;

struct sc_app_info {
	u8 aid[SC_MAX_AID_SIZE];
	size_t aid_len;
	char *label;
	struct sc_path path;
	u8 *ddo;
	size_t ddo_len;
	
	const char *desc;	/* App description, if known */
	int rec_nr;		/* -1, if EF(DIR) is transparent */
};
typedef struct sc_app_info sc_app_info_t;

struct sc_card_cache {
	struct sc_path current_path;
};

#define SC_PROTO_T0		0x00000001
#define SC_PROTO_T1		0x00000002
#define SC_PROTO_RAW		0x00001000
#define SC_PROTO_ANY		0xFFFFFFFF

struct sc_reader_driver {
	const char *name;
	const char *short_name;
	struct sc_reader_operations *ops;
};

#define SC_SLOT_CARD_PRESENT	0x00000001

struct sc_slot_info {
	int id;	
	unsigned long flags, capabilities;
	unsigned int supported_protocols, active_protocol;
	u8 atr[SC_MAX_ATR_SIZE];
	size_t atr_len;

	struct _atr_info {
		u8 *hist_bytes;
		size_t hist_bytes_len;
		int Fi, f, Di, N;
		u8 FI, DI;
	} atr_info;

	void *drv_data;
};
typedef struct sc_slot_info sc_slot_info_t;

struct sc_event_listener {
	unsigned int event_mask;
	void (*func)(void *, const struct sc_slot_info *, unsigned int event);
};

struct sc_reader {
	struct sc_context *ctx;
	const struct sc_reader_driver *driver;
	const struct sc_reader_operations *ops;
	void *drv_data;
	char *name;

	struct sc_slot_info slot[SC_MAX_SLOTS];
	int slot_count;
};

#define SC_DISCONNECT			0
#define SC_DISCONNECT_AND_RESET		1
#define SC_DISCONNECT_AND_UNPOWER	2
#define SC_DISCONNECT_AND_EJECT		3

struct sc_reader_operations {
	/* Called during sc_establish_context(), when the driver
	 * is loaded */
	int (*init)(struct sc_context *ctx, void **priv_data);
	/* Called when the driver is being unloaded.  finish() has to
	 * deallocate the private data and any resources. */
	int (*finish)(void *priv_data);
	/* Called when releasing a reader.  release() has to
	 * deallocate the private data.  Other fields will be
	 * freed by OpenSC. */
	int (*release)(struct sc_reader *reader);

	int (*detect_card_presence)(struct sc_reader *reader,
				    struct sc_slot_info *slot);
	int (*connect)(struct sc_reader *reader, struct sc_slot_info *slot);
	int (*disconnect)(struct sc_reader *reader, struct sc_slot_info *slot,
			  int action);
	int (*transmit)(struct sc_reader *reader, struct sc_slot_info *slot,
			const u8 *sendbuf, size_t sendsize,
			u8 *recvbuf, size_t *recvsize);
	int (*lock)(struct sc_reader *reader, struct sc_slot_info *slot);
	int (*unlock)(struct sc_reader *reader, struct sc_slot_info *slot);
	int (*set_protocol)(struct sc_reader *reader, struct sc_slot_info *slot,
			    unsigned int proto);
	int (*add_callback)(struct sc_reader *reader, struct sc_slot_info *slot,
			    const struct sc_event_listener *, void *arg);
};


/*
 * Card flags
 */
/* none yet */

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

struct sc_card {
	struct sc_context *ctx;
	struct sc_reader *reader;
	struct sc_slot_info *slot;

	unsigned long caps, flags;
	int cla;
	u8 atr[SC_MAX_ATR_SIZE];
	size_t atr_len;

	struct sc_app_info *app[SC_MAX_CARD_APPS];
	int app_count;
	struct sc_file *ef_dir;
	
	struct sc_algorithm_info *algorithms;
	int algorithm_count;
	
	int lock_count;

	const struct sc_card_driver *driver;
	struct sc_card_operations *ops;
	void *drv_data;

	struct sc_card_cache cache;
	int cache_valid;

#ifdef HAVE_PTHREAD
	pthread_mutex_t mutex;
#endif
	unsigned int magic;
};
typedef struct sc_card sc_card_t;

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
	int (*write_record)(struct sc_card *card, unsigned int rec_nr,
			    const u8 * buf, size_t count, unsigned long flags);
	int (*append_record)(struct sc_card *card, const u8 * buf,
			     size_t count, unsigned long flags);
	int (*update_record)(struct sc_card *card, unsigned int rec_nr,
			     const u8 * buf, size_t count, unsigned long flags);

	/* select_file: Does the equivalent of SELECT FILE command specified
	 *   in ISO7816-4. Stores information about the selected file to
	 *   <file>, if not NULL. */
	int (*select_file)(struct sc_card *card, const struct sc_path *path,
			   struct sc_file **file_out);
	int (*get_response)(struct sc_card *card, u8 * buf, size_t count);
	int (*get_challenge)(struct sc_card *card, u8 * buf, size_t count);

	/*
	 * ISO 7816-8 functions
	 */

	/* verify:  Verifies reference data of type <acl>, identified by
	 *   <ref_qualifier>. If <tries_left> is not NULL, number of verifying
	 *   tries left is saved in case of verification failure, if the
	 *   information is available. */
	int (*verify)(struct sc_card *card, unsigned int type,
		      int ref_qualifier, const u8 *data, size_t data_len,
		      int *tries_left);

	/* restore_security_env:  Restores a previously saved security
	 *   environment, and stores information about the environment to
	 *   <env_out>, if not NULL. */
	int (*restore_security_env)(struct sc_card *card, int se_num);

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
	int (*change_reference_data)(struct sc_card *card, unsigned int type,
				     int ref_qualifier,
				     const u8 *old, size_t oldlen,
				     const u8 *newref, size_t newlen,
				     int *tries_left);
	int (*reset_retry_counter)(struct sc_card *card, unsigned int type,
				   int ref_qualifier,
				   const u8 *puk, size_t puklen,
				   const u8 *newref, size_t newlen);
	/*
	 * ISO 7816-9 functions
	 */
	int (*create_file)(struct sc_card *card, struct sc_file *file);
	int (*delete_file)(struct sc_card *card, const struct sc_path *path);
	/* list_files:  Enumerates all the files in the current DF, and
	 *   writes the corresponding file identifiers to <buf>.  Returns
	 *   the number of bytes stored. */
	int (*list_files)(struct sc_card *card, u8 *buf, size_t buflen);
	
	int (*check_sw)(struct sc_card *card, int sw1, int sw2);
	int (*card_ctl)(struct sc_card *card, unsigned long request,
				void *data);
};

struct sc_card_driver {
	const char *name;
	const char *short_name;
	struct sc_card_operations *ops;
};

struct sc_context {
	scconf_context *conf;
	scconf_block *conf_blocks[3];
	char *app_name;
	int debug;

	FILE *debug_file, *error_file;
	int log_errors;

	const struct sc_reader_driver *reader_drivers[SC_MAX_READER_DRIVERS+1];
	void *reader_drv_data[SC_MAX_READER_DRIVERS];
	
	struct sc_reader *reader[SC_MAX_READERS];
	int reader_count;
	
	const struct sc_card_driver *card_drivers[SC_MAX_CARD_DRIVERS+1];
	const struct sc_card_driver *forced_driver;

#ifdef HAVE_PTHREAD
	pthread_mutex_t mutex;
#endif
	unsigned int magic;
};
typedef struct sc_context sc_context_t;

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
typedef struct sc_apdu sc_apdu_t;

/* Base64 encoding/decoding functions */
int sc_base64_encode(const u8 *in, size_t inlen, u8 *out, size_t outlen,
		     size_t linelength);
int sc_base64_decode(const char *in, u8 *out, size_t outlen);

/* APDU handling functions */
int sc_transmit_apdu(struct sc_card *card, struct sc_apdu *apdu);
void sc_format_apdu(struct sc_card *card, struct sc_apdu *apdu, int cse, int ins,
		    int p1, int p2);

/**
 * Establishes an OpenSC context
 * @param ctx A pointer to a pointer that will receive the allocated context
 * @param app_name A string that identifies the application, used primarily
 *	in finding application-specific configuration data. Can be NULL.
 */
int sc_establish_context(struct sc_context **ctx, const char *app_name);

/**
 * Releases an established OpenSC context
 * @param ctx A pointer to the context structure to be released
 */
int sc_release_context(struct sc_context *ctx);
/**
 * Forces the use of a specified card driver
 * @param ctx OpenSC context
 * @param short_name The short name of the driver to use (e.g. 'emv')
 */
int sc_set_card_driver(struct sc_context *ctx, const char *short_name);
/**
 * Connects to a card in a reader and auto-detects the card driver.
 * The ATR (Answer to Reset) string of the card is also retrieved.
 * @param reader Reader structure
 * @param slot_id Slot ID to connect to
 * @param card The allocated card object will go here */
int sc_connect_card(struct sc_reader *reader, int slot_id,
		    struct sc_card **card);
/**
 * Disconnects from a card, and frees the card structure. Any locks
 * made by the application must be released before calling this function.
 * NOTE: The card is not reset nor powered down after the operation.
 * @param card The card to disconnect
 */
int sc_disconnect_card(struct sc_card *card, int action);
/**
 * Returns 1 if the magic value of the card object is correct. Mostly
 * used internally by the library.
 * @param card The card object to check
 */
inline int sc_card_valid(const struct sc_card *card);

/**
 * Checks if a card is present in a reader
 * @param reader Reader structure
 * @param reader Slot ID
 * @retval 1 if a card is present
 * @retval 0 card absent
 * @retval < 0 if an error occured
 */
int sc_detect_card_presence(struct sc_reader *reader, int slot_id);

/**
 * Waits for an event on a reader
 * @param reader Reader structure
 * @param slot_id Slot ID
 * @param event_mask The types of events to wait for
 * @param timeout Amount of millisecs to wait; -1 means forever
 * @retval 1 if a card was inserted
 * @retval 0 if operation timed out
 * @retval < 0 if an error occured
 */
int sc_wait_for_event(struct sc_reader *reader, int slot_id,
		      unsigned int event_mask, int timeout);

/**
 * Locks the card against modification from other threads.
 * After the initial call to sc_lock, the card is protected from
 * access from other processes. The function may be called several times.
 * @param card The card to lock
 * @retval SC_SUCCESS on success
 */
int sc_lock(struct sc_card *card);
/** 
 * Unlocks a previously locked card. After the lock count drops to zero,
 * the card is again placed in shared mode, where other processes
 * may access or lock it.
 * @param card The card to unlock
 * @retval SC_SUCCESS on success
 */
int sc_unlock(struct sc_card *card);

/* ISO 7816-4 related functions */

/**
 * Does the equivalent of ISO 7816-4 command SELECT FILE.
 * @param card The card on which to issue the command
 * @param path The path, file id or name of the desired file
 * @param file If not NULL, will receive a pointer to a new structure
 * @retval SC_SUCCESS on success
 */
int sc_select_file(struct sc_card *card, const struct sc_path *path,
		   struct sc_file **file);

int sc_list_files(struct sc_card *card, u8 * buf, size_t buflen);

/* TODO: finish writing API docs */
int sc_read_binary(struct sc_card *card, unsigned int idx, u8 * buf,
		   size_t count, unsigned long flags);
int sc_write_binary(struct sc_card *card, unsigned int idx, const u8 * buf,
		    size_t count, unsigned long flags);
int sc_update_binary(struct sc_card *card, unsigned int idx, const u8 * buf,
		     size_t count, unsigned long flags);
/**
 * Reads a record from the current (i.e. selected) file.
 * @param card The card on which to issue the command
 * @param rec_nr SC_READ_RECORD_CURRENT or a record number starting from 1
 * @param buf Pointer to a buffer for storing the data
 * @param count Number of bytes to read
 * @param flags Flags
 * @retval Number of bytes read or an error value
 */
int sc_read_record(struct sc_card *card, unsigned int rec_nr, u8 * buf,
		   size_t count, unsigned long flags);
int sc_write_record(struct sc_card *card, unsigned int rec_nr, const u8 * buf,
		    size_t count, unsigned long flags);
int sc_append_record(struct sc_card *card, const u8 * buf, size_t count,
		     unsigned long flags);
int sc_update_record(struct sc_card *card, unsigned int rec_nr, const u8 * buf,
		     size_t count, unsigned long flags);

int sc_get_challenge(struct sc_card *card, u8 * rndout, size_t len);

/* ISO 7816-8 related functions */
int sc_restore_security_env(struct sc_card *card, int se_num);
int sc_set_security_env(struct sc_card *card,
			const struct sc_security_env *env, int se_num);
int sc_decipher(struct sc_card *card, const u8 * crgram, size_t crgram_len,
		u8 * out, size_t outlen);
int sc_compute_signature(struct sc_card *card, const u8 * data,
			 size_t data_len, u8 * out, size_t outlen);
int sc_verify(struct sc_card *card, unsigned int type, int ref, const u8 *buf,
	      size_t buflen, int *tries_left);
int sc_change_reference_data(struct sc_card *card, unsigned int type,
			     int ref, const u8 *old, size_t oldlen,
			     const u8 *newref, size_t newlen,
			     int *tries_left);
int sc_reset_retry_counter(struct sc_card *card, unsigned int type,
			   int ref, const u8 *puk, size_t puklen,
			   const u8 *newref, size_t newlen);

/* ISO 7816-9 */
int sc_create_file(struct sc_card *card, struct sc_file *file);
int sc_delete_file(struct sc_card *card, const struct sc_path *path);

/* Card controls */
int sc_card_ctl(struct sc_card *card, unsigned long command, void *arg);

inline int sc_file_valid(const struct sc_file *file);
struct sc_file * sc_file_new();
void sc_file_free(struct sc_file *file);
void sc_file_dup(struct sc_file **dest, const struct sc_file *src);

int sc_file_add_acl_entry(struct sc_file *file, unsigned int operation,
			  unsigned int method, unsigned long key_ref);
const struct sc_acl_entry * sc_file_get_acl_entry(const struct sc_file *file,
						  unsigned int operation);
void sc_file_clear_acl_entries(struct sc_file *file, unsigned int operation);

int sc_file_set_sec_attr(struct sc_file *file, const u8 *sec_attr,
			 size_t sec_attr_len);
int sc_file_set_prop_attr(struct sc_file *file, const u8 *prop_attr,
			  size_t prop_attr_len);

void sc_format_path(const char *path_in, struct sc_path *path_out);
int sc_append_path(struct sc_path *dest, const struct sc_path *src);
int sc_append_path_id(struct sc_path *dest, const u8 *id, size_t idlen);
int sc_hex_to_bin(const char *in, u8 *out, size_t *outlen);
int sc_get_cache_dir(struct sc_context *ctx, char *buf, size_t bufsize);

int sc_enum_apps(struct sc_card *card);
const struct sc_app_info * sc_find_app_by_aid(struct sc_card *card,
					      const u8 *aid, size_t aid_len);
int sc_update_dir(struct sc_card *card, struct sc_app_info *app);

struct sc_card_error {
	int SWs;
	int errorno;
	const char *errorstr;
};

const char *sc_strerror(int sc_errno);

extern const char *sc_version;

extern const struct sc_reader_driver *sc_get_pcsc_driver(void);
extern const struct sc_reader_driver *sc_get_ctapi_driver(void);

extern const struct sc_card_driver *sc_get_iso7816_driver(void);
extern const struct sc_card_driver *sc_get_emv_driver(void);
extern const struct sc_card_driver *sc_get_setcos_driver(void);
extern const struct sc_card_driver *sc_get_miocos_driver(void);
extern const struct sc_card_driver *sc_get_flex_driver(void);
extern const struct sc_card_driver *sc_get_gpk_driver(void);
extern const struct sc_card_driver *sc_get_tcos_driver(void);
extern const struct sc_card_driver *sc_get_default_driver(void);

#ifdef  __cplusplus
}
#endif

#endif
