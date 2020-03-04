/*
 * sc-pkcs11.h: OpenSC project's PKCS#11 implementation header
 *
 * Copyright (C) 2002  Timo Teräs <timo.teras@iki.fi>
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

#ifndef __sc_pkcs11_h__
#define __sc_pkcs11_h__

#include "config.h"

#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"
#include "libopensc/log.h"

#define CRYPTOKI_EXPORTS
#include "pkcs11.h"
#include "pkcs11-opensc.h"
#include "pkcs11-display.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SC_PKCS11_PIN_UNBLOCK_NOT_ALLOWED	0
#define SC_PKCS11_PIN_UNBLOCK_UNLOGGED_SETPIN	1
#define SC_PKCS11_PIN_UNBLOCK_SCONTEXT_SETPIN	2
#define SC_PKCS11_PIN_UNBLOCK_SO_LOGGED_INITPIN	3

#define SC_PKCS11_SLOT_FOR_PIN_USER	1
#define SC_PKCS11_SLOT_FOR_PIN_SIGN	2
#define SC_PKCS11_SLOT_CREATE_ALL	8

#define SC_PKCS11_SLOT_FOR_PINS		(SC_PKCS11_SLOT_FOR_PIN_USER | SC_PKCS11_SLOT_FOR_PIN_SIGN)

#ifdef __cplusplus
}
#endif

/* Decide whether to use pkcs11 for initialization support */
#ifdef ENABLE_OPENSSL
#define USE_PKCS15_INIT
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct sc_pkcs11_session;
struct sc_pkcs11_slot;
struct sc_pkcs11_card;

struct sc_pkcs11_config {
	unsigned int max_virtual_slots;
	unsigned int slots_per_card;
	unsigned char lock_login;
	unsigned char atomic;
	unsigned char init_sloppy;
	unsigned int pin_unblock_style;
	unsigned int create_puk_slot;
	unsigned int create_slots_flags;
	unsigned char ignore_pin_length;
};

/*
 * PKCS#11 Object abstraction layer
 */

struct sc_pkcs11_object_ops {
	/* Generic operations */
	void (*release)(void *);

	/* Management methods */
	CK_RV (*set_attribute)(struct sc_pkcs11_session *, void *, CK_ATTRIBUTE_PTR);
	CK_RV (*get_attribute)(struct sc_pkcs11_session *, void *, CK_ATTRIBUTE_PTR);
	CK_RV (*cmp_attribute)(struct sc_pkcs11_session *, void *, CK_ATTRIBUTE_PTR);

	CK_RV (*destroy_object)(struct sc_pkcs11_session *, void *);
	CK_RV (*get_size)(struct sc_pkcs11_session *, void *);

	/* Cryptographic methods */
	CK_RV (*sign)(struct sc_pkcs11_session *, void *,
			CK_MECHANISM_PTR,
			CK_BYTE_PTR pData, CK_ULONG ulDataLen,
			CK_BYTE_PTR pSignature, CK_ULONG_PTR pulDataLen);
	CK_RV (*unwrap_key)(struct sc_pkcs11_session *, void *,
			CK_MECHANISM_PTR,
			CK_BYTE_PTR pData, CK_ULONG ulDataLen,
			void *targetKey);
	CK_RV (*decrypt)(struct sc_pkcs11_session *, void *,
			CK_MECHANISM_PTR,
			CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
			CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);

	CK_RV (*derive)(struct sc_pkcs11_session *, void *,
			CK_MECHANISM_PTR,
			CK_BYTE_PTR pSeedData, CK_ULONG ulSeedDataLen,
			CK_BYTE_PTR pDerived, CK_ULONG_PTR pulDerivedLen);

	/* Check compatibility of PKCS#15 object usage and an asked PKCS#11 mechanism. */
	CK_RV (*can_do)(struct sc_pkcs11_session *, void *, CK_MECHANISM_TYPE, unsigned int);

	/* General validation of mechanism parameters (sign, encrypt, etc) */
	CK_RV (*init_params)(struct sc_pkcs11_session *, CK_MECHANISM_PTR);

	CK_RV (*wrap_key)(struct sc_pkcs11_session *, void *,
			CK_MECHANISM_PTR,
			void*,
			CK_BYTE_PTR pData, CK_ULONG_PTR ulDataLen);

	/* Others to be added when implemented */
};

struct sc_pkcs11_object {
	CK_OBJECT_HANDLE handle;
	int flags;
	struct sc_pkcs11_object_ops *ops;
};

#define SC_PKCS11_OBJECT_SEEN	0x0001
#define SC_PKCS11_OBJECT_HIDDEN	0x0002
#define SC_PKCS11_OBJECT_RECURS	0x8000


/*
 * PKCS#11 smart card Framework abstraction
 */

struct sc_pkcs11_framework_ops {
	/* Detect and bind card to framework */
	CK_RV (*bind)(struct sc_pkcs11_card *, struct sc_app_info *);
	/* Unbind and release allocated resources */
	CK_RV (*unbind)(struct sc_pkcs11_card *);

	/* Create tokens to virtual slots and
	 * objects in tokens; called after bind */
	CK_RV (*create_tokens)(struct sc_pkcs11_card *, struct sc_app_info *);
	CK_RV (*release_token)(struct sc_pkcs11_card *, void *);

	/* Login and logout */
	CK_RV (*login)(struct sc_pkcs11_slot *,
				CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG);
	CK_RV (*logout)(struct sc_pkcs11_slot *);
	CK_RV (*change_pin)(struct sc_pkcs11_slot *,
				CK_CHAR_PTR, CK_ULONG,
				CK_CHAR_PTR, CK_ULONG);
	/*
	 * In future: functions to create new objects (i.e. certificates, private keys)
	 */
	CK_RV (*init_token)(struct sc_pkcs11_slot *, void *,
				CK_UTF8CHAR_PTR, CK_ULONG,
				CK_UTF8CHAR_PTR);
	CK_RV (*init_pin)(struct sc_pkcs11_slot *,
				CK_UTF8CHAR_PTR, CK_ULONG);
	CK_RV (*create_object)(struct sc_pkcs11_slot *,
				CK_ATTRIBUTE_PTR, CK_ULONG,
				CK_OBJECT_HANDLE_PTR);
	CK_RV (*gen_keypair)(struct sc_pkcs11_slot *,
				CK_MECHANISM_PTR,
				CK_ATTRIBUTE_PTR, CK_ULONG,
				CK_ATTRIBUTE_PTR, CK_ULONG,
				CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);
	CK_RV (*get_random)(struct sc_pkcs11_slot *,
				CK_BYTE_PTR, CK_ULONG);
};

/*
 * PKCS#11 Slot (used to access card with specific framework data)
 */

#ifndef _WIN32
typedef unsigned long long sc_timestamp_t;
#else
typedef unsigned __int64   sc_timestamp_t;
#endif

#define SC_PKCS11_FRAMEWORK_DATA_MAX_NUM	4
struct sc_pkcs11_card {
	sc_reader_t *reader;
	sc_card_t *card;
	struct sc_pkcs11_framework_ops *framework;
	void *fws_data[SC_PKCS11_FRAMEWORK_DATA_MAX_NUM];

	/* List of supported mechanisms */
	struct sc_pkcs11_mechanism_type **mechanisms;
	unsigned int nmechanisms;
};


struct sc_pkcs11_slot {
	CK_SLOT_ID id;			/* ID of the slot */
	int login_user;			/* Currently logged in user */
	CK_SLOT_INFO slot_info;		/* Slot specific information (information about reader) */
	CK_TOKEN_INFO token_info;	/* Token specific information (information about card) */
	sc_reader_t *reader;		/* same as card->reader if there's a card present */
	struct sc_pkcs11_card *p11card;	/* The card associated with this slot */
	unsigned int events;		/* Card events SC_EVENT_CARD_{INSERTED,REMOVED} */
	void *fw_data;			/* Framework specific data */  /* TODO: get know how it used */
	list_t objects;			/* Objects in this slot */
	unsigned int nsessions;		/* Number of sessions using this slot */
	sc_timestamp_t slot_state_expires;

	int fw_data_idx;		/* Index of framework data */
	struct sc_app_info *app_info;	/* Application associated to slot */
	list_t logins;			/* tracks all calls to C_Login if atomic operations are requested */
	int flags;
};
typedef struct sc_pkcs11_slot sc_pkcs11_slot_t;

/* Debug virtual slots. S is slot to be highlighted or NULL
 * C is a comment format string and args It will be preceeded by "VSS " */

#define DEBUG_VSS(S, C...) sc_log(context,"VSS " C); _debug_virtual_slots(S)

/* called by DEBUG_VSS to print table of virtual slots */
void  _debug_virtual_slots(sc_pkcs11_slot_t *p);

/* Forward decl */
typedef struct sc_pkcs11_operation sc_pkcs11_operation_t;

enum {
	SC_PKCS11_OPERATION_FIND = 0,
	SC_PKCS11_OPERATION_SIGN,
	SC_PKCS11_OPERATION_VERIFY,
	SC_PKCS11_OPERATION_DIGEST,
	SC_PKCS11_OPERATION_DECRYPT,
	SC_PKCS11_OPERATION_DERIVE,
	SC_PKCS11_OPERATION_WRAP,
	SC_PKCS11_OPERATION_UNWRAP,
	SC_PKCS11_OPERATION_MAX
};

/* This describes a PKCS11 mechanism */
struct sc_pkcs11_mechanism_type {
	CK_MECHANISM_TYPE mech;		/* algorithm: md5, sha1, ... */
	CK_MECHANISM_INFO mech_info;	/* mechanism info */
	CK_MECHANISM_TYPE key_type;	/* for sign/decipher ops */
	unsigned int	  obj_size;

	/* General management */
	void		  (*release)(sc_pkcs11_operation_t *);

	/* Digest/sign Operations */
	CK_RV		  (*md_init)(sc_pkcs11_operation_t *);
	CK_RV		  (*md_update)(sc_pkcs11_operation_t *,
					CK_BYTE_PTR, CK_ULONG);
	CK_RV		  (*md_final)(sc_pkcs11_operation_t *,
					CK_BYTE_PTR, CK_ULONG_PTR);

	CK_RV		  (*sign_init)(sc_pkcs11_operation_t *,
					struct sc_pkcs11_object *);
	CK_RV		  (*sign_update)(sc_pkcs11_operation_t *,
					CK_BYTE_PTR, CK_ULONG);
	CK_RV		  (*sign_final)(sc_pkcs11_operation_t *,
					CK_BYTE_PTR, CK_ULONG_PTR);
	CK_RV		  (*sign_size)(sc_pkcs11_operation_t *,
					CK_ULONG_PTR);
	CK_RV		  (*verif_init)(sc_pkcs11_operation_t *,
					struct sc_pkcs11_object *);
	CK_RV		  (*verif_update)(sc_pkcs11_operation_t *,
					CK_BYTE_PTR, CK_ULONG);
	CK_RV		  (*verif_final)(sc_pkcs11_operation_t *,
					CK_BYTE_PTR, CK_ULONG);
	CK_RV		  (*decrypt_init)(sc_pkcs11_operation_t *,
					struct sc_pkcs11_object *);
	CK_RV		  (*decrypt)(sc_pkcs11_operation_t *,
					CK_BYTE_PTR, CK_ULONG,
					CK_BYTE_PTR, CK_ULONG_PTR);
	CK_RV		  (*derive)(sc_pkcs11_operation_t *,
					struct sc_pkcs11_object *,
					CK_BYTE_PTR, CK_ULONG,
					CK_BYTE_PTR, CK_ULONG_PTR);
	CK_RV		  (*wrap)(sc_pkcs11_operation_t *,
					struct sc_pkcs11_object *,
					struct sc_pkcs11_object *,
					CK_BYTE_PTR, CK_ULONG_PTR);
	CK_RV		  (*unwrap)(sc_pkcs11_operation_t *,
					struct sc_pkcs11_object *,
					CK_BYTE_PTR, CK_ULONG,
					struct sc_pkcs11_object *);

	/* mechanism specific data */
	const void *  mech_data;
	/* free mechanism specific data */
	void		  (*free_mech_data)(const void *mech_data);
};
typedef struct sc_pkcs11_mechanism_type sc_pkcs11_mechanism_type_t;

/*
 * Generic operation
 */
struct sc_pkcs11_operation {
	sc_pkcs11_mechanism_type_t *type;
	CK_MECHANISM	  mechanism;
	union {
		CK_RSA_PKCS_PSS_PARAMS pss;
		CK_RSA_PKCS_OAEP_PARAMS oaep;
	} mechanism_params;
	struct sc_pkcs11_session *session;
	void *		  priv_data;
};

/* Find Operation */
#define SC_PKCS11_FIND_INC_HANDLES	32
struct sc_pkcs11_find_operation {
	struct sc_pkcs11_operation operation;
	int num_handles, current_handle, allocated_handles;
	CK_OBJECT_HANDLE *handles;
};

/*
 * PKCS#11 Session
 */

struct sc_pkcs11_session {
	CK_SESSION_HANDLE handle;
	/* Session to this slot */
	struct sc_pkcs11_slot *slot;
	CK_FLAGS flags;
	/* Notifications */
	CK_NOTIFY notify_callback;
	CK_VOID_PTR notify_data;
	/* Active operations - one per type */
	struct sc_pkcs11_operation *operation[SC_PKCS11_OPERATION_MAX];
};
typedef struct sc_pkcs11_session sc_pkcs11_session_t;

/* Module variables */
extern struct sc_context *context;
extern struct sc_pkcs11_config sc_pkcs11_conf;
extern list_t sessions;
extern list_t virtual_slots;
extern list_t cards;

/* Framework definitions */
extern struct sc_pkcs11_framework_ops framework_pkcs15;
extern struct sc_pkcs11_framework_ops framework_pkcs15init;

void strcpy_bp(u8 *dst, const char *src, size_t dstsize);
CK_RV sc_to_cryptoki_error(int rc, const char *ctx);
void sc_pkcs11_print_attrs(int level, const char *file, unsigned int line, const char *function,
		const char *info, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
#define dump_template(level, info, pTemplate, ulCount) \
		sc_pkcs11_print_attrs(level, __FILE__, __LINE__, __FUNCTION__, \
				info, pTemplate, ulCount)

/* Slot and card handling functions */
CK_RV card_removed(sc_reader_t *reader);
CK_RV card_detect_all(void);
CK_RV create_slot(sc_reader_t *reader);
void init_slot_info(CK_SLOT_INFO_PTR pInfo, sc_reader_t *reader);
CK_RV card_detect(sc_reader_t *reader);
CK_RV slot_get_slot(CK_SLOT_ID id, struct sc_pkcs11_slot **);
CK_RV slot_get_token(CK_SLOT_ID id, struct sc_pkcs11_slot **);
CK_RV slot_token_removed(CK_SLOT_ID id);
CK_RV slot_allocate(struct sc_pkcs11_slot **, struct sc_pkcs11_card *);
CK_RV slot_find_changed(CK_SLOT_ID_PTR idp, int mask);
int slot_get_logged_in_state(struct sc_pkcs11_slot *slot);

/* Login tracking functions */
CK_RV restore_login_state(struct sc_pkcs11_slot *slot);
CK_RV reset_login_state(struct sc_pkcs11_slot *slot, CK_RV rv);
CK_RV push_login_state(struct sc_pkcs11_slot *slot,
		CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen);
void pop_login_state(struct sc_pkcs11_slot *slot);
void pop_all_login_states(struct sc_pkcs11_slot *slot);

/* Session manipulation */
CK_RV get_session(CK_SESSION_HANDLE hSession, struct sc_pkcs11_session ** session);
CK_RV session_start_operation(struct sc_pkcs11_session *,
			int, sc_pkcs11_mechanism_type_t *,
			struct sc_pkcs11_operation **);
CK_RV session_get_operation(struct sc_pkcs11_session *, int,
			struct sc_pkcs11_operation **);
CK_RV session_stop_operation(struct sc_pkcs11_session *, int);
CK_RV sc_pkcs11_close_all_sessions(CK_SLOT_ID);

/* Generic secret key stuff */
CK_RV sc_pkcs11_create_secret_key(struct sc_pkcs11_session *,
			const u8 *, size_t,
			CK_ATTRIBUTE_PTR, CK_ULONG,
			struct sc_pkcs11_object **);
/* Generic object handling */
CK_RV sc_pkcs11_any_cmp_attribute(struct sc_pkcs11_session *,
			void *, CK_ATTRIBUTE_PTR);

/* Get attributes from template (misc.c) */
CK_RV attr_find(CK_ATTRIBUTE_PTR, CK_ULONG, CK_ULONG, void *, size_t *);
CK_RV attr_find2(CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG,
		CK_ULONG, void *, size_t *);
CK_RV attr_find_ptr(CK_ATTRIBUTE_PTR, CK_ULONG, CK_ULONG, void **, size_t *);
CK_RV attr_find_ptr2(CK_ATTRIBUTE_PTR pTemp1, CK_ULONG ulCount1,
		CK_ATTRIBUTE_PTR pTemp2, CK_ULONG ulCount2, CK_ULONG type, void **ptr, size_t * sizep);
CK_RV attr_find_and_allocate_ptr(CK_ATTRIBUTE_PTR, CK_ULONG, CK_ULONG, void **, size_t *);
CK_RV attr_find_var(CK_ATTRIBUTE_PTR, CK_ULONG, CK_ULONG, void *, size_t *);
CK_RV attr_extract(CK_ATTRIBUTE_PTR, void *, size_t *);

/* Generic Mechanism functions */
CK_RV sc_pkcs11_register_mechanism(struct sc_pkcs11_card *,
				sc_pkcs11_mechanism_type_t *);
CK_RV sc_pkcs11_get_mechanism_list(struct sc_pkcs11_card *,
				CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
CK_RV sc_pkcs11_get_mechanism_info(struct sc_pkcs11_card *, CK_MECHANISM_TYPE,
				CK_MECHANISM_INFO_PTR);
CK_RV sc_pkcs11_md_init(struct sc_pkcs11_session *, CK_MECHANISM_PTR);
CK_RV sc_pkcs11_md_update(struct sc_pkcs11_session *, CK_BYTE_PTR, CK_ULONG);
CK_RV sc_pkcs11_md_final(struct sc_pkcs11_session *, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV sc_pkcs11_sign_init(struct sc_pkcs11_session *, CK_MECHANISM_PTR,
				struct sc_pkcs11_object *, CK_MECHANISM_TYPE);
CK_RV sc_pkcs11_sign_update(struct sc_pkcs11_session *, CK_BYTE_PTR, CK_ULONG);
CK_RV sc_pkcs11_sign_final(struct sc_pkcs11_session *, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV sc_pkcs11_sign_size(struct sc_pkcs11_session *, CK_ULONG_PTR);
#ifdef ENABLE_OPENSSL
CK_RV sc_pkcs11_verif_init(struct sc_pkcs11_session *, CK_MECHANISM_PTR,
				struct sc_pkcs11_object *, CK_MECHANISM_TYPE);
CK_RV sc_pkcs11_verif_update(struct sc_pkcs11_session *, CK_BYTE_PTR, CK_ULONG);
CK_RV sc_pkcs11_verif_final(struct sc_pkcs11_session *, CK_BYTE_PTR, CK_ULONG);
#endif
CK_RV sc_pkcs11_decr_init(struct sc_pkcs11_session *, CK_MECHANISM_PTR, struct sc_pkcs11_object *, CK_MECHANISM_TYPE);
CK_RV sc_pkcs11_decr(struct sc_pkcs11_session *, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV sc_pkcs11_wrap(struct sc_pkcs11_session *,CK_MECHANISM_PTR, struct sc_pkcs11_object *, CK_KEY_TYPE, struct sc_pkcs11_object *, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV sc_pkcs11_unwrap(struct sc_pkcs11_session *,CK_MECHANISM_PTR, struct sc_pkcs11_object *, CK_KEY_TYPE, CK_BYTE_PTR, CK_ULONG, struct sc_pkcs11_object *);
CK_RV sc_pkcs11_deri(struct sc_pkcs11_session *, CK_MECHANISM_PTR,
				struct sc_pkcs11_object *, CK_KEY_TYPE,
				CK_SESSION_HANDLE, CK_OBJECT_HANDLE, struct sc_pkcs11_object *);
sc_pkcs11_mechanism_type_t *sc_pkcs11_find_mechanism(struct sc_pkcs11_card *,
				CK_MECHANISM_TYPE, unsigned int);
sc_pkcs11_mechanism_type_t *sc_pkcs11_new_fw_mechanism(CK_MECHANISM_TYPE,
				CK_MECHANISM_INFO_PTR, CK_KEY_TYPE,
				const void *, void (*)(const void *));
sc_pkcs11_operation_t *sc_pkcs11_new_operation(sc_pkcs11_session_t *,
				sc_pkcs11_mechanism_type_t *);
void sc_pkcs11_release_operation(sc_pkcs11_operation_t **);
CK_RV sc_pkcs11_register_generic_mechanisms(struct sc_pkcs11_card *);
#ifdef ENABLE_OPENSSL
void sc_pkcs11_register_openssl_mechanisms(struct sc_pkcs11_card *);
#endif
CK_RV sc_pkcs11_register_sign_and_hash_mechanism(struct sc_pkcs11_card *,
				CK_MECHANISM_TYPE, CK_MECHANISM_TYPE,
				sc_pkcs11_mechanism_type_t *);

#ifdef ENABLE_OPENSSL
CK_RV sc_pkcs11_verify_data(const unsigned char *pubkey, unsigned int pubkey_len,
	const unsigned char *pubkey_params, unsigned int pubkey_params_len,
	CK_MECHANISM_PTR mech, sc_pkcs11_operation_t *md,
	unsigned char *inp, unsigned int inp_len,
	unsigned char *signat, unsigned int signat_len);
#endif

/* Load configuration defaults */
void load_pkcs11_parameters(struct sc_pkcs11_config *, struct sc_context *);

/* Locking primitives at the pkcs11 level */
CK_RV sc_pkcs11_init_lock(CK_C_INITIALIZE_ARGS_PTR);
CK_RV sc_pkcs11_lock(void);
void sc_pkcs11_unlock(void);
void sc_pkcs11_free_lock(void);

#ifdef __cplusplus
}
#endif

#endif  /* __sc_pkcs11_h__ */
