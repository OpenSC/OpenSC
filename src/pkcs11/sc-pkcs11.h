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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#include <opensc/log.h>

#ifndef _WIN32
#include "rsaref/unix.h"
#include "rsaref/pkcs11.h"
#else
#include "rsaref/win32.h"
#pragma pack(push, cryptoki, 1)
#include "rsaref/pkcs11.h"
#pragma pack(pop, cryptoki)
#endif

/* Decide whether to use pkcs11 for initialization support */
#ifdef HAVE_OPENSSL
#define USE_PKCS15_INIT
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SC_PKCS11_MAX_VIRTUAL_SLOTS	8
#define SC_PKCS11_DEF_SLOTS_PER_CARD	4
#define SC_PKCS11_MAX_READERS           SC_MAX_READERS

struct sc_pkcs11_session;
struct sc_pkcs11_slot;
struct sc_pkcs11_card;

/* Object Pool */
struct sc_pkcs11_pool_item {
	int handle;
        void *item;
	struct sc_pkcs11_pool_item *next;
        struct sc_pkcs11_pool_item *prev;
};

enum {
	POOL_TYPE_SESSION,
	POOL_TYPE_OBJECT
};

struct sc_pkcs11_pool {
	int type;
        int next_free_handle;
	int num_items;
	struct sc_pkcs11_pool_item *head;
        struct sc_pkcs11_pool_item *tail;
};

struct sc_pkcs11_config {
	unsigned int num_slots;
	unsigned char hide_empty_tokens;
	unsigned char lock_login;
	unsigned char cache_pins;
	unsigned char soft_keygen_allowed;
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
	int   (*cmp_attribute)(struct sc_pkcs11_session *, void *, CK_ATTRIBUTE_PTR);

	CK_RV (*destroy_object)(struct sc_pkcs11_session *, void *);
        CK_RV (*get_size)(struct sc_pkcs11_session *, void *);

	/* Cryptographic methods */
	CK_RV (*sign)(struct sc_pkcs11_session *, void *, CK_MECHANISM_PTR pMechanism, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulDataLen);
	CK_RV (*unwrap_key)(struct sc_pkcs11_session *, void *,
			CK_MECHANISM_PTR,
			CK_BYTE_PTR pData, CK_ULONG ulDataLen,
			CK_ATTRIBUTE_PTR, CK_ULONG,
			void **);
        /* Others to be added when implemented */
};

struct sc_pkcs11_object {
	int flags;
        struct sc_pkcs11_object_ops *ops;
};

#define SC_PKCS11_OBJECT_SEEN	0x0001
#define SC_PKCS11_OBJECT_HIDDEN	0x0002
#define SC_PKCS11_OBJECT_RECURS	0x8000


/*
 * PKCS#11 Smartcard Framework abstraction
 */

struct sc_pkcs11_framework_ops {
        /* Detect and bind card to framework */
	CK_RV (*bind)(struct sc_pkcs11_card *);
        /* Unbind and release allocated resources */
	CK_RV (*unbind)(struct sc_pkcs11_card *);

	/* Create tokens to virtual slots and
	 * objects in tokens; called after bind */
	CK_RV (*create_tokens)(struct sc_pkcs11_card *);
        CK_RV (*release_token)(struct sc_pkcs11_card *, void *);

	/* Login and logout */
	CK_RV (*login)(struct sc_pkcs11_card *, void *,
				CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG);
        CK_RV (*logout)(struct sc_pkcs11_card *, void *);
	CK_RV (*change_pin)(struct sc_pkcs11_card *, void *,
				CK_CHAR_PTR, CK_ULONG,
				CK_CHAR_PTR, CK_ULONG);

	/*
	 * In future: functions to create new objects
	 * (ie. certificates, private keys)
         */
	CK_RV (*init_token)(struct sc_pkcs11_card *, void *,
				CK_UTF8CHAR_PTR, CK_ULONG,
				CK_UTF8CHAR_PTR);
	CK_RV (*init_pin)(struct sc_pkcs11_card *,
				struct sc_pkcs11_slot *,
				CK_UTF8CHAR_PTR, CK_ULONG);
	CK_RV (*create_object)(struct sc_pkcs11_card *,
				struct sc_pkcs11_slot *,
				CK_ATTRIBUTE_PTR, CK_ULONG,
				CK_OBJECT_HANDLE_PTR);
	CK_RV (*gen_keypair)(struct sc_pkcs11_card *p11card,
				struct sc_pkcs11_slot *slot,
				CK_MECHANISM_PTR pMechanism,
				CK_ATTRIBUTE_PTR pPubKeyTempl, CK_ULONG ulPubKeyAttrCnt,
				CK_ATTRIBUTE_PTR pPrivKeyTempl, CK_ULONG ulPrivKeyAttrCnt,
				CK_OBJECT_HANDLE_PTR phPubKey, CK_OBJECT_HANDLE_PTR phPrivKey);
};


/*
 * PKCS#11 Slot (used to access card with specific framework data)
 */

struct sc_pkcs11_card {
        int reader;
	struct sc_card *card;
        struct sc_pkcs11_framework_ops *framework;
	void *fw_data;
	sc_timestamp_t slot_state_expires;

	/* Number of slots owned by this card object */
	unsigned int num_slots;
	unsigned int max_slots;
	unsigned int first_slot;

	/* List of supported mechanisms */
	struct sc_pkcs11_mechanism_type **mechanisms;
	unsigned int nmechanisms;
};

struct sc_pkcs11_slot {
	int id;
        int login_user;
        /* Slot specific information (information about reader) */
	CK_SLOT_INFO slot_info;
	/* Token specific information (information about card) */
        CK_TOKEN_INFO token_info;

	/* Reader to which card is allocated (same as card->reader
	 * if there's a card present) */
	int reader;

        /* The card associated with this slot */
	struct sc_pkcs11_card *card;
	/* Card events SC_EVENT_CARD_{INSERTED,REMOVED} */
	int events;
	/* Framework specific data */
	void *fw_data;
	/* Object pools */
	struct sc_pkcs11_pool object_pool;
	/* Number of sessions using this slot */
	unsigned int nsessions;
};
typedef struct sc_pkcs11_slot sc_pkcs11_slot_t;


/* Forward decl */
typedef struct sc_pkcs11_operation sc_pkcs11_operation_t;

enum {
	SC_PKCS11_OPERATION_FIND = 0,
	SC_PKCS11_OPERATION_SIGN,
	SC_PKCS11_OPERATION_VERIFY,
	SC_PKCS11_OPERATION_DIGEST,
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
#ifdef HAVE_OPENSSL
	CK_RV		  (*verif_init)(sc_pkcs11_operation_t *,
					struct sc_pkcs11_object *);
	CK_RV		  (*verif_update)(sc_pkcs11_operation_t *,
					CK_BYTE_PTR, CK_ULONG);
	CK_RV		  (*verif_final)(sc_pkcs11_operation_t *,
					CK_BYTE_PTR, CK_ULONG);
#endif
	/* mechanism specific data */
	const void *		  mech_data;
};
typedef struct sc_pkcs11_mechanism_type sc_pkcs11_mechanism_type_t;

/*
 * Generic operation
 */
struct sc_pkcs11_operation {
	sc_pkcs11_mechanism_type_t *type;
	CK_MECHANISM	  mechanism;
	struct sc_pkcs11_session *session;
	void *		  priv_data;
};

/* Find Operation */
#define SC_PKCS11_FIND_MAX_HANDLES	32
struct sc_pkcs11_find_operation {
	struct sc_pkcs11_operation operation;
        int num_handles, current_handle;
        CK_OBJECT_HANDLE handles[SC_PKCS11_FIND_MAX_HANDLES];
};

/*
 * PKCS#11 Session
 */

struct sc_pkcs11_session {
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
extern struct sc_pkcs11_pool session_pool;
extern struct sc_pkcs11_slot virtual_slots[SC_PKCS11_MAX_VIRTUAL_SLOTS];
extern struct sc_pkcs11_card card_table[SC_PKCS11_MAX_READERS];
extern struct sc_pkcs11_config sc_pkcs11_conf;
extern unsigned int first_free_slot;

/* Framework definitions */
extern struct sc_pkcs11_framework_ops framework_pkcs15;
extern struct sc_pkcs11_framework_ops framework_pkcs15init;

void strcpy_bp(u8 *dst, const char *src, int dstsize);
CK_RV sc_to_cryptoki_error(int rc, int reader);
void sc_pkcs11_print_attrs(const char *file, unsigned int line, const char *function,
		const char *info, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
#define dump_template(info, pTemplate, ulCount) \
		sc_pkcs11_print_attrs(__FILE__, __LINE__, __FUNCTION__, \
				info, pTemplate, ulCount)

/* Slot and card handling functions */
CK_RV card_initialize(int reader);
CK_RV card_detect_all(void);
CK_RV __card_detect_all(int);
CK_RV card_detect(int reader);
CK_RV card_removed(int reader);
CK_RV slot_initialize(int id, struct sc_pkcs11_slot *);
CK_RV slot_get_slot(int id, struct sc_pkcs11_slot **);
CK_RV slot_get_token(int id, struct sc_pkcs11_slot **);
CK_RV slot_token_removed(int id);
CK_RV slot_find_changed(CK_SLOT_ID_PTR idp, int mask);
CK_RV slot_allocate(struct sc_pkcs11_slot **, struct sc_pkcs11_card *);

/* Pool */
CK_RV pool_initialize(struct sc_pkcs11_pool *, int);
CK_RV pool_insert(struct sc_pkcs11_pool *, void *, CK_ULONG_PTR);
CK_RV pool_find(struct sc_pkcs11_pool *, CK_ULONG, void **);
CK_RV pool_find_and_delete(struct sc_pkcs11_pool *, CK_ULONG, void **);

/* Session manipulation */
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
int sc_pkcs11_any_cmp_attribute(struct sc_pkcs11_session *,
			void *, CK_ATTRIBUTE_PTR);

/* Get attributes from template (misc.c) */
CK_RV attr_find(CK_ATTRIBUTE_PTR, CK_ULONG, CK_ULONG, void *, size_t *);
CK_RV attr_find2(CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG,
		CK_ULONG, void *, size_t *);
CK_RV attr_find_ptr(CK_ATTRIBUTE_PTR, CK_ULONG, CK_ULONG, void **, size_t *);
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
#ifdef HAVE_OPENSSL
CK_RV sc_pkcs11_verif_init(struct sc_pkcs11_session *, CK_MECHANISM_PTR,
				struct sc_pkcs11_object *, CK_MECHANISM_TYPE);
CK_RV sc_pkcs11_verif_update(struct sc_pkcs11_session *, CK_BYTE_PTR, CK_ULONG);
CK_RV sc_pkcs11_verif_final(struct sc_pkcs11_session *, CK_BYTE_PTR, CK_ULONG);
#endif
CK_RV sc_pkcs11_sign_hash(struct sc_pkcs11_session *, CK_BYTE_PTR, CK_ULONG,
				CK_BYTE_PTR, CK_ULONG_PTR);
sc_pkcs11_mechanism_type_t *sc_pkcs11_find_mechanism(struct sc_pkcs11_card *,
				CK_MECHANISM_TYPE, int);
sc_pkcs11_mechanism_type_t *sc_pkcs11_new_fw_mechanism(CK_MECHANISM_TYPE,
				CK_MECHANISM_INFO_PTR, CK_KEY_TYPE,
				void *);
sc_pkcs11_operation_t *sc_pkcs11_new_operation(sc_pkcs11_session_t *,
				sc_pkcs11_mechanism_type_t *);
void sc_pkcs11_release_operation(sc_pkcs11_operation_t **);
CK_RV sc_pkcs11_register_generic_mechanisms(struct sc_pkcs11_card *);
#ifdef HAVE_OPENSSL
void sc_pkcs11_register_openssl_mechanisms(struct sc_pkcs11_card *);
#endif
CK_RV sc_pkcs11_register_sign_and_hash_mechanism(struct sc_pkcs11_card *,
				CK_MECHANISM_TYPE, CK_MECHANISM_TYPE,
				sc_pkcs11_mechanism_type_t *);

#ifdef HAVE_OPENSSL
/* Random generation functions */
CK_RV sc_pkcs11_openssl_add_seed_rand(struct sc_pkcs11_session *, CK_BYTE_PTR, CK_ULONG);
CK_RV sc_pkcs11_openssl_add_gen_rand(struct sc_pkcs11_session *, CK_BYTE_PTR, CK_ULONG);
CK_RV sc_pkcs11_gen_keypair_soft(CK_KEY_TYPE keytype, CK_ULONG keybits,
	struct sc_pkcs15_prkey *privkey, struct sc_pkcs15_pubkey *pubkey);
CK_RV sc_pkcs11_verify_data(unsigned char *pubkey, int pubkey_len,
	CK_MECHANISM_TYPE mech, sc_pkcs11_operation_t *md,
	unsigned char *inp, int inp_len,
	unsigned char *signat, int signat_len);
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

#endif
