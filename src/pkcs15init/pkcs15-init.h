/*
 * Function prototypes for pkcs15-init
 *
 * Copyright (C) 2002 Olaf Kirch <okir@suse.de>
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

#ifndef PKCS15_INIT_H
#define PKCS15_INIT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libopensc/pkcs15.h"

#define DEFAULT_PRIVATE_KEY_LABEL "Private Key"
#define DEFAULT_SECRET_KEY_LABEL  "Secret Key"

#define SC_PKCS15INIT_X509_DIGITAL_SIGNATURE     0x0080UL
#define SC_PKCS15INIT_X509_NON_REPUDIATION       0x0040UL
#define SC_PKCS15INIT_X509_KEY_ENCIPHERMENT      0x0020UL
#define SC_PKCS15INIT_X509_DATA_ENCIPHERMENT     0x0010UL
#define SC_PKCS15INIT_X509_KEY_AGREEMENT         0x0008UL
#define SC_PKCS15INIT_X509_KEY_CERT_SIGN         0x0004UL
#define SC_PKCS15INIT_X509_CRL_SIGN              0x0002UL

typedef struct sc_profile sc_profile_t; /* opaque type */

struct sc_pkcs15init_operations {
	/*
	 * Erase everything that's on the card
	 */
	int	(*erase_card)(struct sc_profile *, struct sc_pkcs15_card *);

	/*
	 * New style API
	 */

	/*
	 * Card-specific initialization of PKCS15 meta-information.
	 * Currently used by the cflex driver to read the card's
	 * serial number and use it as the pkcs15 serial number.
	 */
	int	(*init_card)(struct sc_profile *, struct sc_pkcs15_card *);

	/*
	 * Create a DF
	 */
	int	(*create_dir)(struct sc_profile *, struct sc_pkcs15_card *, struct sc_file *);

	/*
	 * Create a "pin domain". This is for cards such as
	 * the cryptoflex that need to put their pins into
	 * separate directories
	 */
	int	(*create_domain)(struct sc_profile *, struct sc_pkcs15_card *,
			const struct sc_pkcs15_id *, struct sc_file **);

	/*
	 * Select a PIN reference
	 */
	int	(*select_pin_reference)(struct sc_profile *, struct sc_pkcs15_card *,
			struct sc_pkcs15_auth_info *);

	/*
	 * Create a PIN object within the given DF.
	 *
	 * The pin_info object is completely filled in by the caller.
	 * The card driver can reject the pin reference; in this case
	 * the caller needs to adjust it.
	 */
	int	(*create_pin)(struct sc_profile *, struct sc_pkcs15_card *, struct sc_file *,
			struct sc_pkcs15_object *,
			const unsigned char *, size_t,
			const unsigned char *, size_t);

	/*
	 * Select a reference for a private key object
	 */
	int	(*select_key_reference)(struct sc_profile *, struct sc_pkcs15_card *,
			struct sc_pkcs15_prkey_info *);

	/*
	 * Create an empty key object.
	 * @index is the number key objects already on the card.
	 * @pin_info contains information on the PIN protecting
	 *		the key. NULL if the key should be
	 *		unprotected.
	 * @key_info should be filled in by the function
	 */
	int	(*create_key)(struct sc_profile *, struct sc_pkcs15_card *,
			struct sc_pkcs15_object *);

	/*
	 * Store a key on the card
	 */
	int	(*store_key)(struct sc_profile *, struct sc_pkcs15_card *,
			struct sc_pkcs15_object *,
			struct sc_pkcs15_prkey *);

	/*
	 * Generate key
	 */
	int	(*generate_key)(struct sc_profile *, struct sc_pkcs15_card *,
			struct sc_pkcs15_object *,
			struct sc_pkcs15_pubkey *);

	/*
	 * Encode private/public key
	 * These are used mostly by the Cryptoflex/Cyberflex drivers.
	 */
	int	(*encode_private_key)(struct sc_profile *, struct sc_card *,
			struct sc_pkcs15_prkey_rsa *,
			unsigned char *, size_t *, int);
	int	(*encode_public_key)(struct sc_profile *, struct sc_card *,
			struct sc_pkcs15_prkey_rsa *,
			unsigned char *, size_t *, int);

	/*
	 * Finalize card
	 * Ends the initialization phase of the smart card/token
	 * (actually this command is currently only for starcos spk 2.3
	 * cards).
	 */
	int	(*finalize_card)(struct sc_card *);

	/*
	 * Delete object
	 */
	int (*delete_object)(struct sc_profile *, struct sc_pkcs15_card *,
			struct sc_pkcs15_object *, const struct sc_path *);

	/*
	 * Support of pkcs15init emulation
	 */
	int (*emu_update_dir) (struct sc_profile *, struct sc_pkcs15_card *,
			struct sc_app_info *);
	int (*emu_update_any_df) (struct sc_profile *, struct sc_pkcs15_card *,
			unsigned, struct sc_pkcs15_object *);
	int (*emu_update_tokeninfo) (struct sc_profile *, struct sc_pkcs15_card *,
			struct sc_pkcs15_tokeninfo *);
	int (*emu_write_info)(struct sc_profile *, struct sc_pkcs15_card *,
		struct sc_pkcs15_object *);
	int (*emu_store_data)(struct sc_pkcs15_card *, struct sc_profile *, struct sc_pkcs15_object *,
			struct sc_pkcs15_der *, struct sc_path *);

	int (*sanity_check)(struct sc_profile *, struct sc_pkcs15_card *);
};

/* Do not change these or reorder these */
#define SC_PKCS15INIT_ID_STYLE_NATIVE		0
#define SC_PKCS15INIT_ID_STYLE_MOZILLA		1
#define SC_PKCS15INIT_ID_STYLE_RFC2459		2

#define SC_PKCS15INIT_SO_PIN		0
#define SC_PKCS15INIT_SO_PUK		1
#define SC_PKCS15INIT_USER_PIN		2
#define SC_PKCS15INIT_USER_PUK		3
#define SC_PKCS15INIT_NPINS		4

#define SC_PKCS15INIT_MD_STYLE_NONE	0
#define SC_PKCS15INIT_MD_STYLE_GEMALTO	1

struct sc_pkcs15init_callbacks {
	/*
	 * Get a PIN from the front-end. The first argument is
	 * one of the SC_PKCS15INIT_XXX_PIN/PUK macros.
	 */
	int	(*get_pin)(struct sc_profile *, int, const struct sc_pkcs15_auth_info *,
				const char *, unsigned char *, size_t *);

	/*
	 * Get a transport/secure messaging key from the front-end.
	 */
	int	(*get_key)(struct sc_profile *, int, int,
				const unsigned char *, size_t,
				unsigned char *, size_t *);
};

struct sc_pkcs15init_initargs {
	const unsigned char *	so_pin;
	size_t			so_pin_len;
	const unsigned char *	so_puk;
	size_t			so_puk_len;
	const char *		so_pin_label;
	const char *		label;
	const char *		serial;
};

struct sc_pkcs15init_pinargs {
	struct sc_pkcs15_id	auth_id;
	const char *		label;
	const unsigned char *	pin;
	size_t			pin_len;

	struct sc_pkcs15_id	puk_id;
	const char *		puk_label;
	const unsigned char *	puk;
	size_t			puk_len;
};

struct sc_pkcs15init_keyarg_gost_params {
	unsigned char gostr3410, gostr3411, gost28147;
};

struct sc_pkcs15init_prkeyargs {
	/* TODO: member for private key algorithm: currently is used algorithm from 'key' member */
	struct sc_pkcs15_id	id;
	struct sc_pkcs15_id	auth_id;
	char *label;
	unsigned char *guid;
	size_t guid_len;
	unsigned long		usage;
	unsigned long		x509_usage;
	unsigned int		flags;
	unsigned int		access_flags;

	union {
		struct sc_pkcs15init_keyarg_gost_params gost;
	} params;

	struct sc_pkcs15_prkey	key;
};

struct sc_pkcs15init_keygen_args {
	struct sc_pkcs15init_prkeyargs prkey_args;
	const char *                   pubkey_label;
};

struct sc_pkcs15init_pubkeyargs {
	struct sc_pkcs15_id	id;
	struct sc_pkcs15_id	auth_id;
	const char *		label;
	unsigned long		usage;
	unsigned long		x509_usage;

	union {
		struct sc_pkcs15init_keyarg_gost_params gost;
	} params;

	struct sc_pkcs15_pubkey	key;
};

struct sc_pkcs15init_dataargs {
	struct sc_pkcs15_id	id;
	const char *		label;
	struct sc_pkcs15_id	auth_id;
	const char *		app_label;
	struct sc_object_id	app_oid;

	struct sc_pkcs15_der	der_encoded; /* Wrong name: is not DER encoded */
};

struct sc_pkcs15init_skeyargs {
	struct sc_pkcs15_id	id;
	struct sc_pkcs15_id	auth_id;
	const char *		label;
	unsigned long           usage;
	unsigned int		flags;
	unsigned int		access_flags;
	unsigned long		algorithm; /* User requested algorithm */
	unsigned long		value_len; /* User requested length */

	struct sc_pkcs15_skey	key;
};

struct sc_pkcs15init_certargs {
	struct sc_pkcs15_id	id;
	const char *		label;
	int update;

	unsigned long		x509_usage;
	unsigned char		authority;
	struct sc_pkcs15_der	der_encoded;
};

#define P15_ATTR_TYPE_LABEL	0
#define P15_ATTR_TYPE_ID	1


extern struct	sc_pkcs15_object *sc_pkcs15init_new_object(int, const char *,
				struct sc_pkcs15_id *, void *);
extern void		sc_pkcs15init_free_object(struct sc_pkcs15_object *);
extern void	sc_pkcs15init_set_callbacks(struct sc_pkcs15init_callbacks *);
extern int	sc_pkcs15init_bind(struct sc_card *, const char *, const char *,
				struct sc_app_info *app_info, struct sc_profile **);
extern void	sc_pkcs15init_unbind(struct sc_profile *);
extern void	sc_pkcs15init_set_p15card(struct sc_profile *,
				struct sc_pkcs15_card *);
extern int	sc_pkcs15init_set_lifecycle(struct sc_card *, int);
extern int	sc_pkcs15init_erase_card(struct sc_pkcs15_card *,
				struct sc_profile *, struct sc_aid *);
/* XXX could this function be merged with ..._set_lifecycle ?? */
extern int	sc_pkcs15init_finalize_card(struct sc_card *,
				struct sc_profile *);
extern int	sc_pkcs15init_add_app(struct sc_card *,
				struct sc_profile *,
				struct sc_pkcs15init_initargs *);
extern int	sc_pkcs15init_store_pin(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_pinargs *);
extern int	sc_pkcs15init_generate_key(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_keygen_args *,
				unsigned int keybits,
				struct sc_pkcs15_object **);
extern int	sc_pkcs15init_generate_secret_key(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_skeyargs *,
				struct sc_pkcs15_object **);
extern int	sc_pkcs15init_store_private_key(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_prkeyargs *,
				struct sc_pkcs15_object **);
extern int	sc_pkcs15init_store_split_key(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_prkeyargs *,
				struct sc_pkcs15_object **,
				struct sc_pkcs15_object **);
extern int	sc_pkcs15init_store_public_key(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_pubkeyargs *,
				struct sc_pkcs15_object **);
extern int	sc_pkcs15init_store_secret_key(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_skeyargs *,
				struct sc_pkcs15_object **);
extern int	sc_pkcs15init_store_certificate(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_certargs *,
				struct sc_pkcs15_object **);
extern int	sc_pkcs15init_store_data_object(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_dataargs *,
				struct sc_pkcs15_object **);
/* Change the value of a pkcs15 attribute.
 * new_attrib_type can (currently) be either P15_ATTR_TYPE_LABEL or
 *   P15_ATTR_TYPE_ID.
 * If P15_ATTR_TYPE_LABEL, then *new_value is a struct sc_pkcs15_id;
 * If P15_ATTR_TYPE_ID, then *new_value is a char array.
 */
extern int	sc_pkcs15init_change_attrib(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15_object *,
				int,
				void *,
				int);
extern int	sc_pkcs15init_add_object(struct sc_pkcs15_card *,
			struct sc_profile *profile,
			unsigned int,
			struct sc_pkcs15_object *);
extern int	sc_pkcs15init_delete_object(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15_object *);
/* Replace an existing cert with a new one, which is assumed to be
 * compatible with the corresponding private key (e.g. the old and
 * new cert should have the same public key).
 */
extern int	sc_pkcs15init_update_certificate(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15_object *,
				const unsigned char *,
				size_t);

extern int	sc_pkcs15init_create_file(struct sc_profile *,
				struct sc_pkcs15_card *, struct sc_file *);
extern int	sc_pkcs15init_update_file(struct sc_profile *,
				struct sc_pkcs15_card *, struct sc_file *, void *, unsigned int);
extern int	sc_pkcs15init_authenticate(struct sc_profile *, struct sc_pkcs15_card *,
				struct sc_file *, int);
extern int	sc_pkcs15init_fixup_file(struct sc_profile *, struct sc_pkcs15_card *,
				struct sc_file *);
extern int	sc_pkcs15init_get_pin_info(struct sc_profile *, int, struct sc_pkcs15_auth_info *);
extern int	sc_profile_get_pin_retries(struct sc_profile *, int);
extern int	sc_pkcs15init_get_manufacturer(struct sc_profile *,
				const char **);
extern int	sc_pkcs15init_get_serial(struct sc_profile *, const char **);
extern int	sc_pkcs15init_set_serial(struct sc_profile *, const char *);

extern int	sc_pkcs15init_verify_secret(struct sc_profile *, struct sc_pkcs15_card *,
				sc_file_t *,  unsigned int, int);
extern int	sc_pkcs15init_delete_by_path(struct sc_profile *,
				struct sc_pkcs15_card *, const struct sc_path *);
extern int	sc_pkcs15init_update_any_df(struct sc_pkcs15_card *, struct sc_profile *,
			struct sc_pkcs15_df *, int);
extern int	sc_pkcs15init_select_intrinsic_id(struct sc_pkcs15_card *, struct sc_profile *,
			int, struct sc_pkcs15_id *, void *);

/* Erasing the card structure via rm -rf */
extern int	sc_pkcs15init_erase_card_recursively(struct sc_pkcs15_card *,
				struct sc_profile *);
extern int	sc_pkcs15init_rmdir(struct sc_pkcs15_card *, struct sc_profile *,
				struct sc_file *);

extern int	sc_pkcs15_create_pin_domain(struct sc_profile *, struct sc_pkcs15_card *,
				const struct sc_pkcs15_id *, struct sc_file **);

extern int	sc_pkcs15init_get_pin_reference(struct sc_pkcs15_card *,
				struct sc_profile *, unsigned, int);

extern int	sc_pkcs15init_sanity_check(struct sc_pkcs15_card *, struct sc_profile *);

extern int	sc_pkcs15init_finalize_profile(struct sc_card *card, struct sc_profile *profile,
		                struct sc_aid *aid);

extern struct sc_pkcs15init_operations *sc_pkcs15init_get_gpk_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_miocos_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_cryptoflex_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_cyberflex_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_cardos_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_jcop_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_starcos_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_oberthur_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_setcos_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_incrypto34_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_muscle_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_asepcos_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_rutoken_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_entersafe_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_epass2003_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_rtecp_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_westcos_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_myeid_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_authentic_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_iasecc_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_piv_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_openpgp_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_sc_hsm_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_isoApplet_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_gids_ops(void);

#ifdef __cplusplus
}
#endif

#endif /* PKCS15_INIT_H */
