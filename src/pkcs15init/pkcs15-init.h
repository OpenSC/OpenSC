/*
 * Function prototypes for pkcs15-init
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
 */

#ifndef PKCS15_INIT_H
#define PKCS15_INIT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <opensc/pkcs15.h>

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
	int	(*erase_card)(struct sc_profile *, struct sc_card *);

	/*
	 * New style API
	 */

	/*
	 * Card-specific initialization of PKCS15 meta-information.
	 * Currently used by the cflex driver to read the card's
	 * serial number and use it as the pkcs15 serial number.
	 */
	int	(*init_card)(sc_profile_t *, sc_card_t *);

	/*
	 * Create a DF
	 */
	int	(*create_dir)(sc_profile_t *, sc_card_t *, sc_file_t *);

	/*
	 * Create a "pin domain". This is for cards such as
	 * the cryptoflex that need to put their pins into
	 * separate directories
	 */
	int	(*create_domain)(sc_profile_t *, sc_card_t *,
			const sc_pkcs15_id_t *, sc_file_t **);

	/*
	 * Select a PIN reference
	 */
	int	(*select_pin_reference)(sc_profile_t *, sc_card_t *,
			sc_pkcs15_pin_info_t *);

	/*
	 * Create a PIN object within the given DF.
	 *
	 * The pin_info object is completely filled in by the caller.
	 * The card driver can reject the pin reference; in this case
	 * the caller needs to adjust it.
	 */
	int	(*create_pin)(sc_profile_t *, sc_card_t *, sc_file_t *,
			sc_pkcs15_object_t *,
			const u8 *pin, size_t pin_len,
			const u8 *puk, size_t puk_len);

	/*
	 * Select a reference for a private key object
	 */
	int	(*select_key_reference)(sc_profile_t *, sc_card_t *,
			sc_pkcs15_prkey_info_t *);

	/*
	 * Create an empty key object.
	 * @index is the number key objects already on the card.
	 * @pin_info contains information on the PIN protecting
	 * 		the key. NULL if the key should be
	 * 		unprotected.
	 * @key_info should be filled in by the function
	 */
	int	(*create_key)(sc_profile_t *, sc_card_t *,
			sc_pkcs15_object_t *o);

	/*
	 * Store a key on the card
	 */
	int	(*store_key)(sc_profile_t *, sc_card_t *,
			sc_pkcs15_object_t *,
			sc_pkcs15_prkey_t *);

	/*
	 * Generate key
	 */
	int	(*generate_key)(sc_profile_t *, sc_card_t *,
			sc_pkcs15_object_t *,
			sc_pkcs15_pubkey_t *);

	/*
	 * Encode private/public key
	 * These are used mostly by the Cryptoflex/Cyberflex drivers.
	 */
	int	(*encode_private_key)(sc_profile_t *, sc_card_t *,
			struct sc_pkcs15_prkey_rsa *,
			u8 *buf, size_t *bufsize, int key_ref);
	int	(*encode_public_key)(sc_profile_t *, sc_card_t *,
			struct sc_pkcs15_prkey_rsa *,
			u8 *buf, size_t *bufsize, int key_ref);

	/*
	 * Finalize card
	 * Ends the initialization phase of the smart card/token
	 * (actually this command is currently only for starcos spk 2.3
	 * cards).
	 */
	int	(*finalize_card)(sc_card_t *);

	/*
	 * Old-style API
	 */

	/*
	 * Initialize application, and optionally set a SO pin
	 */
	int	(*init_app)(struct sc_profile *, struct sc_card *,
			struct sc_pkcs15_pin_info *,
			const u8 *pin, size_t pin_len,
			const u8 *puk, size_t puk_len);

	/*
	 * Store a new PIN
	 * On some cards (such as the CryptoFlex) this will create
	 * a new subdirectory of the AppDF.
	 * Index is the number of the PIN in the AODF (this should
	 * help the card driver to pick the right file ID/directory ID/
	 * pin file index.
	 */
	int	(*new_pin)(struct sc_profile *, struct sc_card *,
			struct sc_pkcs15_pin_info *, unsigned int idx,
			const u8 *pin, size_t pin_len,
			const u8 *puk, size_t puk_len);

	/*
	 * Store a key on the card
	 */
	int	(*new_key)(struct sc_profile *, struct sc_card *,
			struct sc_pkcs15_prkey *key, unsigned int idx,
			struct sc_pkcs15_prkey_info *);

	/*
	 * Create a file based on a PKCS15_TYPE_xxx
	 */
	int	(*new_file)(struct sc_profile *, struct sc_card *,
			unsigned int, unsigned int, struct sc_file **out);

	/*
	 * Generate a new key pair
	 */
	int	(*old_generate_key)(struct sc_profile *, struct sc_card *,
			unsigned int idx, unsigned int keybits,
			sc_pkcs15_pubkey_t *pubkey_res,
			struct sc_pkcs15_prkey_info *);

	/*
	 * Delete object
	 */
	int (*delete_object)(struct sc_profile *, struct sc_card *,
			unsigned int type, const void *data, const sc_path_t *path);
};

/* Do not change these or reorder these */
#define SC_PKCS15INIT_SO_PIN		0
#define SC_PKCS15INIT_SO_PUK		1
#define SC_PKCS15INIT_USER_PIN		2
#define SC_PKCS15INIT_USER_PUK		3
#define SC_PKCS15INIT_NPINS		4

struct sc_pkcs15init_callbacks {
	/*
	 * Get a PIN from the front-end. The first argument is
	 * one of the SC_PKCS15INIT_XXX_PIN/PUK macros.
	 */
	int	(*get_pin)(struct sc_profile *, int,
				const struct sc_pkcs15_pin_info *,
				const char *label,
				u8 *, size_t *);

	/*
	 * Get a transport/secure messaging key from the front-end.
	 */
	int	(*get_key)(struct sc_profile *,
				int method, int reference,
				const u8 *def_key, size_t def_size,
				u8 *key_buf, size_t *key_size);
};

struct sc_pkcs15init_initargs {
	const u8 *		so_pin;
	size_t			so_pin_len;
	const u8 *		so_puk;
	size_t			so_puk_len;
	const char *		so_pin_label;
	const char *		label;
	const char *		serial;
};

struct sc_pkcs15init_pinargs {
	struct sc_pkcs15_id	auth_id;
	const char *		label;
	const u8 *		pin;
	size_t			pin_len;
	const u8 *		puk;
	size_t			puk_len;
};

struct sc_pkcs15init_keyarg_gost_params {
	unsigned char gostr3410, gostr3411, gost28147;
};

struct sc_pkcs15init_prkeyargs {
	struct sc_pkcs15_id	id;
	struct sc_pkcs15_id	auth_id;
	const char *		label;
	unsigned long		usage;
	unsigned long		x509_usage;
	unsigned int		flags;
	struct sc_pkcs15init_keyarg_gost_params gost_params;

	sc_pkcs15_prkey_t	key;

	/* support for non-native keys */
	char *			passphrase;
};

struct sc_pkcs15init_keygen_args {
	struct sc_pkcs15init_prkeyargs prkey_args;
	const char *                   pubkey_label;
};

#define SC_PKCS15INIT_EXTRACTABLE	0x0001
#define SC_PKCS15INIT_NO_PASSPHRASE	0x0002
#define SC_PKCS15INIT_SPLIT_KEY		0x0004

struct sc_pkcs15init_pubkeyargs {
	struct sc_pkcs15_id	id;
	struct sc_pkcs15_id	auth_id;
	const char *		label;
	unsigned long		usage;
	unsigned long		x509_usage;
	struct sc_pkcs15init_keyarg_gost_params gost_params;

	sc_pkcs15_pubkey_t	key;
};

struct sc_pkcs15init_dataargs {
	struct sc_pkcs15_id	id;
	const char *		label;
	struct sc_pkcs15_id	auth_id;
	const char *		app_label;
	struct sc_object_id	app_oid;

	sc_pkcs15_der_t		der_encoded; /* Wrong name: is not DER encoded */
};

struct sc_pkcs15init_certargs {
	struct sc_pkcs15_id	id;
	const char *		label;

	unsigned long		x509_usage;
	unsigned char		authority;
	sc_pkcs15_der_t		der_encoded;
};

#define P15_ATTR_TYPE_LABEL	0
#define P15_ATTR_TYPE_ID	1

extern void	sc_pkcs15init_set_callbacks(struct sc_pkcs15init_callbacks *);
extern int	sc_pkcs15init_bind(struct sc_card *, const char *, const char *,
				struct sc_profile **);
extern void	sc_pkcs15init_unbind(struct sc_profile *);
extern void	sc_pkcs15init_set_p15card(sc_profile_t *,
				sc_pkcs15_card_t *);
extern int	sc_pkcs15init_set_lifecycle(sc_card_t *card, int lcycle);
extern int	sc_pkcs15init_erase_card(struct sc_card *,
				struct sc_profile *);
/* XXX could this function be merged with ..._set_lifecycle ?? */
extern int	sc_pkcs15init_finalize_card(sc_card_t *,
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
extern int	sc_pkcs15init_change_attrib(struct sc_pkcs15_card *p15card,
				struct sc_profile *profile,
				struct sc_pkcs15_object *object,
				int new_attrib_type,
				void *new_value,
				int new_len);
extern int	sc_pkcs15init_delete_object(sc_pkcs15_card_t *p15card,
				sc_profile_t *profile,
				sc_pkcs15_object_t *obj);
/* Replace an existing cert with a new one, which is assumed to be
 * compatible with the correcsponding private key (e.g. the old and
 * new cert should have the same public key).
 */
extern int	sc_pkcs15init_update_certificate(sc_pkcs15_card_t *p15card,
				sc_profile_t *profile,
				sc_pkcs15_object_t *obj,
				const unsigned char *rawcert,
				size_t certlen);

extern int	sc_pkcs15init_create_file(struct sc_profile *,
				struct sc_card *, struct sc_file *);
extern int	sc_pkcs15init_update_file(struct sc_profile *,
				struct sc_card *, struct sc_file *, void *, unsigned int);
extern int	sc_pkcs15init_authenticate(struct sc_profile *,
				struct sc_card *, struct sc_file *, int);
extern int	sc_pkcs15init_fixup_file(struct sc_profile *, struct sc_file *);
extern int	sc_pkcs15init_fixup_acls(struct sc_profile *,
				struct sc_file *,
				struct sc_acl_entry *,
				struct sc_acl_entry *);
extern int	sc_pkcs15init_get_pin_info(struct sc_profile *, unsigned int,
				struct sc_pkcs15_pin_info *);
extern int	sc_profile_get_pin_retries(sc_profile_t *, unsigned int);
extern int	sc_pkcs15init_get_manufacturer(struct sc_profile *,
				const char **);
extern int	sc_pkcs15init_get_serial(struct sc_profile *, const char **);
extern int	sc_pkcs15init_set_serial(struct sc_profile *, const char *);
extern int	sc_pkcs15init_get_label(struct sc_profile *, const char **);

extern void	sc_pkcs15init_set_secret(struct sc_profile *,
				int, int, u8 *, size_t);
extern int	sc_pkcs15init_set_pin_data(struct sc_profile *, int,
				const u8 *, size_t);
extern int	sc_pkcs15init_verify_key(struct sc_profile *, struct sc_card *,
				sc_file_t *,  unsigned int, unsigned int);
extern int	sc_pkcs15init_delete_by_path(struct sc_profile *,
				struct sc_card *, const sc_path_t *path);
extern int  sc_pkcs15init_update_any_df(sc_pkcs15_card_t *, sc_profile_t *, 
			sc_pkcs15_df_t *, int);

/* Erasing the card structure via rm -rf */
extern int	sc_pkcs15init_erase_card_recursively(struct sc_card *,
				struct sc_profile *, int so_ref);
extern int	sc_pkcs15init_rmdir(struct sc_card *, struct sc_profile *,
				struct sc_file *df);

/* Helper function for CardOS */
extern int	sc_pkcs15init_requires_restrictive_usage(
				struct sc_pkcs15_card *,
				struct sc_pkcs15init_prkeyargs *,
				unsigned int);

extern int	sc_pkcs15_create_pin_domain(sc_profile_t *, sc_card_t *,
				const sc_pkcs15_id_t *, sc_file_t **);

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
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_rtecp_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_westcos_ops(void);
extern struct sc_pkcs15init_operations *sc_pkcs15init_get_myeid_ops(void);

#ifdef __cplusplus
}
#endif

#endif /* PKCS15_INIT_H */
