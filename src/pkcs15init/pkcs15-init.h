/*
 * Function prototypes for pkcs15-init
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
 */

#ifndef PKCS15_INIT_H
#define PKCS15_INIT_H

#include <opensc-pkcs15.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

struct sc_profile; /* opaque type */

struct sc_pkcs15init_operations {
	/*
	 * Erase everything that's on the card
	 * So far, only the GPK supports this
	 */
	int	(*erase_card)(struct sc_profile *, struct sc_card *);

	/*
	 * Initialize application, and optionally set a SO pin
	 */
	int	(*init_app)(struct sc_profile *, struct sc_card *,
			const unsigned char *pin, size_t pin_len,
			const unsigned char *puk, size_t puk_len);

	/*
	 * Store a new PIN
	 * On some cards (such as the CryptoFlex) this will create
	 * a new subdirectory of the AppDF.
	 * Index is the number of the PIN in the AODF (this should
	 * help the card driver to pick the right file ID/directory ID/
	 * pin file index.
	 */
	int	(*new_pin)(struct sc_profile *, struct sc_card *,
			struct sc_pkcs15_pin_info *, unsigned int index,
			const unsigned char *pin, size_t pin_len,
			const unsigned char *puk, size_t puk_len);

	/*
	 * Store a key on the card
	 */
	int	(*new_key)(struct sc_profile *, struct sc_card *,
			EVP_PKEY *key, unsigned int index,
			struct sc_pkcs15_prkey_info *);

	/*
	 * Create a file based on a PKCS15_TYPE_xxx
	 */
	int	(*new_file)(struct sc_profile *, struct sc_card *,
			unsigned int, unsigned int, struct sc_file **out);
};

#define SC_PKCS15INIT_SO_PIN		0
#define SC_PKCS15INIT_SO_PUK		1
#define SC_PKCS15INIT_USER_PIN		2
#define SC_PKCS15INIT_USER_PUK		3
#define SC_PKCS15INIT_NPINS		4

struct sc_pkcs15init_callbacks {
	/* Error and debug output */
	void	(*error)(const char *, ...);
	void	(*debug)(const char *, ...);

	/*
	 * Get a PIN from the front-end. The first argument is
	 * one if the SC_PKCS15INIT_XXX_PIN/PUK macros.
	 */
	int	(*get_pin)(struct sc_profile *, int,
				const struct sc_pkcs15_pin_info *,
				u8 *, size_t *);
	int	(*get_key)(struct sc_profile *,
				const char *prompt, u8 *, size_t *);
};

struct sc_pkcs15init_initargs {
	const u8 *		so_pin;
	size_t			so_pin_len;
	const u8 *		so_puk;
	size_t			so_puk_len;
};

struct sc_pkcs15init_pinargs {
	struct sc_pkcs15_id	auth_id;
	const char *		label;
	const u8 *		pin;
	size_t			pin_len;
	const u8 *		puk;
	size_t			puk_len;
};

struct sc_pkcs15init_keyargs {
	struct sc_pkcs15_id	id;
	struct sc_pkcs15_id	auth_id;
	const char *		label;
	const char *		template_name;
	unsigned long		usage;

	/* For key generation */
	unsigned char		onboard_keygen;
	unsigned int		algorithm;
	unsigned int		keybits;

	EVP_PKEY *		pkey;
	X509 *			cert;
};

struct sc_pkcs15init_certargs {
	struct sc_pkcs15_id	id;
	const char *		label;
	const char *		template_name;

	X509 *			cert;
};

extern void	sc_pkcs15init_set_callbacks(struct sc_pkcs15init_callbacks *);
extern int	sc_pkcs15init_bind(struct sc_profile *,
				struct sc_card *, const char *);
extern int	sc_pkcs15init_add_app(struct sc_card *,
				struct sc_profile *,
				struct sc_pkcs15init_initargs *);
extern int	sc_pkcs15init_store_pin(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_pinargs *);
extern int	sc_pkcs15init_generate_key(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_keyargs *);
extern int	sc_pkcs15init_store_private_key(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_keyargs *);
extern int	sc_pkcs15init_store_public_key(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_keyargs *);
extern int	sc_pkcs15init_store_certificate(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_certargs *);

extern int	sc_pkcs15init_create_file(struct sc_profile *,
				struct sc_card *, struct sc_file *);
extern int	sc_pkcs15init_update_file(struct sc_profile *,
				struct sc_card *, struct sc_file *, void *, unsigned int);
extern int	sc_pkcs15init_authenticate(struct sc_profile *,
				struct sc_card *, struct sc_file *, int);
extern int	sc_pkcs15init_present_pin(struct sc_profile *,
				struct sc_card *, unsigned int);
extern int	sc_pkcs15init_fixup_file(struct sc_profile *, struct sc_file *);
extern int	sc_pkcs15init_fixup_acls(struct sc_profile *,
				struct sc_file *,
				struct sc_acl_entry *,
				struct sc_acl_entry *);

#endif /* PKCS15_INIT_H */
