/*
 * Function prototypes for pkcs15-init
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
 */

#ifndef PKCS15_INIT_H
#define PKCS15_INIT_H

#include <openssl/evp.h>
#include <openssl/x509.h>
#include "profile.h"

struct pkcs15_init_operations {
	int	(*erase_card)(struct sc_profile *, struct sc_card *);
	int	(*init_app)(struct sc_profile *, struct sc_card *);
	int	(*allocate_file)(struct sc_profile *, struct sc_card *,
			unsigned int, unsigned int, struct sc_file **out);
	int	(*store_rsa)(struct sc_profile *, struct sc_card *,
			struct sc_key_template *, RSA *);
	int	(*store_dsa)(struct sc_profile *, struct sc_card *,
			struct sc_key_template *, DSA *);
};

struct sc_pkcs15init_keyargs {
	struct sc_pkcs15_id	id;
	const char *		label;
	const char *		template_name;

	/* For key generation */
	unsigned char		onboard_keygen;
	unsigned int		algorithm;
	unsigned int		keybits;

	EVP_PKEY *		pkey;
};

struct sc_pkcs15init_certargs {
	struct sc_pkcs15_id	id;
	const char *		label;
	const char *		template_name;

	X509 *			cert;
};

extern int	sc_pkcs15init_add_app(struct sc_card *,
				struct sc_profile *);
extern int	sc_pkcs15init_generate_key(struct sc_pkcs15_card *,
				struct sc_profile *,
				struct sc_pkcs15init_keyargs *);
extern int	sc_pkcs15init_create_file(struct sc_profile *,
				struct sc_file *);
extern int	sc_pkcs15init_update_file(struct sc_profile *,
				struct sc_file *, void *, unsigned int);
extern int	sc_pkcs15init_authenticate(struct sc_profile *,
				struct sc_file *, int);

/* Card specific stuff */
extern void	bind_gpk_operations(struct pkcs15_init_operations *);
extern void	bind_miocos_operations(struct pkcs15_init_operations *);
extern void	bind_cflex_operations(struct pkcs15_init_operations *);

#endif /* PKCS15_INIT_H */
