/*
 * Function prototypes for pkcs15-init
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
 */

#ifndef PKCS15_INIT_H
#define PKCS15_INIT_H

#include "profile.h"

extern int	do_create_file(struct sc_profile *, struct sc_file *);
extern int	do_create_and_update_file(struct sc_profile *,
				struct sc_file *, void *, unsigned int);
extern int	do_select_parent(struct sc_profile *, struct sc_file *,
				struct sc_file **);
extern int	do_verify_authinfo(struct sc_profile *, struct sc_file *, int);

/* Card specific stuff */
extern void	bind_gpk_operations(struct sc_profile *);

#endif /* PKCS15_INIT_H */
