
#include <stdio.h>
#include <stdlib.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <openssl/x509.h>
#include <openssl/rsa.h>

#include <sc.h>
#include <sc-pkcs15.h>

static struct sc_context *ctx = NULL;
static struct sc_card *card = NULL;

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	int r, i;
	const char *user, *password = NULL;

	printf("argc = %d\n", argc);
	for (i = 0; i < argc; i++)
		printf("%s\n", argv[i]);

	r = pam_get_user(pamh, &user, NULL);
	if (r != PAM_SUCCESS)
		return r;

	r = sc_establish_context(&ctx);
	if (r != 0) {
		printf("establish_context() failed: %s\n", sc_strerror(r));
		return PAM_AUTH_ERR;
	}
	for (i = 0; i < ctx->reader_count; i++) {
		if (sc_detect_card(ctx, i) == 1) {
			printf("Using card in reader %s.\n", ctx->readers[i]);
			if (sc_connect_card(ctx, i, &card) != 0) {
				printf("Connecting to card failed: %s\n", sc_strerror(r));
				goto err;
			}
		}
	}
	if (card == NULL) {
		printf("SmartCard absent.\n");
		goto err;
	}

	sc_destroy_context(ctx);

	return PAM_SUCCESS;
err:
	if (card)
		sc_disconnect_card(card);
	if (ctx)
		sc_destroy_context(ctx);
	return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	printf("pam_sm_setcred() called\n");
	return PAM_SUCCESS;
}
