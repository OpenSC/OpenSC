
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>

#include <opensc.h>
#include <opensc-pkcs15.h>

#ifndef NDEBUG
#define DBG(x) { if (pamdebug) { x; } }
#else
#define DBG(x)
#endif

static struct sc_context *ctx = NULL;
static struct sc_card *card = NULL;
static struct sc_pkcs15_card *p15card = NULL;

static const char *eid_path = ".eid";
static const char *auth_cert_file = "authorized_certificates";

static int pamdebug = 1;


static int format_eid_dir_path(const char *user, char **buf)
{
	struct passwd *pwent = getpwnam(user);
	char *dir;
	
	if (pwent == NULL)
		return PAM_AUTH_ERR;
	dir = malloc(strlen(pwent->pw_dir) + strlen(eid_path) + 2);
	if (dir == NULL)
		return PAM_SYSTEM_ERR; /* FIXME: Is this correct? */
	strcpy(dir, pwent->pw_dir);
	strcat(dir, "/");
	strcat(dir, eid_path);
	*buf = dir;

	return PAM_SUCCESS;
}

static int is_eid_dir_present(const char *user)
{
	char *eid_dir;
	int r;
	struct stat stbuf;
	
	r = format_eid_dir_path(user, &eid_dir);
	if (r)
		return r;
	r = stat(eid_dir, &stbuf);
	/* FIXME: Check if owned by myself and if group/world-writable */
	free(eid_dir);
	if (r)
		return PAM_AUTH_ERR;	/* User has no .eid, or .eid unreadable */
	return PAM_SUCCESS;
}

static int get_certificate(const char *user, X509 **cert_out)
{
	char *dir = NULL, *cert_path = NULL;
	int r;
	BIO *in = NULL;
	X509 *cert = NULL;
	int err = PAM_AUTH_ERR;
	
	r = format_eid_dir_path(user, &dir);
	if (r)
		return r;
	cert_path = malloc(strlen(dir) + strlen(auth_cert_file) + 2);
	if (cert_path == NULL) {
		err = PAM_SYSTEM_ERR;
		goto end;
	}
	strcpy(cert_path, dir);
	strcat(cert_path, "/");
	strcat(cert_path, auth_cert_file);
	in = BIO_new(BIO_s_file());
	if (in == NULL) {
		err = PAM_SYSTEM_ERR;
		goto end;
	}
	if (BIO_read_filename(in, cert_path) <= 0) {
		DBG(printf("BIO_read_filename() failed\n"));
		goto end;
	}
	cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
	if (cert == NULL)
		goto end;
	*cert_out = cert;
	err = PAM_SUCCESS;
end:
	if (in)
		BIO_free(in);
	if (dir)
		free(dir);
	if (cert_path)
		free(cert_path);
	return err;
}

static int get_random(u8 *buf, int len)
{
	int fd, r;
	
	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return PAM_SYSTEM_ERR;
	while (len) {
		r = read(fd, buf, len);
		if (r < 0)
			return PAM_SYSTEM_ERR;
		len -= r;
		buf += r;
	}
	return PAM_SUCCESS;
}

#ifndef TEST
static int get_password(pam_handle_t * pamh, char **password, const char *pinname)
{
	int r;
	
	DBG(printf("Trying to get AUTHTOK...\n"));
	r = pam_get_item(pamh, PAM_AUTHTOK, (void *) password);
	if (!*password) {
		char buf[50];
		struct pam_message msg_template =
		{	PAM_PROMPT_ECHO_OFF, buf };
		const struct pam_message *pin_msg[1] = { &msg_template };
		struct pam_response *resp;
		struct pam_conv *conv;
		char tmp[30];

		strncpy(tmp, pinname, sizeof(tmp)-1);
		tmp[sizeof(tmp)-1] = 0;
		sprintf(buf, "Enter PIN [%s]: ", tmp);
		
		DBG(printf("failed; Trying to get CONV object...\n"));
		r = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
		if (r != PAM_SUCCESS)
			return r;
		DBG(printf("Conversing...\n"));
		r = conv->conv(1, pin_msg, &resp, conv->appdata_ptr);
		if (r != PAM_SUCCESS)
			return r;
		if (resp) {
			*password = resp[0].resp;
			resp[0].resp = NULL;
		} else
			return PAM_CONV_ERR;
		_pam_drop_reply(resp, 1);
		pam_set_item(pamh, PAM_AUTHTOK, password);
	}
	return PAM_SUCCESS;
}
#endif

int verify_authenticity(struct sc_pkcs15_card *p15card,
			struct sc_pkcs15_prkey_info *prkey,
			RSA *rsa)
{
	int r;

	u8 random_data[20];
	u8 chg[256];
	int chglen = sizeof(chg);

	DBG(printf("Getting random data...\n"));
	r = get_random(random_data, sizeof(random_data));
	if (r != PAM_SUCCESS)
		return -1;
/*	DBG(printf("Encrypting...\n"));
	r = RSA_public_encrypt(117, random_data, chg, pubkey->pkey.rsa, RSA_PKCS1_PADDING);
	if (r != 128)
		goto end;
 */
 	chglen = RSA_size(rsa);
 	if (chglen > sizeof(chg)) {
 		DBG(printf("Too large RSA key. Bailing out.\n"));
 		return -1;
 	}
 	r = sc_pkcs15_compute_signature(p15card, prkey, SC_PKCS15_HASH_SHA1,
 					random_data, 20, chg, chglen);
 	if (r < 0) {
 		DBG(printf("Compute signature failed: %s\n", sc_strerror(r)));
 		return -1;
 	}
 	DBG(printf("Verifying signature...\n"));
	r = RSA_verify(NID_sha1, random_data, 20, chg, r, rsa);
	if (r != 1) {
		DBG(printf("No luck this time.\n"));
		return 0;
	} else
		return 1;

	return 0;
}
	u8 random_data[20];
	u8 chg[256];
	int chglen = sizeof(chg);
	u8 plain_text[128];


#ifdef TEST
int main(int argc, const char **argv)
#else
PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc, const char **argv)
#endif
{
	int r, i, err = PAM_AUTH_ERR, locked = 0;
	const char *user;
	char *password = NULL;
	X509 *cert = NULL;
	EVP_PKEY *pubkey = NULL;
	struct sc_pkcs15_cert_info *cinfo;
	struct sc_pkcs15_prkey_info *prkinfo = NULL;
	struct sc_pkcs15_pin_info *pinfo = NULL;
	
	
	for (i = 0; i < argc; i++)
		printf("%s\n", argv[i]);

#ifdef TEST
	user = "root";
#else
	r = pam_get_user(pamh, &user, NULL);
	if (r != PAM_SUCCESS)
		return r;
#endif
	r = is_eid_dir_present(user);
	if (r != PAM_SUCCESS) {
		DBG(printf("No such user, user has no .eid directory or .eid unreadable. We're not wanted here.\n"));
		return r;
	}
	DBG(printf("Reading certificate...\n"));
	r = get_certificate(user, &cert);
	if (r != PAM_SUCCESS) {
		DBG(printf("Certificate read failed. Bailing out.\n"));
		return r;
	}
	pubkey = X509_get_pubkey(cert);
	if (pubkey == NULL)
		goto end;
	r = sc_establish_context(&ctx);
	if (r != 0) {
		printf("establish_context() failed: %s\n", sc_strerror(r));
		return PAM_AUTH_ERR;
	}
	ctx->use_std_output = 1;
	ctx->debug = 0;
	for (i = 0; i < ctx->reader_count; i++) {
		if (sc_detect_card(ctx, i) == 1) {
			DBG(printf("Connecting to %s...\n", ctx->readers[i]));
			if (sc_connect_card(ctx, i, &card) != 0) {
				printf("Connecting to card failed: %s\n", sc_strerror(r));
				goto end;
			}
		}
	}
	if (card == NULL) {
		printf("SmartCard absent.\n");
		goto end;
	}
	DBG(printf("Locking card...\n"));
	sc_lock(card);
	locked = 1;
	
	DBG(printf("PKCS#15 init...\n"));
	r = sc_pkcs15_bind(card, &p15card);
	if (r != 0) {
		printf("PKCS#15 initialization failed: %s\n", sc_strerror(r));
		goto end;
	}
	DBG(printf("Enumerating certificates...\n"));
	r = sc_pkcs15_enum_certificates(p15card);
	if (r < 0) {
		printf("Cert enum failed: %s\n", sc_strerror(r));
		goto end;
	}
	if (r == 0) /* No certificates found */
		goto end;
	for (i = 0; i < p15card->cert_count; i++) {
	}
	cinfo = &p15card->cert_info[0]; /* FIXME */
	DBG(printf("Finding private key...\n"));
	r = sc_pkcs15_find_prkey_by_id(p15card, &cinfo->id, &prkinfo);
	if (r < 0)
		goto end;
	DBG(printf("Finding PIN code...\n"));
	r = sc_pkcs15_find_pin_by_auth_id(p15card, &prkinfo->com_attr.auth_id, &pinfo);
	if (r < 0)
		goto end;
	DBG(printf("Asking for PIN code '%s'...\n", pinfo->com_attr.label));
#ifdef TEST
	password = strdup(getpass("Enter PIN1: "));
	r = 0;
#else
	r = get_password(pamh, &password, pinfo->com_attr.label);
#endif
	if (r) {
		err = r;
		goto end;
	}
	DBG(printf("Verifying PIN code...\n"));
	r = sc_pkcs15_verify_pin(p15card, pinfo, password, strlen(password));
	memset(password, 0, strlen(password));
	if (r) {
		DBG(printf("PIN code verification failed: %s\n", sc_strerror(r)));
		if (r == SC_ERROR_CARD_REMOVED)
			printf("SmartCard removed.\n");
		goto end;
	}
	DBG(printf("Awright! PIN code correct!\n"));
	/* FIXME: clear password? */
	DBG(printf("Deciphering...\n"));
/*	r = sc_pkcs15_decipher(p15card, prkinfo, chg, sizeof(chg), plain_text, sizeof(plain_text));
	if (r <= 0) {
		DBG(printf("Decipher failed: %s\n", sc_strerror(r)));
		goto end;
	}
 */
 	if (verify_authenticity(p15card, prkinfo, pubkey->pkey.rsa) != 1)
 		goto end;
	DBG(printf("You're in!\n"));	
	err = PAM_SUCCESS;
end:
	if (locked)
		sc_unlock(card);
	if (pubkey)
		EVP_PKEY_free(pubkey);
	if (cert)
		X509_free(cert);
	if (p15card)
		sc_pkcs15_unbind(p15card);
	if (card)
		sc_disconnect_card(card);
	if (ctx)
		sc_destroy_context(ctx);
	return err;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	DBG(printf("pam_sm_setcred() called\n"));
	return PAM_SUCCESS;
}
