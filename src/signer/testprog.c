#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/pkcs7.h>
#include "opensc-support.h"
#include "opensc-crypto.h"
#include "signer.h"

int test(void)
{
	BIO *in;
	PKCS7 *p7;
	
	in = BIO_new_file("sample.pem", "r");
	p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
	if (p7 == NULL) {
		goto err;
	}
#if 0
	return prp7(p7);
#endif
	return 0;
err:
	ERR_load_crypto_strings();
	ERR_print_errors_fp(stderr);
	return 1;
}

int main(void)
{
	PluginInstance pl;
	u8 *data;
	int datalen, r;

#if 0
	test();
	return 0;
#endif
	
	pl.signdata = strdup("12345\ntest foo bar one two three\nTesting 1234567890");
	pl.signdata_len = strlen(pl.signdata);
	r = create_envelope(&pl, &data, &datalen);
	if (r) {
		printf("create_env() failed\n");
		return 1;
	}
	return 0;
}
