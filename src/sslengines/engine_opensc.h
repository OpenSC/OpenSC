#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

int opensc_finish();
int opensc_init();
EVP_PKEY *opensc_load_public_key(ENGINE *e, const char *s_key_id,
	UI_METHOD *ui_method, void *callback_data) ;
EVP_PKEY *opensc_load_private_key(ENGINE *e, const char *s_key_id,
	UI_METHOD *ui_method, void *callback_data) ;
int sc_private_decrypt(int flen, const u_char *from, u_char *to,
	RSA *rsa, int padding);
int sc_sign(int type, const u_char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
int sc_private_encrypt(int flen, const u_char *from, u_char *to, 
	RSA *rsa, int padding);
int opensc_rsa_finish(RSA* rsa) ;

