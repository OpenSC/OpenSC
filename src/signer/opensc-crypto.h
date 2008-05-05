#ifndef _OPENSC_CRYPTO_H
#define _OPENSC_CRYPTO_H

#include <openssl/rsa.h>
#include <opensc/pkcs15.h>

struct sc_priv_data
{
        struct sc_pkcs15_card *p15card;
        struct sc_card *card;
        struct sc_context *ctx;
        struct sc_pkcs15_id cert_id;
        int ref_count, reader_id;
};

extern RSA_METHOD * sc_get_method(void);

#endif
