
#ifndef _SIGNER_H
#define _SIGNER_H

#include <opensc.h>
#include <opensc-pkcs15.h>

typedef struct _PluginInstance
{
    char *signdata;
    int signdata_len;
    struct sc_context *ctx;
    struct sc_card *card;
    struct sc_pkcs15_card *p15card;
} PluginInstance;

#endif
