#ifndef _SIGNER_H
#define _SIGNER_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <X11/Intrinsic.h>
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>

typedef struct _PluginInstance
{
    char *signdata;
    int signdata_len;
    int reader_id;
    struct sc_context *ctx;
    struct sc_card *card;
    struct sc_pkcs15_card *p15card;

    const char *pinname;
    char *pinbuf;
    int pinlen;
} PluginInstance;

#ifdef __cplusplus
extern "C" {
#endif

int ask_pin_code(PluginInstance *inst);

#ifdef __cplusplus
}
#endif

#endif
