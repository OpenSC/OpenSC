
#ifndef _SIGNER_H
#define _SIGNER_H

#include <opensc.h>
#include <opensc-pkcs15.h>
#include <X11/Intrinsic.h>

typedef struct _PluginInstance
{
    char *signdata;
    int signdata_len;
    struct sc_context *ctx;
    struct sc_card *card;
    struct sc_pkcs15_card *p15card;
} PluginInstance;

#ifdef __cplusplus
extern "C" {
#endif

int ask_pin_code(PluginInstance *inst, Display *dpy, Window win);

#ifdef __cplusplus
}
#endif

#endif
