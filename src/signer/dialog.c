#include "signer.h"
#include <assuan.h>
#include <stdarg.h>

#ifndef PIN_ENTRY
#define PIN_ENTRY "/usr/local/bin/gpinentry"
#endif

extern int ask_and_verify_pin_code(struct sc_pkcs15_card *p15card,
                                   struct sc_pkcs15_object *pin);

struct entry_parm_s {
  int lines;
  size_t size;
  char *buffer;
};

static AssuanError
getpin_cb (void *opaque, const void *buffer, size_t length)
{
  struct entry_parm_s *parm = (struct entry_parm_s *) opaque;

  /* we expect the pin to fit on one line */
  if (parm->lines || length >= parm->size)
    return ASSUAN_Too_Much_Data;

  /* fixme: we should make sure that the assuan buffer is allocated in
     secure memory or read the response byte by byte */
  memcpy(parm->buffer, buffer, length);
  parm->buffer[length] = 0;
  parm->lines++;
  return (AssuanError) 0;
}

int ask_and_verify_pin_code(struct sc_pkcs15_card *p15card,
			    struct sc_pkcs15_object *pin)
{
	int r;
	size_t len;
	const char *argv[3];
	const char *pgmname = PIN_ENTRY;
	ASSUAN_CONTEXT ctx;
	char buf[500];
	char errtext[100];
	struct entry_parm_s parm;
	struct sc_pkcs15_pin_info *pinfo = (struct sc_pkcs15_pin_info *) pin->data;
	
	argv[0] = pgmname;
	argv[1] = NULL;
	
	r = assuan_pipe_connect(&ctx, pgmname, (char **) argv, NULL);
	if (r) {
		printf("Can't connect to the PIN entry module: %s\n",
		       assuan_strerror((AssuanError) r));
		goto err;
	}
	sprintf(buf, "SETDESC Enter PIN [%s] for digital signing  ", pin->label);
	r = assuan_transact(ctx, buf, NULL, NULL, NULL, NULL, NULL, NULL);
	if (r) {
		printf("SETDESC: %s\n", assuan_strerror((AssuanError) r));
		goto err;
	}
	errtext[0] = 0;
	while (1) {
		if (errtext[0]) {
			sprintf(buf, "SETERROR %s", errtext);
			r = assuan_transact(ctx, buf, NULL, NULL, NULL, NULL, NULL, NULL);
			errtext[0] = 0;
		}
		parm.lines = 0;
		parm.size = sizeof(buf);
		parm.buffer = buf;
		r = assuan_transact(ctx, "GETPIN", getpin_cb, &parm, NULL, NULL, NULL, NULL);
		if (r == ASSUAN_Canceled) {
			assuan_disconnect(ctx);
			return -2;
		}
		if (r) {
			printf("GETPIN: %s\n", assuan_strerror((AssuanError) r));
			goto err;
		}
		len = strlen(buf);
		if (len < pinfo->min_length) {
			sprintf(errtext, "PIN code too short, min. %lu digits", (unsigned long) pinfo->min_length);
			continue;
		}
		if (len > pinfo->max_length) {
			sprintf(errtext, "PIN code too long, max. %lu digits", (unsigned long) pinfo->max_length);
			continue;
		}
		r = sc_pkcs15_verify_pin(p15card, pinfo, (const u8 *) buf, strlen(buf));
		switch (r) {
		case SC_ERROR_PIN_CODE_INCORRECT:
			sprintf(errtext, "PIN code incorrect (%d %s left)",
			       pinfo->tries_left, pinfo->tries_left == 1 ?
			       "try" : "tries");
			break;
		case 0:
			break;
		default:
			goto err;
		}
		if (r == 0)
			break;
	}

	assuan_disconnect(ctx);	
	return 0;
err:	
	assuan_disconnect(ctx);
	return -1;
}
