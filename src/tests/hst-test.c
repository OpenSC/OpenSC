
/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 */
  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sc.h"

int main(int argc, char **argv) {
  SCARDHANDLE sc_card;
  SCARDCONTEXT sc_ctx;
  SCARD_READERSTATE_A rgReaderStates[1];
  DWORD dwState, dwProt, dwAtrLen;
  DWORD dwPref;
  BYTE pbAtr[MAX_ATR_SIZE];
  BYTE r[MAX_BUFFER_SIZE];
  LPCSTR mszGroups;
  LONG rv;
  DWORD reader_buf_size;
  int i, reader_count;
  char *p, *reader_buf;
  char *readers[4];
  struct sc_apdu apdu;
  struct sc_context ctx;
  struct sc_pkcs15_card card;

  rv = SCardEstablishContext(SCARD_SCOPE_GLOBAL, "localhost", NULL, &sc_ctx);
  if (rv != SCARD_S_SUCCESS) {
    fprintf(stderr, "ERROR: Cannot connect to Resource Manager\n");
    return 1;
  }
  ctx.sc_ctx = sc_ctx;
  SCardListReaders(sc_ctx, NULL, NULL, (LPDWORD) &reader_buf_size);
  reader_buf = (char *)malloc(sizeof(char)*reader_buf_size);
  SCardListReaders(sc_ctx, mszGroups, reader_buf, (LPDWORD) &reader_buf_size);

  p = reader_buf;
  i = reader_count = 0;
  do {
  	reader_count++;
  	readers[i] = strdup(p);
	while (*p++ != 0);
	p++;
  } while (p < reader_buf + reader_buf_size);

  for (i = 0; i < reader_count; i++)
    printf("Reader %d - %s\n", i, readers[i]);

  rgReaderStates[0].szReader       = readers[0];
  rgReaderStates[0].dwCurrentState = SCARD_STATE_EMPTY;
  printf("Please insert a smartcard\n");
  SCardGetStatusChange(sc_ctx, INFINITE, rgReaderStates, 1);

  printf("Connecting... ");
  fflush(stdout);
  rv = SCardConnect(sc_ctx, readers[0], 
		    SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
		    &sc_card, &dwPref);

  if (rv != SCARD_S_SUCCESS) {
    SCardReleaseContext(sc_ctx);
    fprintf(stderr, "Error connecting to reader %ld\n", rv);
    return 1;
  }
  printf("done.\n");

  reader_buf_size = strlen(readers[0])+1;
  rv = SCardStatus(sc_card, readers[0], &reader_buf_size, &dwState,
  		   &dwProt, pbAtr, &dwAtrLen);
  if (rv != SCARD_S_SUCCESS) {
    SCardDisconnect(sc_card, SCARD_UNPOWER_CARD);
    SCardReleaseContext(sc_ctx);
    fprintf(stderr, "Error receiving status info 0x%08X\n", (unsigned int) rv);
    return 1;
  }
  ctx.sc_card = sc_card;

  i = sc_pkcs15_init(&ctx, &card);
  if (i != 0) {
    fprintf(stderr, "PKCS#15 card init failed with %d\n", i);
    SCardDisconnect(sc_card, SCARD_UNPOWER_CARD );
    SCardReleaseContext( sc_ctx );
    return 1;
  }
  i = sc_pkcs15_read_certificate(&card, 0);
  if (i) {
    fprintf(stderr, "Certificate read failed with %d\n", i);
    return 1;
  }
  i = sc_pkcs15_read_pin_object(&card, 1, NULL);
  if (i) {
    fprintf(stderr, "PIN object read failed with %d\n", i);
    return 1;
  }
/*
  printf("Opening EF(DIR)...\n");
  memcpy(r, "\x3f\x00", 2);
  i = sc_select_file(&ctx, &file, r, 2, SC_SELECT_FILE_BY_FILE_ID);
  if (i != 0) {
    fprintf(stderr, "EF(DIR) open failed with %d\n", i);
    SCardDisconnect(sc_card, SCARD_UNPOWER_CARD );
    SCardReleaseContext( sc_ctx );
    return 1;
  }
  
  printf("Reading EF(DIR)...\n");
  i = sc_read_binary(&ctx, 0, r, 0x60);
  if (i < 0) {
    fprintf(stderr, "EF(DIR) read failed with %d\n", i);
    SCardDisconnect(sc_card, SCARD_UNPOWER_CARD );
    SCardReleaseContext( sc_ctx );
    return 1;
  }
  sc_print_tags(r, i);
*/
  
  SCardDisconnect(sc_card, SCARD_UNPOWER_CARD);
  SCardReleaseContext(sc_ctx);

  return 0;
}
