/*
 * card-belpic.c: Support for Belgium EID card
 *
 * Copyright (C) 2003, Zetes Belgium
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*     About the Belpic (Belgian Personal Identity Card) card
 *
 * The Belpic card is a Cyberflex Java card, so you normaly communicate
 * with an applet running on the card. In order to support a pkcs15 file
 * structure, an  applet (the Belpic applet) has been build that emulates
 * this. So the card's behaviour is specific for this Belpic applet, that's
 * why a separate driver has been made.
 *
 * The card contains the citizen's ID data (name, address, photo, ...) and
 * her keys and certs. The ID data are in a seperate directory on the card and
 * are not handled by this software. For the cryptographic data (keys and certs)
 * a pkcs#15 structure has been chosen and they can be accessed and used
 * by the OpenSC software.
 *
 * The current situation about the cryptographic data is: there is 1 PIN
 * that protects 2 private keys and corresponding certs. Then there is a
 * CA cert and the root cert. The first key (Auth Key) can be used for
 * authentication, the second one (NonRep Key) for non repudation purposes
 * (so it can be used as an alternative to manual signatures).
 *
 * There are some special things to note, which all have some consequences:
 * (1) the SELECT FILE command doesn't return any FCI (file length, type, ...)
 * (2) the NonRep key needs a VERIFY PIN before a signature can be done with it
 * (3) pin pad readers had to be supported by a proprietory interface (as at
 *     that moment no other solution was known/avaiable/ready)
 * The consequences are:
 *
 * For (1): we let the SELECT FILE command return that the file length is
 * a fixed large number and that each file is a transparant working EF
 * (except the root dir 3F 00). This way however, there is a problem with the
 * sc_read_binary() function that will only stop reading untill it receivces
 * a 0. Therefore, we use the 'next_idx' trick. Or, if that might fail
 * and so a READ BINARY past the end of file is done, length 0 is returned
 * instead of an error code.
 *
 * For (2), we decided that a GUI for asking the PIN would be the best
 * thing to do (another option would be to make 2 virtual slots but that
 * causes other problems and is less user-friendly). A GUI being popped up
 * by the pkcs11 lib before each NonRep signature has another important
 * security advantage: applications that cache the PIN can't silently do
 * a NonRep signature because there will allways be the GUI.
 *
 * For (3), we link dynamically against a pin pad lib (DLL) that implements the
 * proprietory API for a specific pin pad. For each pin pad reader (identified
 * by it's PC/SC reader name), a pin pad lib correspondends. Some reader/lib
 * name pairs are hardcoded, and others can be added in the config file.
 * Note that there's also a GUI used in this case: if a signature with the
 * NonRep key is done: a dialog box is shown that asks the user to enter
 * her PIN on the pin pad reader in order to make a legally valid signature.
 *
 * Further the (current) Belpic card as quite some limitations:
 * no key pair generation or update of data except after establishing a Secure
 * Channel or CTV-authentication (which can only be done at the municipalities),
 * no encryption. The result is that only a very limited amount of functions
 * is/had to be implemented to get the pkcs11 library working.
 *
 * About the belpic_set_language: the RA-PC software (including the pkcs11 lib)
 * in the Brussels' communities should be able to change the language of the GUI
 * messages. So the language set by this function takes priority on all other
 * language-selection  functionality.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "log.h"

#ifdef BELPIC_PIN_PAD
#ifndef HAVE_GUI
#define HAVE_GUI
#endif
#endif

#ifdef BELPIC_PIN_PAD
#include "winscard.h"
#include "scr.h"
#endif

#ifdef HAVE_GUI
#include "scgui.h"
#ifndef SCR_USAGE_SIGN
#define SCR_USAGE_SIGN 2	/* in scr.h */
#endif
#ifndef SCR_USAGE_AUTH
#define SCR_USAGE_AUTH 1
#endif
#endif

/* To be removed */
#include <time.h>
static long t1, t2, tot_read = 0, tot_dur = 0, dur;

#define BELPIC_VERSION			"1.4"

/* Most of the #defines here are also present in the pkcs15 files, but
 * because this driver has no access to them, it's hardcoded here. If
 * other Belpic cards with other 'settings' appear, we'll have to move
 * these #defines to the struct belpic_priv_data */
#define BELPIC_MAX_FILE_SIZE		65535
#define BELPIC_PIN_BUF_SIZE		8
#define BELPIC_MIN_USER_PIN_LEN		4
#define BELPIC_MAX_USER_PIN_LEN		12
#define BELPIC_PIN_ENCODING		SC_PIN_ENCODING_GLP
#define BELPIC_PAD_CHAR			0xFF
#define BELPIC_KEY_REF_NONREP		0x83

/* Data in the return value for the GET CARD DATA command:
 * All fields are one byte, except when noted otherwise.
 *
 * See §6.9 in
 * https://github.com/Fedict/eid-mw/blob/master/doc/sdk/documentation/Public_Belpic_Applet_v1%207_Ref_Manual%20-%20A01.pdf
 * for the full documentation on the GET CARD DATA command.
 */
// Card serial number (16 bytes)
#define BELPIC_CARDDATA_OFF_SERIALNUM 0
// "Component code"
#define BELPIC_CARDDATA_OFF_COMPCODE 16
// "OS number"
#define BELPIC_CARDDATA_OFF_OSNUM 17
// "OS version"
#define BELPIC_CARDDATA_OFF_OSVER 18
// "Softmask number"
#define BELPIC_CARDDATA_OFF_SMNUM 19
// "Softmask version"
#define BELPIC_CARDDATA_OFF_SMVER 20
// Applet version
#define BELPIC_CARDDATA_OFF_APPLETVERS 21
// Global OS version (2 bytes)
#define BELPIC_CARDDATA_OFF_GL_OSVE 22
// Applet interface version
#define BELPIC_CARDDATA_OFF_APPINTVERS 24
// PKCS#1 support version
#define BELPIC_CARDDATA_OFF_PKCS1 25
// Key exchange version
#define BELPIC_CARDDATA_OFF_KEYX 26
// Applet life cycle (Should always be 0F for released cards, is 07 when not issued yet)
#define BELPIC_CARDDATA_OFF_APPLCYCLE 27
// Full length of reply
#define BELPIC_CARDDATA_RESP_LEN 28

/* Used for a trick in select file and read binary */
static size_t next_idx = (size_t)-1;

static struct sc_atr_table belpic_atrs[] = {
	/* Applet V1.1 */
	{ "3B:98:13:40:0A:A5:03:01:01:01:AD:13:11", NULL, NULL, SC_CARD_TYPE_BELPIC_EID, 0, NULL },
	/* Applet V1.0 with new EMV-compatible ATR */
	{ "3B:98:94:40:0A:A5:03:01:01:01:AD:13:10", NULL, NULL, SC_CARD_TYPE_BELPIC_EID, 0, NULL },
	/* Applet beta 5 + V1.0 */
	{ "3B:98:94:40:FF:A5:03:01:01:01:AD:13:10", NULL, NULL, SC_CARD_TYPE_BELPIC_EID, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

struct belpic_priv_data {
	int lang;
	int options;
#ifdef BELPIC_PIN_PAD
	FARPROC scr_init;
	FARPROC scr_verify_pin;
	FARPROC scr_change_pin;
	char szPinPadDll[64];
#endif
};

#define DRVDATA(card)	((struct belpic_priv_data *) ((card)->drv_data))

/* Single Sign On */
#ifdef HAVE_ALLOW_SSO
#define SSO_OK(drv) ((drv)->allow_sso)
#else
#define SSO_OK(drv) 0
#endif

static struct sc_card_operations belpic_ops;
static struct sc_card_driver belpic_drv = {
	"Belpic cards",
	"belpic",
	&belpic_ops,
	NULL, 0, NULL
};
static const struct sc_card_operations *iso_ops = NULL;

#define LNG_ENG			0
#define LNG_DUTCH		1
#define LNG_FRENCH		2
#define LNG_GERMAN		3
#define LNG_NONE		0xFFFF

#ifdef BELPIC_PIN_PAD

/* Option flags from the config file */
#define PP_MSG_AUTH_PIN			0x00000001
#define PP_MSG_WRONG_PIN		0x00000002
#define PP_MSG_CHANGEPIN_MISMATCH	0x00000004
#define PP_MSG_PIN_BLOCKED		0x00000008

/* Hardcoded pin pad reader names (PC/SC) and their pin pad lib */
static char *pp_reader_names[] = {
	"Xiring X Pass Serial",
	NULL
};
static char *pp_reader_libs[] = {
	"xireid",
	NULL
};

static BYTE aid_belpic[] = { 0xA0, 0x00, 0x00, 0x01, 0x77, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35 };
static SCR_Application scr_app_belpic = {
	{aid_belpic, sizeof(aid_belpic)},
	"ID",
	NULL
};
static char *app_id_longstr[] = {
	"Identity",
	"Identiteit",
	"Identité",
	"Identität"
};
#endif	/* BELPIC_PIN_PAD */

#if defined(HAVE_GUI) ||defined(BELPIC_PIN_PAD)
static char *pin_usg_sig[] = {
	"Signature",
	"Handtekening",
	"Signature",
	"Signatur"
};
static char *pin_usg_auth[] = {
	"Authentication",
	"Authentificatie",
	"Authentification",
	"Authentifizierung"
};
#endif	/* defined(HAVE_GUI) ||defined(BELPIC_PIN_PAD) */

#ifdef BELPIC_PIN_PAD
static char *lang_codes[4] = {
	"en",
	"nl",
	"fr",
	"de"
};
static char *pp_msg_auth_sh[] = {
	"Authentication",
	"Authentificatie",
	"Authentification",
	"Kennzeichnung"
};
static char *pp_msg_auth[] = {
	"Enter your PIN on the reader, in order to authenticate yourself",
	"Geef uw PIN in op de lezer, om u te authentificeren",
	"Entrez votre PIN sur le lecteur, pour vous authentifier",
	"Bitte geben Sie Ihre PIN am Kartenlesegerät ein, um sich zu authentifizieren"
};
static char *pp_msg_sign_sh[] = {
	"Signature",
	"Handtekening",
	"Signature",
	"Signatur"
};
static char *pp_msg_sign[] = {
	"Caution: You are about to make a legally binding electronic signature with your identity card.\nPlease enter your PIN on the card reader to continue or click the Cancel button.\n\nIf you only want to log on to a web site or server, do NOT enter your PIN and click the Cancel button.",
	"Let op: u gaat een wettelijk bindende electronische handtekening plaatsen met uw identiteitskaart.\nGeef uw PIN in op de kaartlezer om verder te gaan of klik op Stoppen.\n\nAls u enkel wil aanloggen op een web site of een server, geef uw PIN NIET in en klik op Stoppen.",
	"Attention: vous allez apposer une signature électronique juridiquement valide avec votre carte d'identité.\nVeuillez entrer votre PIN sur le lecteur externe pour continuer ou cliquez sur Annuler.\n\nSi vous désirez seulement vous connecter à un site ou un serveur, n'entrez PAS votre PIN et cliquez sur Annuler.",
	"Achtung: Mit Ihrem Personalausweis werden Sie eine rechtlich bindende elektronische Signatur setzen.\nBitte geben Sie Ihre PIN am Kartenlesgerät ein zum weitergehen oder klicken Sie auf Abbrechen.\n\nWenn Sie nur auf das Internet gehen möchten, geben Sie bitte Ihre PIN NICHT ein, sondern klicken Sie auf Abbrechen."
};
static char *pp_msg_change_sh[] = {
	"PIN change",
	"PIN verandering",
	"Modification du PIN ",
	"PIN ändern"
};
static char *pp_msg_change[] = {
	"Change your PIN on the reader",
	"Verander uw PIN op de lezer",
	"Modifiez votre PIN sur le lecteur",
	"Bitte ändern Sie Ihre PIN am Kartenlesegerät"
};
static char *pp_msg_pin_mismatch[] = {
	"The new PINs you entered were different.\n\nRetry or cancel?",
	"De ingevoerde nieuwe PINs zijn verschillend.\n\nOpnieuw proberen of stoppen?",
	"Les nouveaux PIN entrés sont différents.\n\nRéessayer ou annuler?",
	"Die von Ihnen eingegebenen PINs unterscheiden sich.\n\nErneut versuchen oder abbrechen?"
};

#define PCSC_ERROR(ctx, desc, rv) sc_debug(ctx, SC_LOG_DEBUG_NORMAL, desc ": %lx\n", rv);

#endif	/* BELPIC_PIN_PAD */

/* Language support for the GUI messages */
#ifdef HAVE_GUI

#ifdef WIN32
#define BTN_KEYB_SHORTCUT "&"
#else
#define BTN_KEYB_SHORTCUT "_"
#endif

static char *app_msg[] = {
	"Identity",
	"Identiteit",
#ifdef _WIN32
	"Identité",
#else
	"Identite",
#endif
#ifdef _WIN32
	"Identität"
#else
	"Identitat",
#endif
};
static char *btn_msg_retry[4] = {
	BTN_KEYB_SHORTCUT"Try again",
	BTN_KEYB_SHORTCUT"Opnieuw proberen",
	BTN_KEYB_SHORTCUT"Réessayer",
	BTN_KEYB_SHORTCUT"Erneut versuchen"
};
static char *btn_msg_cancel[4] = {
	BTN_KEYB_SHORTCUT"Cancel",
	BTN_KEYB_SHORTCUT"Stoppen",
	BTN_KEYB_SHORTCUT"Annuler",
	BTN_KEYB_SHORTCUT"Abbrechen"
};
static char *btn_msg_ok[4] = {
	BTN_KEYB_SHORTCUT"OK",
	BTN_KEYB_SHORTCUT"OK",
	BTN_KEYB_SHORTCUT"OK",
	BTN_KEYB_SHORTCUT"OK"
};
static char *btn_msg_close[4] = {
	BTN_KEYB_SHORTCUT"Close",
	BTN_KEYB_SHORTCUT"Sluiten",
	BTN_KEYB_SHORTCUT"Fermer",
	BTN_KEYB_SHORTCUT"Schliessen"
};
static char *enter_pin_msg_auth[] = {
	"Enter your PIN, in order to authenticate yourself",
	"Geef uw PIN in, om u te authentificeren",
	"Entrez votre PIN, pour vous authentifier",
	"Bitte geben Sie Ihre PIN ein, um sich zu authentifizieren"
};
static char *enter_pin_msg_sign[4] = {
#ifdef _WIN32
	"Caution: You are about to make a legally binding electronic signature with your identity card.\nPlease enter your PIN to continue or click the Cancel button.\n\nWarning: if you only want to log on to a web site or server, do NOT enter your PIN and click the Cancel button.",
	"Let op: u gaat een wettelijk bindende electronische handtekening plaatsen met uw identiteitskaart.\nGeef uw PIN in om verder te gaan of klik op Stoppen.\n\nWaarschuwing: als u enkel wil aanloggen op een web site of een server, geef uw PIN NIET in en klik op Stoppen.",
	"Attention: vous allez apposer une signature électronique juridiquement valide avec votre carte d'identité.\nVeuillez entrer votre PIN pour continuer ou cliquez sur Annuler.\n\nPrécaution: si vous désirez seulement vous connecter à un site ou un serveur, n'entrez PAS votre PIN et cliquez sur Annuler.",
	"Achtung: Mit Ihrem Personalausweis werden Sie eine rechtlich bindende elektronische Signatur setzen.\nBitte geben Sie Ihre PIN ein zum weitergehen oder klicken Sie auf Abbrechen.\n\nWarnung: Wenn Sie nur auf das Internet gehen möchten, geben Sie bitte Ihre PIN NICHT ein, sondern klicken Sie auf Abbrechen."
#else
#ifdef __APPLE__
	"CAUTION: you are about to make a legally binding electronic signature with your identity card. Please enter your PIN to continue or press the Cancel button.                                        If you only want to log on to a web site or a server, do NOT enter your PIN and press the Cancel button.",
	"LET OP: u gaat een wettelijk bindende electronische handtekening plaatsen met uw identiteitskaart. Geef uw PIN in om verder te gaan of klik op Stoppen.                                    Als u enkel wil aanloggen op een web site of een server, geef uw PIN NIET in en klik op Stoppen.",
	"ATTENTION: vous allez apposer une signature electronique\njuridiquement valide avec votre carte d'identite.Veuillez entrer votre PIN pour continuer ou cliquez sur Annuler. Si vous desirez seulement vous connecter a un site ou un serveur, n' entrez PAS votre PIN et cliquez sur Annuler.",
	"ACHTUNG: Mit Ihrem Personalausweis werden Sie eine rechtlich bindende elektronische Signatur setzen. Geben Sie Ihre PIN ein zum weitergehen oder klicken Sie auf Abbrechen. Warnung: Wenn Sie nur auf das Internet gehen mochten, geben Sie bitte Ihre PIN NICHT ein, sondern klicken Sie auf Abbrechen."
#else
	"<u>Caution</u>: you are about to make a legally binding electronic\nsignature with your identity card.\nPlease enter your PIN to continue or press the Cancel button.\n\nIf you only want to log on to a web site or a server,\ndo <b>NOT</b> enter your PIN and press the Cancel button.",
	"<u>Let op</u>: u gaat een wettelijk bindende electronische handtekening\nplaatsen met uw identiteitskaart.\nGeef uw PIN in om verder te gaan of klik op Stoppen.\n\nAls u enkel wil aanloggen op een web site\nof een server, geef uw PIN <b>NIET</b> in en klik op Stoppen.",
	"<u>Attention</u>: vous allez apposer une signature electronique\njuridiquement valide avec votre carte d'identite.\nVeuillez entrer votre PIN pour continuer ou cliquez sur Annuler.\n\nSi vous desirez seulement vous connecter a un site\nou un serveur, n'entrez <b>PAS</b> votre PIN et cliquez sur Annuler.",
	"<u>Achtung</u>: Mit Ihrem Personalausweis werden Sie eine rechtlich\r\nbindende elektronische Signatur setzen.\r\nGeben Sie Ihre PIN ein zum weitergehen oder klicken Sie auf Abbrechen.\r\n\r\nWarnung: Wenn Sie nur auf das Internet gehen mochten, geben\r\nSie bitte Ihre PIN <b>NICHT</b> ein, sondern klicken Sie auf Abbrechen."
#endif
#endif
};
static char *wrong_pin_len_msgs[4] = {
	"Wrong PIN length",
	"Foute PIN lengte",
	"Longueur de PIN erroné",
	"Falsche PIN-Länge"
};
static char *wrong_pin_msgs[4] = {
	"Wrong PIN, %d tries left\n\nRetry or cancel?",
	"Foute PIN, nog %d pogingen\n\nOpnieuw proberen of stoppen?",
	"PIN erroné, %d essais restants\n\nRéessayer ou annuler?",
	"Falsche PIN, %d verbleibende Versuche\n\nErneut versuchen oder abbrechen?"
};
static char *pin_blocked_msgs[4] = {
	"PIN blocked",
	"PIN geblokkeerd",
	"PIN bloqué ",
	"PIN gesperrt"
};

#endif	/* HAVE_GUI */

#ifdef BELPIC_PIN_PAD

#define SCR_INIT_ID	100
#define SCR_VERIFY_ID	101
#define SCR_CHANGE_ID	102
#define SCR_CARD_HANDLE	999

struct tTLV {
	unsigned char *base;
	unsigned char *end;
	unsigned char *current;
	unsigned char *next;
};

static void TLVInit(struct tTLV *tlv, u8 * base, size_t size)
{
	tlv->base = base;
	tlv->end = base + size;
	tlv->current = tlv->next = base;
}

static void TLVNext(struct tTLV *tlv, u8 tag)
{
	assert(tlv->next + 2 < tlv->end);
	tlv->current = tlv->next;
	*(tlv->next++) = tag;
	*(tlv->next++) = 0;
}

static void TLVAdd(struct tTLV *tlv, u8 val)
{
	assert(tlv->next + 1 < tlv->end);
	*(tlv->next++) = val;
	tlv->current[1]++;
}

static void TLVAddBuffer(struct tTLV *tlv, u8 * val, size_t size)
{
	assert(tlv->next + size < tlv->end);
	memcpy(tlv->next, val, size);
	tlv->current[1] = size;
	tlv->next = tlv->next + size;
}

static size_t TLVLen(struct tTLV *tlv)
{
	return tlv->next - tlv->base;
}

static LONG SCR_SCardInit(LPCTSTR szPinPadDll, LPCTSTR szReader, DWORD version,
			  SCR_SupportConstants * supported)
{
	LONG rv;
	unsigned char sendbuf[256];
	unsigned char recvbuf[2];
	char szTemp[32];
	DWORD dwRecvLength;
	struct tTLV tlv;

	memset(szTemp, 0, sizeof(szTemp));
	memset(sendbuf, 0, sizeof(sendbuf));
	memset(recvbuf, 0, sizeof(recvbuf));
	dwRecvLength = sizeof(recvbuf);

	/* Make TLV buffer */
	TLVInit(&tlv, sendbuf, sizeof(sendbuf));
	TLVNext(&tlv, 0x01);	/* Function ID */
	sprintf(szTemp, "%ld", SCR_INIT_ID);
	TLVAddBuffer(&tlv, (u8 *) szTemp, strlen(szTemp));
	TLVNext(&tlv, 0x02);	/* PinPad Dll */
	TLVAddBuffer(&tlv, (u8 *) szPinPadDll, strlen(szPinPadDll));
	TLVNext(&tlv, 0x03);	/* Reader Name */
	TLVAddBuffer(&tlv, (u8 *) szReader, strlen(szReader));
	TLVNext(&tlv, 0x04);	/* Version */
	sprintf(szTemp, "%ld", version);
	TLVAddBuffer(&tlv, (u8 *) szTemp, strlen(szTemp));

#ifdef HAVE_PCSC_OLD
	rv = SCardControl(SCR_CARD_HANDLE, sendbuf, TLVLen(&tlv), recvbuf, &dwRecvLength);
#else
	rv = SCardControl(SCR_CARD_HANDLE, 0, sendbuf, TLVLen(&tlv),
			  recvbuf, dwRecvLength, &dwRecvLength);
#endif
	if (dwRecvLength > 0) {
		*supported = recvbuf[0];
	} else {
		rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}

	return rv;
}

static LONG SCR_SCardPIN(long lAction, LPCTSTR szPinPadDll, const SCR_Card * pCard, BYTE pinID,
			 const SCR_PinUsage * pUsage, const SCR_Application * pApp,
			 BYTE * pCardStatus)
{
	LONG rv;
	unsigned char sendbuf[256];
	unsigned char recvbuf[2];
	char szTemp[32];
	DWORD dwRecvLength;
	struct tTLV tlv;

	memset(szTemp, 0, sizeof(szTemp));
	memset(recvbuf, 0, sizeof(recvbuf));
	dwRecvLength = sizeof(recvbuf);

	/* Make TLV buffer */
	TLVInit(&tlv, sendbuf, sizeof(sendbuf));
	TLVNext(&tlv, 0x01);	/* Function ID */
	sprintf(szTemp, "%ld", lAction);
	TLVAddBuffer(&tlv, (u8 *) szTemp, strlen(szTemp));
	TLVNext(&tlv, 0x02);	/* PinPad Dll */
	TLVAddBuffer(&tlv, (u8 *) szPinPadDll, strlen(szPinPadDll));
	TLVNext(&tlv, 0x03);	/* SCR_Card Handle */
	sprintf(szTemp, "%ld", pCard->hCard);
	TLVAddBuffer(&tlv, (u8 *) szTemp, strlen(szTemp));
	if (pCard->language != NULL) {
		TLVNext(&tlv, 0x04);	/* SCR_Card language */
		TLVAddBuffer(&tlv, (u8 *) pCard->language, strlen(pCard->language));
	}
	if (pCard->id.data != NULL) {
		TLVNext(&tlv, 0x05);	/* SCR_Card id */
		TLVAddBuffer(&tlv, pCard->id.data, pCard->id.length);
	}
	TLVNext(&tlv, 0x06);	/* PinID */
	TLVAdd(&tlv, pinID);
	if (pUsage != NULL) {
		TLVNext(&tlv, 0x07);	/* SCR_PinUsage code */
		sprintf(szTemp, "%ld", pUsage->code);
		TLVAddBuffer(&tlv, (u8 *) szTemp, strlen(szTemp));
		if (pUsage->shortString != NULL) {
			TLVNext(&tlv, 0x08);	/* SCR_PinUsage shortstring */
			TLVAddBuffer(&tlv, (u8 *) pUsage->shortString, strlen(pUsage->shortString));
		}
		if (pUsage->longString != NULL) {
			TLVNext(&tlv, 0x09);	/* SCR_PinUsage longstring */
			TLVAddBuffer(&tlv, (u8 *) pUsage->longString, strlen(pUsage->longString));
		}
	}
	if (pApp->id.data != NULL) {
		TLVNext(&tlv, 0x0A);	/* SCR_Application id */
		TLVAddBuffer(&tlv, (u8 *) pApp->id.data, pApp->id.length);
	}
	if (pApp->shortString != NULL) {
		TLVNext(&tlv, 0x0B);	/* SCR_Application shortstring */
		TLVAddBuffer(&tlv, (u8 *) pApp->shortString, strlen(pApp->shortString));
	}
	if (pApp->longString != NULL) {
		TLVNext(&tlv, 0x0C);	/* SCR_Application longstring */
		TLVAddBuffer(&tlv, (u8 *) pApp->longString, strlen(pApp->longString));
	}
#ifdef HAVE_PCSC_OLD
	rv = SCardControl(SCR_CARD_HANDLE, sendbuf, TLVLen(&tlv), recvbuf, &dwRecvLength);
#else
	rv = SCardControl(SCR_CARD_HANDLE, 0, sendbuf, TLVLen(&tlv),
			  recvbuf, dwRecvLength, &dwRecvLength);
#endif
	if (dwRecvLength < 2) {
		rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
	} else {
		memcpy(pCardStatus, recvbuf, 2);
	}

	return rv;
}

static LONG SCR_SCardVerifyPIN(LPCTSTR szPinPadDll, const SCR_Card * pCard, BYTE pinID,
			       const SCR_PinUsage * pUsage, const SCR_Application * pApp,
			       BYTE * pCardStatus)
{
	return SCR_SCardPIN(SCR_VERIFY_ID, szPinPadDll, pCard, pinID, pUsage, pApp, pCardStatus);
}

static LONG SCR_SCardChangePIN(LPCTSTR szPinPadDll, const SCR_Card * pCard, BYTE pinID,
			       const SCR_Application * pApp, BYTE * pCardStatus)
{
	return SCR_SCardPIN(SCR_CHANGE_ID, szPinPadDll, pCard, pinID, NULL, pApp, pCardStatus);
}

#endif	/* BELPIC_PIN_PAD */

#if defined(HAVE_GUI) ||defined(BELPIC_PIN_PAD)

static int belpic_calculate_lang(sc_card_t *card)
{
	struct belpic_priv_data *priv = DRVDATA(card);
	int lang = priv->lang;
	return lang;
}

#endif	/* defined(HAVE_GUI) ||defined(BELPIC_PIN_PAD) */

static int str2lang(sc_context_t *ctx, char *lang)
{
	if (memcmp(lang, "en", 2) == 0)
		return LNG_ENG;
	else if (memcmp(lang, "nl", 2) == 0)
		return LNG_DUTCH;
	else if (memcmp(lang, "fr", 2) == 0)
		return LNG_FRENCH;
	else if (memcmp(lang, "de", 2) == 0)
		return LNG_GERMAN;
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Unknown/unsupported language code: %c%c\n", lang[0], lang[1]);
	return -1;
}

static int get_carddata(sc_card_t *card, u8* carddata_loc, unsigned int carddataloc_len)
{
	sc_apdu_t apdu;
	u8 carddata_cmd[] = { 0x80, 0xE4, 0x00, 0x00, 0x1C };
	int r;

	assert(carddataloc_len == BELPIC_CARDDATA_RESP_LEN);

	r = sc_bytes2apdu(card->ctx, carddata_cmd, sizeof(carddata_cmd), &apdu);
	if(r) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "bytes to APDU conversion failed: %d\n", r);
		return r;
	}

	apdu.resp = carddata_loc;
	apdu.resplen = carddataloc_len;

	r = sc_transmit_apdu(card, &apdu);
	if(r) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "GetCardData command failed: %d\n", r);
		return r;
	}

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if(r) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "GetCardData: card returned %d\n", r);
		return r;
	}
	if(apdu.resplen < carddataloc_len) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "GetCardData: card returned %d bytes rather than expected %d\n", apdu.resplen, carddataloc_len);
		return SC_ERROR_WRONG_LENGTH;
	}

	return 0;
}

#ifdef GET_LANG_FROM_CARD

/* str is in lower case, the case of buf can be both, and buf is large enough */
static int match_string(const char *str, const char *buf)
{
	int i = 0;

	while (str[i] != '\0') {
		if (str[i] != ((buf[i] >= 'A' && buf[i] <= 'Z') ? buf[i] + 32 : buf[i]))
			return 0;
		i++;
	}
	return 1;		/* match */
}

static int get_pref(const char *prefs, int prefs_len, const char *title, const char *key, int *len)
{
	int i = 0;
	int title_len = strlen(title);
	int key_len = strlen(key);

	while (prefs[i] != '\0' && i < prefs_len)
		i++;
	prefs_len = i;

	i = 0;
	while (i < prefs_len) {
		while (i < prefs_len && prefs[i] != '[')
			i++;
		if (i + title_len >= prefs_len)
			return -1;
		if (!match_string(title, prefs + i)) {
			i++;
			continue;
		}
		i += title_len;
		while (i < prefs_len) {
			while (i < prefs_len && (prefs[i] == '\r' || prefs[i] == '\n'))
				i++;
			if (i < prefs_len && prefs[i] == '[')
				break;
			if (i + key_len + 1 >= prefs_len)
				return -2;
			if (!match_string(key, prefs + i)) {
				i++;
				continue;
			}
			i += key_len;
			if (prefs[i] != '=')
				return -3;
			*len = ++i;
			while (*len < prefs_len && prefs[*len] != '\r' && prefs[*len] != '\n')
				(*len)++;
			*len -= i;
			return i;
		}
	}

	return -1;
}

static int get_language(sc_card_t *card)
{
	sc_apdu_t apdu;
	u8 prefs[240], *lg_value;
	u8 path[] = { 0x3F, 0x00, 0xDF, 0x01, 0x40, 0x39 };
	int r, i, len;

	/* Get the language from the card's preferences file */
	assert(card != NULL);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x08, 0x0C);
	apdu.lc = sizeof(path);
	apdu.data = path;
	apdu.datalen = sizeof(path);
	apdu.resplen = 0;
	apdu.le = 0;

	r = sc_lock(card);
	if (r < 0)
		goto prefs_error;

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Select_File[prefs_file] command failed: %d\n", r);
		sc_unlock(card);
		goto prefs_error;
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r < 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Select_File[prefs_file]: card returned %d\n", r);
		sc_unlock(card);
		goto prefs_error;
	}

	r = iso_ops->read_binary(card, 0, prefs, sizeof(prefs), 0);
	sc_unlock(card);
	if (r <= 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Read_Binary[prefs_file] returned %d\n", r);
		goto prefs_error;
	}
	i = get_pref(prefs, r, "[gen]", "lg", &len);
	if (i <= 0 || len < 2) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Couldn't find language in prefs file: %d\n", i);
		goto prefs_error;
	}
	lg_value = prefs + i;	/* language code(s) found, starts here */
	i = 0;
	while (1) {
		while (i <= len - 2 && (lg_value[i] == ' ' || lg_value[i] == '|'))
			i++;
		if (i > len - 2)
			goto prefs_error;
		r = str2lang(card->ctx, lg_value + i);
		if (r >= 0)
			return r;
		i += 2;
	}

      prefs_error:
	/* If troubles with the card's prefs file, get the language from the OS */
#ifdef _WIN32
	switch (GetUserDefaultLangID() & 0x00FF) {
	case 0x13:
		return LNG_DUTCH;
	case 0x0C:
		return LNG_FRENCH;
	case 0x07:
		return LNG_GERMAN;
	default:
		return LNG_ENG;
	}
#endif
	return LNG_ENG;		/* default */
}

#endif	/* GET_LANG_FROM_CARD */

static scconf_block *get_belpic_conf(sc_context_t *ctx, const char *name)
{
	scconf_block *conf_block = NULL, **blocks;
	int i;

	for (i = 0; ctx->conf_blocks[i] != NULL; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i], name, NULL);
		if (!blocks)
			return NULL;
		conf_block = blocks[0];
		free(blocks);
		if (conf_block != NULL)
			break;
	}

	return conf_block;
}

#ifdef BELPIC_PIN_PAD

static void load_pin_pad_err(const char *reader_name, const char *pp_reader_lib, char *msg)
{
	char buf[300];
	void *hDlg;

	if (strlen(reader_name) + strlen(pp_reader_lib) > 200)
		return;

	sprintf(buf, "Error while loading library \"%s\" for pin pad reader \"%s\": %s\n",
		pp_reader_lib, reader_name, msg);
	scgui_ask_message(app_msg[0], "Pin pad library error", buf, btn_msg_close[0], NULL,
			  reader_name);
}

static int belpic_load_pin_pad_lib(sc_card_t *card, struct belpic_priv_data *priv_data,
				   const char *reader_name, const char *pp_reader_lib)
{
	LONG r;
	DWORD supported;

	memset(priv_data->szPinPadDll, 0, sizeof(priv_data->szPinPadDll));
	strcpy(priv_data->szPinPadDll, pp_reader_lib);

	priv_data->scr_init = (FARPROC) SCR_SCardInit;
	priv_data->scr_verify_pin = (FARPROC) SCR_SCardVerifyPIN;
	priv_data->scr_change_pin = (FARPROC) SCR_SCardChangePIN;

	if (priv_data->scr_init == NULL || priv_data->scr_verify_pin == NULL) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Function not found in \"%s\" err = 0x%0x\n",
			 pp_reader_lib, GetLastError());
		load_pin_pad_err(reader_name, pp_reader_lib,
				 "unsufficient functionality found in library");
		return SC_ERROR_READER;
	}

	r = priv_data->scr_init(pp_reader_lib, reader_name, 1, &supported);
	if (r != SCARD_S_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "SCR_Init() returned 0x%0x\n", r);
		load_pin_pad_err(reader_name, pp_reader_lib, "Initialization of library failed");
		return SC_ERROR_READER;
	}
	if (supported) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "SCR_init() returned not supported code 0x%0x\n", supported);
		load_pin_pad_err(reader_name, pp_reader_lib,
				 "Initialization of library returned UNSUPPORTED");
		return SC_ERROR_READER;
	}
	return 1;
}

static int belpic_detect_pin_pad(sc_card_t *card, struct belpic_priv_data *priv_data)
{
	int i = 0;
	char *reader_name = card->reader->name, *conf_reader, *conf_lib;
	scconf_block *conf_block = NULL;
	char *reader_i = "reader ", *lib_i = "lib ";
	int rn_len = strlen(reader_name);

	/* Hardcoded readers */
	for (i = 0; pp_reader_names[i] != NULL; i++) {
		int pp_rn_len = strlen(pp_reader_names[i]);
		if (rn_len >= pp_rn_len && strncmp(reader_name, pp_reader_names[i], pp_rn_len) == 0) {
			return belpic_load_pin_pad_lib(card, priv_data,
						       reader_name, pp_reader_libs[i]);
		}
	}

	/* From the config file */
	conf_block = get_belpic_conf(card->ctx, "belpic_pin_pad");
	if (conf_block == NULL)
		return 0;
	for (i = 0; i < 10; i++) {
		reader_i[6] = (char) (0x30 + i);
		conf_reader = (char *) scconf_get_str(conf_block, reader_i, NULL);
		if (conf_reader != NULL && rn_len >= strlen(conf_reader) &&
		    strncmp(reader_name, conf_reader, strlen(conf_reader)) == 0) {
			lib_i[3] = (char) (0x30 + i);
			conf_lib = (char *) scconf_get_str(conf_block, lib_i, NULL);
			if (conf_lib != NULL)
				return belpic_load_pin_pad_lib(card, priv_data,
							       reader_name, conf_lib);
		}
	}

	return 0;
}
#endif	/* BELPIC_PIN_PAD */

static int belpic_finish(sc_card_t *card)
{
	free(DRVDATA(card));
	return 0;
}

static int belpic_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, belpic_atrs, &card->type);
	if (i < 0)
		return 0;
	return 1;
}

static int belpic_init(sc_card_t *card)
{
	struct belpic_priv_data *priv = NULL;
	scconf_block *conf_block;
	u8 applet_version;
	u8 carddata[BELPIC_CARDDATA_RESP_LEN];
	int key_size = 1024;
	int r;

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Belpic V%s", BELPIC_VERSION);
#ifdef HAVE_GUI
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, " with GUI support");
#endif
#ifdef BELPIC_PIN_PAD
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, " with support for pin pad reader libs");
#endif
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "\n");

	if (card->type < 0)
		card->type = SC_CARD_TYPE_BELPIC_EID;	/* Unknown card: assume it's the Belpic Card */

	priv = calloc(1, sizeof(struct belpic_priv_data));
	if (priv == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	card->drv_data = priv;
	card->cla = 0x00;
	if (card->type == SC_CARD_TYPE_BELPIC_EID) {
		if((r = get_carddata(card, carddata, sizeof(carddata))) < 0) {
			return r;
		}
		applet_version = carddata[BELPIC_CARDDATA_OFF_APPLETVERS];
		if(applet_version >= 0x17) {
			key_size = 2048;
		}
		_sc_card_add_rsa_alg(card, key_size,
				     SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE, 0);
	}

	/* State that we have an RNG */
	card->caps |= SC_CARD_CAP_RNG;

	/* Language prefences */
	priv->lang = -1;
	conf_block = get_belpic_conf(card->ctx, "belpic_general");
	if (conf_block != NULL) {
		char *lang = (char *) scconf_get_str(conf_block, "force_language", NULL);
		if (lang != NULL && strlen(lang) == 2)
			priv->lang = str2lang(card->ctx, lang);
	}
#ifdef GET_LANG_FROM_CARD
	if (priv->lang == -1)
		priv->lang = get_language(card);
#endif

	card->max_pin_len = BELPIC_MAX_USER_PIN_LEN;

#ifdef HAVE_GUI
	r = scgui_init();
	if (r != 0)
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "scgui_init() returned error %d\n", i);
#endif

#ifdef BELPIC_PIN_PAD
	r = belpic_detect_pin_pad(card, priv);
	if (r == 1)
		card->reader->capabilities |= SC_READER_CAP_PIN_PAD;
	else if (r < 0)
		return r;	/* error loading/initing pin pad lib */

	conf_block = get_belpic_conf(card->ctx, "belpic_pin_pad");
	if (conf_block != NULL) {
		if (scconf_get_bool(conf_block, "msg_auth_pin", 1))
			priv->options |= PP_MSG_AUTH_PIN;
		if (scconf_get_bool(conf_block, "msg_wrong_pin", 1))
			priv->options |= PP_MSG_WRONG_PIN;
		if (scconf_get_bool(conf_block, "msg_changepin_mismatch", 1))
			priv->options |= PP_MSG_CHANGEPIN_MISMATCH;
		if (scconf_get_bool(conf_block, "msg_pin_blocked", 1))
			priv->options |= PP_MSG_PIN_BLOCKED;
	}
#endif

	return 0;
}

static int belpic_select_file(sc_card_t *card,
			      const sc_path_t *in_path, sc_file_t **file_out)
{
	sc_apdu_t apdu;
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int r, pathlen;
	sc_file_t *file = NULL;

	assert(card != NULL && in_path != NULL);
	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x08, 0x0C);

	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	apdu.resplen = 0;
	apdu.le = 0;

	r = sc_transmit_apdu(card, &apdu);

	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Select File APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);

	next_idx = (size_t)-1;		/* reset */

	if (file_out != NULL) {
		file = sc_file_new();
		file->path = *in_path;
		if (pathlen >= 2)
			file->id = (in_path->value[pathlen - 2] << 8) | in_path->value[pathlen - 1];
		file->size = BELPIC_MAX_FILE_SIZE;
		file->shareable = 1;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		if (pathlen == 2 && memcmp("\x3F\x00", in_path->value, 2) == 0)
			file->type = SC_FILE_TYPE_DF;
		else
			file->type = SC_FILE_TYPE_WORKING_EF;
		*file_out = file;
	}

	return 0;
}

static int belpic_read_binary(sc_card_t *card,
			      unsigned int idx, u8 * buf, size_t count, unsigned long flags)
{
	int r;

	if (next_idx == idx)
		return 0;	/* File was already read entirely */

	t1 = clock();
	r = iso_ops->read_binary(card, idx, buf, count, flags);
	t2 = clock();

	/* If the 'next_idx trick' shouldn't work, we hope this error
	 * means that an attempt was made to read beyond the file's
	 * contents, so we'll return 0 to end the loop in sc_read_binary()*/
	if (r == SC_ERROR_INCORRECT_PARAMETERS)
		return 0;

	if (r >= 0 && (size_t)r < count)
		next_idx = idx + (size_t)r;

	dur = t2 - t1;
	tot_dur += dur;
	tot_read += r;
	return r;
}

#ifdef BELPIC_PIN_PAD

/* Test the result code of the pin pad reader + the card's status bytes */
static int belpic_pp_test_res(sc_card_t *card, int r, const u8 * card_status, int *tries_left)
{
	if (r != SCARD_S_SUCCESS) {
		switch (r) {
		case SCARD_E_CANCELLED:
			return SC_ERROR_KEYPAD_CANCELLED;
		case SCARD_W_REMOVED_CARD:
			return SC_ERROR_CARD_REMOVED;
		case SCR_I_PIN_CHECK_FAILED:
			return SC_ERROR_KEYPAD_PIN_MISMATCH;
		default:
			return SC_ERROR_TRANSMIT_FAILED;
		}
	}
	if (card_status[0] == 0xEC && card_status[1] == 0xD2)
		return SC_ERROR_KEYPAD_TIMEOUT;
	if (card_status[0] == 0xEC && card_status[1] == 0xD6)
		return SC_ERROR_KEYPAD_CANCELLED;
	if (card_status[0] == 0x63) {
		if ((card_status[1] & 0xF0) == 0xC0 && tries_left != NULL)
			*tries_left = card_status[1] & 0x0F;
		return SC_ERROR_PIN_CODE_INCORRECT;
	}
	return sc_check_sw(card, card_status[0], card_status[1]);
}

/* Send the verify pin command to the pin pad reader + optionally show message */
static int belpic_pp_verify(sc_card_t *card, SCR_Card * scr_card,
			    struct belpic_priv_data *priv, int pin_ref,
			    int pin_usage, int *tries_left)
{
	BYTE card_status[2];
	void *hDlg;
	int first_time = 1, r = SC_ERROR_PIN_CODE_INCORRECT;
	int lang = belpic_calculate_lang(card);
	SCR_PinUsage scr_pin_usage = {
		pin_usage,
		pin_usage == SCR_USAGE_SIGN ? "SIG" : "AUT",
		pin_usage == SCR_USAGE_SIGN ? pin_usg_sig[lang] : pin_usg_auth[lang]
	};
	char *reader_name = card->reader->name;
	char *pp_msg_login_sh =
	    (pin_usage == SCR_USAGE_SIGN ? pp_msg_sign_sh[lang] : pp_msg_auth_sh[lang]);
	char *pp_msg_login = (pin_usage == SCR_USAGE_SIGN ? pp_msg_sign[lang] : pp_msg_auth[lang]);
	scgui_param_t icon = (pin_usage == SCR_USAGE_SIGN ? SCGUI_SIGN_ICON : SCGUI_NO_ICON);
	int mesg_on_screen = (priv->options & PP_MSG_AUTH_PIN) ||
	    (pin_usage != SCR_USAGE_AUTH) || SSO_OK(card->ctx);

	while (r == SC_ERROR_PIN_CODE_INCORRECT) {
		if (!first_time) {
			if (priv->options & PP_MSG_WRONG_PIN) {
				int r1;
				char msg[200];

				sprintf(msg, wrong_pin_msgs[lang], *tries_left);
				r1 = scgui_ask_message(app_msg[lang], pp_msg_login_sh, msg,
						       btn_msg_retry[lang], btn_msg_cancel[lang],
						       reader_name);
				if (r1 == SCGUI_CANCEL)
					return r;
				else if (r1 != SCGUI_OK) {
					sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "scgui_ask_message returned %d\n", r1);
					return SC_ERROR_INTERNAL;
				}
			} else
				return r;
		}
		first_time = 0;

		if (mesg_on_screen) {
			scgui_display_message(app_msg[lang], pp_msg_login_sh, pp_msg_login,
					      NULL, &hDlg, icon, reader_name);
		}
		r = priv->scr_verify_pin(priv->szPinPadDll, scr_card, pin_ref,
					 &scr_pin_usage, &scr_app_belpic, card_status);
		if (mesg_on_screen)
			scgui_remove_message(hDlg);

		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "SCR_Verify_PIN(): res = 0x%0x, status = %2X %2X\n",
			 r, card_status[0], card_status[1]);
		r = belpic_pp_test_res(card, r, card_status, tries_left);
	}

	return r;
}

/* Send the change pin command to the pin pad reader + show message */
static int belpic_pp_change(sc_card_t *card, SCR_Card * scr_card,
			    struct belpic_priv_data *priv, int pin_ref, int *tries_left)
{
	BYTE card_status[2];
	void *hDlg;
	int first_time = 1, r = SC_ERROR_KEYPAD_PIN_MISMATCH, r1;
	int lang = belpic_calculate_lang(card);
	char *reader_name = card->reader->name;

	while (r == SC_ERROR_KEYPAD_PIN_MISMATCH || r == SC_ERROR_PIN_CODE_INCORRECT) {
		if (!first_time) {
			int r1 = SCGUI_OK;
			if (r == SC_ERROR_KEYPAD_PIN_MISMATCH) {
				if (!(priv->options & PP_MSG_CHANGEPIN_MISMATCH))
					return r;
				r1 = scgui_ask_message(app_msg[lang], pp_msg_change_sh[lang],
						       pp_msg_pin_mismatch[lang],
						       btn_msg_retry[lang], btn_msg_cancel[lang],
						       reader_name);
			}
			if (r == SC_ERROR_PIN_CODE_INCORRECT) {
				char msg[200];

				if (!(priv->options & PP_MSG_WRONG_PIN))
					return r;
				sprintf(msg, wrong_pin_msgs[lang], *tries_left);
				r1 = scgui_ask_message(app_msg[lang], pp_msg_change_sh[lang],
						       msg, btn_msg_retry[lang],
						       btn_msg_cancel[lang], reader_name);
			}
			if (r1 == SCGUI_CANCEL)
				return r;
			else if (r1 != SCGUI_OK) {
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "scgui_ask_message returned %d\n", r1);
				return SC_ERROR_INTERNAL;
			}
		}
		first_time = 0;

		scgui_display_message(app_msg[lang], pp_msg_change_sh[lang],
				      pp_msg_change[lang], NULL, &hDlg, SCGUI_NO_ICON, reader_name);
		r = priv->scr_change_pin(priv->szPinPadDll, scr_card, pin_ref,
					 &scr_app_belpic, card_status);
		scgui_remove_message(hDlg);

		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "SCR_Change_PIN(): res = 0x%0x, status = %2X %2X\n",
			 r, card_status[0], card_status[1]);
		r = belpic_pp_test_res(card, r, card_status, tries_left);
	}

	return r;
}

#endif	/* BELPIC_PIN_PAD */

static int belpic_pin_cmd_usage(sc_card_t *card, struct sc_pin_cmd_data *data,
				int *tries_left, int pin_usage)
{
#ifdef BELPIC_PIN_PAD
	sc_apdu_t apdu;
	int r;

	struct belpic_priv_data *priv = DRVDATA(card);
	int lang = belpic_calculate_lang(card);
	if (card->reader->capabilities & SC_READER_CAP_PIN_PAD && priv->scr_init != NULL) {
		LONG r;
		SCR_Card scr_card = {
			priv->pcsc_card,
			lang_codes[lang],
			{NULL, 0}
			,
			NULL
		};

		scr_app_belpic.longString = app_id_longstr[lang];

		switch (data->cmd) {
		case SC_PIN_CMD_VERIFY:
			r = belpic_pp_verify(card, &scr_card,
					     priv, data->pin_reference, pin_usage, tries_left);
			break;
		case SC_PIN_CMD_CHANGE:
			r = belpic_pp_change(card, &scr_card,
					     priv, data->pin_reference, tries_left);
			break;
		default:
			r = SC_ERROR_NOT_SUPPORTED;
		}

		if (r == SC_ERROR_AUTH_METHOD_BLOCKED && (priv->options & PP_MSG_PIN_BLOCKED))
			scgui_ask_message(app_msg[lang], " ", pin_blocked_msgs[lang],
					  btn_msg_close[lang], NULL, card->reader->name);
		return r;
	}
#endif	/* BELPIC_PIN_PAD */

	data->pin1.encoding = data->pin2.encoding = BELPIC_PIN_ENCODING;
	data->pin1.pad_char = data->pin2.pad_char = BELPIC_PAD_CHAR;
	data->pin1.min_length = data->pin2.min_length = BELPIC_MIN_USER_PIN_LEN;
	data->pin1.max_length = data->pin2.max_length = BELPIC_MAX_USER_PIN_LEN;
	data->apdu = NULL;

	return iso_ops->pin_cmd(card, data, tries_left);
}

static int belpic_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	if (SSO_OK(card->ctx) && data->cmd == SC_PIN_CMD_VERIFY)
		return 0;	/* Don't log in right now, just say it's OK */
	else
		return belpic_pin_cmd_usage(card, data, tries_left, 1);	/* SCR_USAGE_AUTH = 1 */
}

#ifdef HAVE_GUI

/* Called by belpic_set_security_env() when a NonRep signature will be done,
 * or by belpic-compute_signature the first fime an auth signature is done
 * and the allow_sso is true
 */
static int belpic_askpin_verify(sc_card_t *card, int pin_usage)
{
	struct sc_pin_cmd_data data;
	sc_apdu_t apdu;
	u8 pin_data[BELPIC_MAX_USER_PIN_LEN + 1];
	int pin_len;
	int tries_left;
	int r;
	struct belpic_priv_data *priv = DRVDATA(card);
	int lang = belpic_calculate_lang(card);
	char *enter_pin_msg = (pin_usage == SCR_USAGE_AUTH ?
			       enter_pin_msg_auth[lang] : enter_pin_msg_sign[lang]);
	scgui_param_t icon = (pin_usage == SCR_USAGE_AUTH ? SCGUI_NO_ICON : SCGUI_SIGN_ICON);

	data.pin1.encoding = BELPIC_PIN_ENCODING;
	data.pin1.pad_char = BELPIC_PAD_CHAR;
	data.pin1.min_length = BELPIC_MIN_USER_PIN_LEN;
	data.pin1.max_length = BELPIC_MAX_USER_PIN_LEN;

	data.cmd = SC_PIN_CMD_VERIFY;
	data.flags = 0;
	data.pin_type = SC_AC_CHV;
	data.pin_reference = 1;


#ifdef BELPIC_PIN_PAD
	/* In case of a pinpad reader */
	if (card->reader->capabilities & SC_READER_CAP_PIN_PAD && priv->scr_init != NULL) {
		data.pin1.data = NULL;
		data.pin1.len = 0;

		return belpic_pin_cmd_usage(card, &data, &tries_left, pin_usage);
	}
#endif

	pin_len = BELPIC_MAX_USER_PIN_LEN + 1;
	r = scgui_enterpin(app_msg[lang], enter_pin_msg, pin_data, &pin_len,
			   btn_msg_ok[lang], btn_msg_cancel[lang], wrong_pin_len_msgs[lang], icon);
	if (r == SCGUI_CANCEL)
		return SC_ERROR_KEYPAD_CANCELLED;
	if (r != SCGUI_OK)
		return SC_ERROR_INTERNAL;

	data.pin1.data = pin_data;
	data.pin1.len = pin_len;
	r = belpic_pin_cmd_usage(card, &data, &tries_left, pin_usage);

	/* card->ctx->allow_sso = true: we do PIN mgmnt ourselves */
	while (r == SC_ERROR_PIN_CODE_INCORRECT && SSO_OK(card->ctx)) {
		int r1;
		char msg[200];

		sprintf(msg, wrong_pin_msgs[lang], tries_left);
		r1 = scgui_ask_message(app_msg[lang], pin_usg_auth[lang], msg,
				       btn_msg_retry[lang], btn_msg_cancel[lang],
				       card->reader->name);
		if (r1 == SCGUI_CANCEL)
			return r;
		else if (r1 != SCGUI_OK) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "scgui_ask_message returned %d\n", r1);
			return SC_ERROR_INTERNAL;
		}

		pin_len = BELPIC_MAX_USER_PIN_LEN + 1;
		r = scgui_enterpin(app_msg[lang], enter_pin_msg, pin_data, &pin_len,
				   btn_msg_ok[lang], btn_msg_cancel[lang], wrong_pin_len_msgs[lang],
				   icon);
		if (r == SCGUI_CANCEL)
			return SC_ERROR_KEYPAD_CANCELLED;
		if (r != SCGUI_OK)
			return SC_ERROR_INTERNAL;

		data.pin1.data = pin_data;
		data.pin1.len = pin_len;
		r = belpic_pin_cmd_usage(card, &data, &tries_left, pin_usage);
		if (tries_left == 0)
			r = SC_ERROR_AUTH_METHOD_BLOCKED;
	}

	if (r == SC_ERROR_AUTH_METHOD_BLOCKED && SSO_OK(card->ctx))
		scgui_ask_message(app_msg[lang], " ", pin_blocked_msgs[lang],
				  btn_msg_close[lang], NULL, card->reader->name);

	return r;
}
#endif	/* HAVE_GUI */

static int belpic_set_security_env(sc_card_t *card,
				   const sc_security_env_t *env, int se_num)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "belpic_set_security_env(), keyRef = 0x%0x, algo = 0x%0x\n",
		 *env->key_ref, env->algorithm_flags);

	assert(card != NULL && env != NULL);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0, 0);
	switch (env->operation) {
	case SC_SEC_OPERATION_SIGN:
		apdu.p1 = 0x41;
		apdu.p2 = 0xB6;
		sbuf[0] = 0x04;	/* length of the following data */
		sbuf[1] = 0x80;	/* tag for algorithm reference */
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1)
			sbuf[2] = 0x01;
		else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)
			sbuf[2] = 0x02;
		else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_MD5)
			sbuf[2] = 0x04;
		else {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Set Sec Env: unsupported algo 0X%0X\n",
				 env->algorithm_flags);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		sbuf[3] = 0x84;	/* tag for private key reference */
		sbuf[4] = *env->key_ref;	/* key reference */
		apdu.lc = 5;
		apdu.datalen = 5;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	apdu.le = 0;
	apdu.data = sbuf;
	apdu.resplen = 0;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Set Security Env APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card's Set Security Env command returned error");

	/* If a NonRep signature will be done, ask to enter a PIN. It would be more
	 * logical to put the code below into the compute signature function because
	 * a Verify Pin call must immediately preceed a Compute Signature call.
	 * It's not done because the Compute Signature is completely ISO7816 compliant
	 * so we use the iso7816_compute_signature() function, and because this function
	 * doesn't know about the key reference.
	 * It's not a problem either, because this function is (for pkcs11) only called
	 * by sc_pkcs15_compute_signature(), where the card is already locked, and
	 * the next function to be executed will be the compute_signature function.
	 */
	if (*env->key_ref == BELPIC_KEY_REF_NONREP) {
#ifdef HAVE_GUI
		r = belpic_askpin_verify(card, SCR_USAGE_SIGN);
		if (r != 0 && r != SC_ERROR_KEYPAD_CANCELLED)
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Verify PIN in SET command returned %d\n", r);
		else
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Verify PIN in SET command returned %d\n", r);
#else
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "No GUI for NonRep key present, signature cancelled\n");
		return SC_ERROR_NOT_SUPPORTED;
#endif
	}

	return r;
}

static int belpic_compute_signature(sc_card_t *card, const u8 * data,
				    size_t data_len, u8 * out, size_t outlen)
{
	int r;

	r = iso_ops->compute_signature(card, data, data_len, out, outlen);

#ifdef HAVE_GUI
	if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED && SSO_OK(card->ctx)) {
		r = belpic_askpin_verify(card, SCR_USAGE_AUTH);
		if (r == 0)
			r = iso_ops->compute_signature(card, data, data_len, out, outlen);
	}
#endif

	return r;
}

static int belpic_update_binary(sc_card_t *card,
			unsigned int idx, const u8 *buf, size_t count,
			unsigned long flags)
{
       int r;

       r = iso_ops->update_binary(card, idx, buf, count, flags);

#ifdef HAVE_GUI
       if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED && SSO_OK(card->ctx)) {
               r = belpic_askpin_verify(card, SCR_USAGE_AUTH);
               if (r == 0)
                       r = iso_ops->update_binary(card, idx, buf, count, flags);
       }
#endif

       return r;
}

static struct sc_card_driver *sc_get_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;

	belpic_ops.match_card = belpic_match_card;
	belpic_ops.init = belpic_init;
	belpic_ops.finish = belpic_finish;

	belpic_ops.update_binary = belpic_update_binary;
	belpic_ops.select_file = belpic_select_file;
	belpic_ops.read_binary = belpic_read_binary;
	belpic_ops.pin_cmd = belpic_pin_cmd;
	belpic_ops.set_security_env = belpic_set_security_env;

	belpic_ops.compute_signature = belpic_compute_signature;
	belpic_ops.get_challenge = iso_ops->get_challenge;
	belpic_ops.get_response = iso_ops->get_response;
	belpic_ops.check_sw = iso_ops->check_sw;

	return &belpic_drv;
}

#if 1
struct sc_card_driver *sc_get_belpic_driver(void)
{
	return sc_get_driver();
}
#endif
