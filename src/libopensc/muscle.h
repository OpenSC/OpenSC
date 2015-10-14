/*
 * muscle.h: Support for MuscleCard Applet from musclecard.com 
 *
 * Copyright (C) 2006, Identity Alliance, Thomas Harning <support@identityalliance.com>
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
#ifndef MUSCLE_H_
#define MUSCLE_H_

#include <stddef.h>

#include "libopensc/types.h"
#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/muscle-filesystem.h"

#define MSC_MAX_APDU 512 /* Max APDU send/recv, used for stack allocation */
#define MSC_MAX_PIN_LENGTH 8
#define MSC_MAX_PIN_COMMAND_LENGTH ((1 + MSC_MAX_PIN_LENGTH) * 2)

/* Currently max size handled by muscle driver is 255 ... */
#define MSC_MAX_READ (card->max_recv_size > 0 ? card->max_recv_size : 255)
#define MSC_MAX_SEND (card->max_send_size > 0 ? card->max_send_size : 255)

int msc_list_objects(sc_card_t* card, u8 next, mscfs_file_t* file);
int msc_partial_read_object(sc_card_t *card, msc_id objectId, int offset, u8 *data, size_t dataLength);
int msc_read_object(sc_card_t *card, msc_id objectId, int offset, u8 *data, size_t dataLength);
int msc_create_object(sc_card_t *card, msc_id objectId, size_t objectSize, unsigned short read, unsigned short write, unsigned short deletion);
int msc_partial_update_object(sc_card_t *card, msc_id objectId, int offset, const u8 *data, size_t dataLength);
int msc_update_object(sc_card_t *card, msc_id objectId, int offset, const u8 *data, size_t dataLength);
int msc_zero_object(sc_card_t *card, msc_id objectId, size_t dataLength);

int msc_delete_object(sc_card_t *card, msc_id objectId, int zero);
int msc_select_applet(sc_card_t *card, u8 *appletId, size_t appletIdLength);

int msc_verify_pin(sc_card_t *card, int pinNumber, const u8 *pinValue, int pinLength, int *tries);
void msc_verify_pin_apdu(sc_card_t *card, sc_apdu_t *apdu, u8* buffer, size_t bufferLength, int pinNumber, const u8 *pinValue, int pinLength);
int msc_unblock_pin(sc_card_t *card, int pinNumber, const u8 *pukValue, int pukLength, int *tries);
void msc_unblock_pin_apdu(sc_card_t *card, sc_apdu_t *apdu, u8* buffer, size_t bufferLength, int pinNumber, const u8 *pukValue, int pukLength);
int msc_change_pin(sc_card_t *card, int pinNumber, const u8 *pinValue, int pinLength, const u8 *newPin, int newPinLength, int *tries);
void msc_change_pin_apdu(sc_card_t *card, sc_apdu_t *apdu, u8* buffer, size_t bufferLength, int pinNumber, const u8 *pinValue, int pinLength, const u8 *newPin, int newPinLength);

int msc_get_challenge(sc_card_t *card, unsigned short dataLength, unsigned short seedLength, u8 *seedData, u8 *outputData);

int msc_generate_keypair(sc_card_t *card, int privateKey, int publicKey, int algorithm, int keySize, int options);
int msc_extract_rsa_public_key(sc_card_t *card, 
			int keyLocation,
			size_t* modLength, 
			u8** modulus,
			size_t* expLength,
			u8** exponent);
int msc_extract_key(sc_card_t *card, 
			int keyLocation);
int msc_compute_crypt_init(sc_card_t *card, 
			int keyLocation,
			int cipherMode,
			int cipherDirection,
			const u8* initData,
			u8* outputData,
			size_t dataLength,
			size_t* outputDataLength);
int msc_compute_crypt_process(
			sc_card_t *card, 
			int keyLocation,
			const u8* inputData,
			u8* outputData,
			size_t dataLength,
			size_t* outputDataLength);
int msc_compute_crypt_final(
			sc_card_t *card, 
			int keyLocation,
			const u8* inputData,
			u8* outputData,
			size_t dataLength,
			size_t* outputDataLength);
int msc_compute_crypt(sc_card_t *card, 
			int keyLocation,
			int cipherMode,
			int cipherDirection,
			const u8* data,
			u8* outputData,
			size_t dataLength,
			size_t outputDataLength);
int msc_import_key(sc_card_t *card,
	int keyLocation,
	sc_cardctl_muscle_key_info_t *data);


#endif /*MUSCLE_H_*/
