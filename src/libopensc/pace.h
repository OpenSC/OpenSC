/*
 * opensc.h: PACE library header file
 *
 * Copyright (C) ???? Frank Morgner <morgner@informatik.hu-berlin.de>
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

#ifndef _PACE_H
#define _PACE_H

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "libopensc/opensc.h"
#ifdef ENABLE_SM
#include "libopensc/sm.h"
#endif

#define PACE_PIN_ID_MRZ 0x01
#define PACE_PIN_ID_CAN 0x02
#define PACE_PIN_ID_PIN 0x03
#define PACE_PIN_ID_PUK 0x04
/**
 * Input data for EstablishPACEChannel()
 */
struct establish_pace_channel_input {
    /** Type of secret (CAN, MRZ, PIN or PUK). */
    unsigned char pin_id;

    /** Length of \a chat */
    size_t chat_length;
    /** Card holder authorization template */
    const unsigned char *chat;

    /** Length of \a pin */
    size_t pin_length;
    /** Secret */
    const unsigned char *pin;

    /** Length of \a certificate_description */
    size_t certificate_description_length;
    /** Certificate description */
    const unsigned char *certificate_description;
};

/**
 * Output data for EstablishPACEChannel()
 */
struct establish_pace_channel_output {
    /** PACE result (TR-03119) */
    unsigned int result;

    /** MSE: Set AT status byte */
    unsigned char mse_set_at_sw1;
    /** MSE: Set AT status byte */
    unsigned char mse_set_at_sw2;

    /** Length of \a ef_cardaccess */
    size_t ef_cardaccess_length;
    /** EF.CardAccess */
    unsigned char *ef_cardaccess;

    /** Length of \a recent_car */
    size_t recent_car_length;
    /** Most recent certificate authority reference */
    unsigned char *recent_car;

    /** Length of \a previous_car */
    size_t previous_car_length;
    /** Previous certificate authority reference */
    unsigned char *previous_car;

    /** Length of \a id_icc */
    size_t id_icc_length;
    /** ICC identifier */
    unsigned char *id_icc;

    /** Length of \a id_pcd */
    size_t id_pcd_length;
    /** PCD identifier */
    unsigned char *id_pcd;
};

#ifdef __cplusplus
}
#endif

#endif
