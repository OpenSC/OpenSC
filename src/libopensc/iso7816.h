/*
 * iso7816.h: ISO-7816 defines
 */

#ifndef _ISO7816_TYPES_H
#define _ISO7816_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#define ISO7816_TAG_FCP		0x62
#define ISO7816_TAG_FCP_SIZE	0x80
#define ISO7816_TAG_FCP_TYPE	0x82
#define ISO7816_TAG_FCP_ID	0x83
#define ISO7816_TAG_FCP_ACLS	0x86

/* Interindustry data tags */	
#define ISO7816_TAG_II_CARD_SERVICE             0x43
#define ISO7816_TAG_II_INITIAL_ACCESS_DATA      0x44
#define ISO7816_TAG_II_CARD_ISSUER_DATA         0x45
#define ISO7816_TAG_II_PRE_ISSUING              0x46
#define ISO7816_TAG_II_CARD_CAPABILITIES        0x47
#define ISO7816_TAG_II_AID                      0x4F
#define ISO7816_TAG_II_IO_BUFFER_SIZES          0xE0
#define ISO7816_TAG_II_ALLOCATION_SCHEME        0x78
#define ISO7816_TAG_II_STATUS                   0x82

#define ISO7816_FILE_TYPE_TRANSPARENT_EF	0x01
#define ISO7816_FILE_TYPE_DF			0x38

#ifdef __cplusplus
}
#endif

#endif
