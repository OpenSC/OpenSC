#ifndef _OPENSC_ITACNS_H
#define _OPENSC_ITACNS_H

typedef struct {
	u8 ic_manufacturer_code;
	u8 mask_manufacturer_code;
	u8 os_version_h;
	u8 os_version_l;
	u8 cns_version;
} itacns_drv_data_t;

#define ITACNS_MASKMAN_SIEMENS		0x08
#define ITACNS_MASKMAN_STINCARD		0x09

#endif /* _OPENSC_ITACNS_H */
