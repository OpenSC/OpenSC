#include <errno.h>
#include <linux/usbdevice_fs.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>

#include "usbtoken.h"

#ifdef USB_DEBUG
void debug_hexdump(char *msg, uint8_t * buf, int size)
{
	char line[1024];
	const char hex[16] =
	    { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b',
		'c', 'd', 'e', 'f'
	};
	int n, i, max;

	i = max = 0;
	while (i < size) {
		snprintf(line, sizeof(line), "%s %04x:", msg, i);
		n = strlen(line);

		max = i + 16;
		if (max > size) {
			max = size;
		}
		while (i < max) {
			line[n++] = ' ';
			line[n++] = hex[buf[i] / 16];
			line[n++] = hex[buf[i] % 16];
			i++;
		}
		line[n++] = 0;
		syslog(LOG_DEBUG, line);
	}
}
#endif				/* USB_DEBUG */

int usb_control_xmit(int type, int req, int value, int index, int size,
		     uint8_t * buf)
{
	struct usbdevfs_ctrltransfer ctrl;
	int rc;

	ctrl.requesttype = type;
	ctrl.request = req;
	ctrl.value = value;
	ctrl.index = index;
	ctrl.length = size;
	ctrl.data = buf;
	ctrl.timeout = usbtoken.drv.timeout;

#ifdef USB_DEBUG
	syslog(LOG_DEBUG,
	       "usb xmit %02hx %02hx %02hx %02hx %02hx %02hx %02hx %02hx\n",
	       type, req, value & 0xff, value >> 8, index & 0xff,
	       index >> 8, size & 0xff, size >> 8);

	if (!(type & 0x80))
		debug_hexdump("Sending:", buf, size);
#endif				/* USB_DEBUG */

	rc = ioctl(usbtoken.usbfd, USBDEVFS_CONTROL, &ctrl);
	if (rc == -1) {
		syslog(LOG_ERR, "usb ioctl control transfer failed:%s\n",
		       strerror(errno));
	}
#ifdef USB_DEBUG
	if (type & 0x80)
		debug_hexdump("Received:", buf, rc);
#endif				/* USB_DEBUG */

	return rc;
}

int usb_reset()
{
	int rc;

	rc = ioctl(usbtoken.usbfd, USBDEVFS_RESET, NULL);
	if (rc == -1) {
		syslog(LOG_ERR, "usb ioctl reset failed:%s\n",
		       strerror(errno));
		return USBTOKEN_ERROR;
	}

	return USBTOKEN_OK;
}
