#ifndef _USBTOKEN_H
#define _USBTOKEN_H

#include <stdint.h>

#define SYSLOG_NAME "usbtoken"
#define PIDFILE "/var/run/usbtoken%d.pid"
#define SOCKET "/var/run/usbtoken/socket%d"
#define UMASK 0000		/* used while creating the socket */
#define MAXTOKEN 10
#define USBTOKEN_OK 0
#define USBTOKEN_ERROR 1
#define USBTOKEN_INCOMPLETE 2

struct token_drv {
	int (*init) ();
	int (*transmit) (uint8_t * send, int send_len, uint8_t * recv,
			 int *recv_len);
	int max_ifsc;
	int timeout;
	char *name;
};

struct token {
	struct token_drv drv;
	int unixfd;
	int connfd;
	int usbfd;
	int usbvendor;
	int usbproduct;
	int slot;
	int ifsc;
	int rc;			/* redundancy check */
	int nad;		/* nad byte */
	int nr;			/* next r block (0|1) */
	int ns;			/* next s block (0|1) */
	uint8_t *atr;
	int atrlen;
};

extern struct token usbtoken;

int etoken_test(char *product);
int eutron_test(char *product);
int ikey2k_test(char *product);
int ikey3k_test(char *product);

/* atr.c */
int parse_atr();
int increase_ifsc();
int is_atr_complete(uint8_t * buffer, int lr);

/* pid.c */
void pid_exit();
int pid_init();

/* socket.c */
int socket_init();
int socket_accept();
int socket_hangup();
int socket_xmit();

/* t1.c */
int t1_process(uint8_t * apdu_cmd, int apdu_cmdlen,
	       uint8_t * apdu_rsp, int *apdu_rsplen);

/* usb.c */
void debug_hexdump(char *msg, uint8_t * buf, int size);
int usb_control_xmit(int type, int req, int value, int index,
		     int size, uint8_t * buf);
int usb_reset();

#endif
