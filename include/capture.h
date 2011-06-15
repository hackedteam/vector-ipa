
/* $Id: capture.h 2628 2010-07-01 13:12:42Z alor $ */

#ifndef __CAPTURE_H
#define __CAPTURE_H

#include <threads.h>

void capture_init(void);
void capture_close(void);
void capture_start(void);
void capture_stop(void);

int is_pcap_file(char *file, char *errbuf);
void capture_getifs(void);

#define IFACE_DOWN 0x00
#define IFACE_UP   0x01

#endif

/* EOF */

// vim:ts=3:expandtab

