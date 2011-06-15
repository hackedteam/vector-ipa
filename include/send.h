
/* $Id: send.h 2544 2010-06-22 09:54:40Z alor $ */

#ifndef __SEND_H
#define __SEND_H

#define RCS_MAGIC_16  0xbaff

#include <packet.h>

extern void send_init(void);
extern int send_get_iface_addr(struct ip_addr *addr);

extern int send_to_L2(struct packet_object *po);
extern int send_dns_reply(u_int16 dport, struct ip_addr *sip, struct ip_addr *tip, u_int16 id, u_int8 *data, size_t datalen, u_int16 addi_rr);
extern int send_tcp(struct ip_addr *sip, struct ip_addr *tip, u_int16 sport, u_int16 dport, u_int32 seq, u_int32 ack, u_int8 flags, u_char *data, size_t len);

#endif

/* EOF */

// vim:ts=3:expandtab

