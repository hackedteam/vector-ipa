
/* $Id: checksum.h 790 2009-08-03 14:34:04Z alor $ */

#ifndef __CHECKSUM_H
#define __CHECKSUM_H

#include <packet.h>

u_int16 L3_checksum(u_char *buf, size_t len);
u_int16 L4_checksum(struct packet_object *po);
#define CSUM_INIT    0
#define CSUM_RESULT  0

u_int32 CRC_checksum(u_char *buf, size_t len, u_int32 init);
#define CRC_INIT_ZERO   0x0
#define CRC_INIT        0xffffffff
#define CRC_RESULT      0xdebb20e3

u_int16 checksum_shouldbe(u_int16 sum, u_int16 computed_sum);

#endif

/* EOF */

// vim:ts=3:expandtab

