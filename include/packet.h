
/* $Id: packet.h 2672 2010-07-13 09:05:28Z alor $ */

#ifndef __PACKET_H
#define __PACKET_H

#include <proto.h>
#include <inet.h>
#include <match.h>

#include <sys/time.h>

struct packet_object {

   /* timestamp of the packet */
   struct timeval ts;

   struct L2 {
      u_int8 proto;
      u_char * header;
      size_t len;
      u_int8 src[MEDIA_ADDR_LEN];
      u_int8 dst[MEDIA_ADDR_LEN];
      u_int16 vlan;
      u_int8 flags;
         #define PO_L2_FCS  0x01
   } L2;

   struct L3 {
      u_int16 proto;
      u_char * header;
      u_char * options;
      size_t len;
      size_t payload_len;
      size_t optlen;
      struct ip_addr src;
      struct ip_addr dst;
      u_int8 ttl;
   } L3;

   struct L4 {
      u_int8 proto;
      u_int8 flags;
      u_char * header;
      u_char * options;
      size_t len;
      size_t optlen;
      u_int16 src;
      u_int16 dst;
      u_int32 seq;
      u_int32 ack;
   } L4;

   struct data {
      u_char * data;
      size_t len;
   } DATA;

   size_t len;             /* total length of the packet */
   u_char * packet;        /* the buffer containing the real packet */

   u_int16 flags;                       /* flags relative to the packet */
      #define PO_INTERESTING  ((u_int16)(1<<7))     /* the packet is interesting */
      #define PO_DUP          ((u_int16)(1<<8))     /* the packet is a duplicate we have to free the buffer on destroy */
      #define PO_EOF          ((u_int16)(1<<9))     /* we are reading from a file and this is the last packet */

   char tag[MAX_TAG_LEN];  /* used to tag packets belonging to a specific user */
};

inline int packet_create_object(struct packet_object *po, u_char * buf, size_t len);
inline int packet_destroy_object(struct packet_object *po);
struct packet_object * packet_dup(struct packet_object *po, u_char flag);

/* Do we want to duplicate data? */
#define PO_DUP_NONE     0
#define PO_DUP_PACKET   1

#endif

/* EOF */

// vim:ts=3:expandtab

