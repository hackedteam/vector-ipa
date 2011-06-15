/*
    MODULE -- UDP decoder module

    Copyright (c) Alberto Ornaghi

    $Id: udp.c 2657 2010-07-07 07:18:33Z alor $
*/

#include <main.h>
#include <decode.h>

/* globals */

struct udp_header {
   u_int16  sport;           /* source port */
   u_int16  dport;           /* destination port */
   u_int16  ulen;            /* udp length */
   u_int16  csum;            /* udp checksum */
};

/* protos */

FUNC_DECODER(decode_udp);
void udp_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init udp_init(void)
{
   add_decoder(PROTO_LAYER, NL_TYPE_UDP, decode_udp);
}


FUNC_DECODER(decode_udp)
{
   struct udp_header *udp;

   DEBUG_MSG(D_EXCESSIVE, "%s", __FUNCTION__);

   udp = (struct udp_header *)DECODE_DATA;

   DECODED_LEN = sizeof(struct udp_header);

   /* source and dest port */
   PACKET->L4.src = udp->sport;
   PACKET->L4.dst = udp->dport;

   PACKET->L4.len = DECODED_LEN;
   PACKET->L4.header = (u_char *)DECODE_DATA;
   PACKET->L4.options = NULL;

   /* this is UDP */
   PACKET->L4.proto = NL_TYPE_UDP;

   /* set up the data poiters */
   PACKET->DATA.data = ((u_char *)udp) + sizeof(struct udp_header);
   if (ntohs(udp->ulen) < (u_int16)sizeof(struct udp_header))
      return NULL;
   PACKET->DATA.len = ntohs(udp->ulen) - (u_int16)sizeof(struct udp_header);

   /* HOOK POINT: HOOK_PACKET_UDP */
   hook_point(HOOK_PACKET_UDP, po);

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

