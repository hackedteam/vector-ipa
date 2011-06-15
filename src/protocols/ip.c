/*
    MODULE -- IP decoder module

    Copyright (c) Alberto Ornaghi

    $Id: ip.c 3553 2011-06-06 14:10:57Z alor $
*/

#include <main.h>
#include <inet.h>
#include <decode.h>


/* globals */

struct ip_header {
#ifndef WORDS_BIGENDIAN
   u_int8   ihl:4;
   u_int8   version:4;
#else
   u_int8   version:4;
   u_int8   ihl:4;
#endif
   u_int8   tos;
   u_int16  tot_len;
   u_int16  id;
   u_int16  frag_off;
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_FRAG 0x1fff
   u_int8   ttl;
   u_int8   protocol;
   u_int16  csum;
   u_int32  saddr;
   u_int32  daddr;
/*The options start here. */
};

/* protos */

FUNC_DECODER(decode_ip);
void ip_init(void);


/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init ip_init(void)
{
   add_decoder(NET_LAYER, LL_TYPE_IP, decode_ip);
   add_decoder(NET_LAYER, LL_TYPE_PPP_IP, decode_ip);
}


FUNC_DECODER(decode_ip)
{
   FUNC_DECODER_PTR(next_decoder);
   struct ip_header *ip;
   u_int32 t_len;

   DEBUG_MSG(D_EXCESSIVE, "%s", __FUNCTION__);

   ip = (struct ip_header *)DECODE_DATA;

   DECODED_LEN = (u_int32)(ip->ihl * 4);

   /* IP addresses */
   ip_addr_init(&PACKET->L3.src, AF_INET, (u_char *)&ip->saddr);
   ip_addr_init(&PACKET->L3.dst, AF_INET, (u_char *)&ip->daddr);

   /* this is needed at upper layer to calculate the tcp payload size */
   t_len = (u_int32) ntohs(ip->tot_len);
   if (t_len < (u_int32)DECODED_LEN)
      return NULL;
   PACKET->L3.payload_len = t_len - DECODED_LEN;

   /* other relevant infos */
   PACKET->L3.header = (u_char *)DECODE_DATA;
   PACKET->L3.len = DECODED_LEN;

   /* parse the options */
   if ( (u_int32)(ip->ihl * 4) > sizeof(struct ip_header)) {
      PACKET->L3.options = (u_char *)(DECODE_DATA) + sizeof(struct ip_header);
      PACKET->L3.optlen = (u_int32)(ip->ihl * 4) - sizeof(struct ip_header);
   } else {
      PACKET->L3.options = NULL;
      PACKET->L3.optlen = 0;
   }

   PACKET->L3.proto = htons(LL_TYPE_IP);
   PACKET->L3.ttl = ip->ttl;

   /* HOOK POINT: HOOK_PACKET_IP */
   hook_point(HOOK_PACKET_IP, po);

   /* XXX - implement the handling of fragmented packet */
   /* don't process fragmented packets */
   if (ntohs(ip->frag_off) & IP_FRAG || ntohs(ip->frag_off) & IP_MF)
      return NULL;

   /* if the packet is directed to the proxy ip, skip it */
   if (!ip_addr_cmp(&PACKET->L3.dst, &GBL_NET->proxy_ip) || !ip_addr_cmp(&PACKET->L3.src, &GBL_NET->proxy_ip)) {
	   DEBUG_MSG(D_EXCESSIVE, "Packet directed to proxy ip, skipping it");
	   return NULL;
   }

   /* Jump to next Layer */
   next_decoder = get_decoder(PROTO_LAYER, ip->protocol);
   EXECUTE_DECODER(next_decoder);

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

