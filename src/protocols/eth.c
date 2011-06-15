/*
    MODULE -- ETH decoder module

    Copyright (c) Alberto Ornaghi

    $Id: eth.c 2657 2010-07-07 07:18:33Z alor $
*/

#include <main.h>
#include <decode.h>
#include <capture.h>

/* globals */

struct eth_header
{
   u_int8   dha[ETH_ADDR_LEN];       /* destination eth addr */
   u_int8   sha[ETH_ADDR_LEN];       /* source ether addr */
   u_int16  proto;                   /* packet type ID field */
};

/* protos */

FUNC_DECODER(decode_eth);
void eth_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init eth_init(void)
{
   add_decoder(LINK_LAYER, IL_TYPE_ETH, decode_eth);
}


FUNC_DECODER(decode_eth)
{
   FUNC_DECODER_PTR(next_decoder);
   struct eth_header *eth;

   DEBUG_MSG(D_EXCESSIVE, "%s", __FUNCTION__);

   DECODED_LEN = sizeof(struct eth_header);

   eth = (struct eth_header *)DECODE_DATA;

   /* fill the packet object with sensitive data */
   PACKET->L2.header = (u_char *)DECODE_DATA;
   PACKET->L2.proto = IL_TYPE_ETH;
   PACKET->L2.len = DECODED_LEN;

   memcpy(PACKET->L2.src, eth->sha, ETH_ADDR_LEN);
   memcpy(PACKET->L2.dst, eth->dha, ETH_ADDR_LEN);

   /* HOOK POINT : HOOK_PACKET_ETH */
   hook_point(HOOK_PACKET_ETH, po);

   /* leave the control to the next decoder */
   next_decoder = get_decoder(NET_LAYER, ntohs(eth->proto));

   EXECUTE_DECODER(next_decoder);

   /* eth header does not care about modification of upper layer */

   return NULL;
}

/* EOF */

// vim:ts=3:expandtab

