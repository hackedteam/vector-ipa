/*
    MODULE -- TOKEN RING decoder module

    Copyright (c) Alberto Ornaghi

    $Id: tr.c 2657 2010-07-07 07:18:33Z alor $
*/

#include <main.h>
#include <decode.h>
#include <capture.h>

/* globals */
struct token_ring_header
{
   u_int8  access_control;
      #define TR_FRAME  0x10
   u_int8  frame_control;
      #define TR_LLC_FRAME  0x40
   u_int8  dha[TR_ADDR_LEN];
   u_int8  sha[TR_ADDR_LEN];
   u_int8  llc_dsap;
   u_int8  llc_ssap;
   u_int8  llc_control;
   u_int8  llc_org_code[3];
   u_int16 proto;
};

/* encapsulated ethernet */
u_int8 TR_ORG_CODE[3] = {0x00, 0x00, 0x00};

/* protos */

FUNC_DECODER(decode_tr);
void tr_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init tr_init(void)
{
   //add_decoder(LINK_LAYER, IL_TYPE_TR, decode_tr);
}


FUNC_DECODER(decode_tr)
{
   FUNC_DECODER_PTR(next_decoder);
   struct token_ring_header *tr;

   DEBUG_MSG(D_EXCESSIVE, "%s", __FUNCTION__);

   DECODED_LEN = sizeof(struct token_ring_header);

   tr = (struct token_ring_header *)DECODE_DATA;

   /* org_code != encapsulated ethernet not yet supported */
   if (memcmp(tr->llc_org_code, TR_ORG_CODE, 3))
      NOT_IMPLEMENTED();

   /* fill the packet object with sensitive data */
   PACKET->L2.header = (u_char *)DECODE_DATA;
   PACKET->L2.proto = IL_TYPE_TR;
   PACKET->L2.len = DECODED_LEN;

   memcpy(PACKET->L2.src, tr->sha, TR_ADDR_LEN);
   memcpy(PACKET->L2.dst, tr->dha, TR_ADDR_LEN);

   /* HOOK POINT : HOOK_PACKET_tr */
   hook_point(HOOK_PACKET_TR, po);

   /* leave the control to the next decoder */
   next_decoder = get_decoder(NET_LAYER, ntohs(tr->proto));

   EXECUTE_DECODER(next_decoder);

   /* token ring header does not care about modification of upper layer */

   return NULL;
}

/* EOF */

// vim:ts=3:expandtab

