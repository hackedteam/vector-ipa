/*
    MODULE -- PPPoE decoder module

    Copyright (c) Alberto Ornaghi

    $Id: pppoe.c 2657 2010-07-07 07:18:33Z alor $
*/

#include <main.h>
#include <decode.h>
#include <capture.h>

/* globals */

struct pppoe_header
{
   u_int8   version;
   u_int8   session;
   u_int16  id;
   u_int16  len;
   u_int16  proto;      /* this is actually part of the PPP header */
};

/* protos */

FUNC_DECODER(decode_pppoe);
void pppoe_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init pppoe_init(void)
{
   add_decoder(NET_LAYER, LL_TYPE_PPPOE, decode_pppoe);
}


FUNC_DECODER(decode_pppoe)
{
   FUNC_DECODER_PTR(next_decoder);
   struct pppoe_header *pppoe;

   DEBUG_MSG(D_EXCESSIVE, "%s", __FUNCTION__);

   DECODED_LEN = sizeof(struct pppoe_header);

   pppoe = (struct pppoe_header *)DECODE_DATA;

   /* HOOK POINT : HOOK_PACKET_pppoe */
   hook_point(HOOK_PACKET_PPPOE, po);

   /* leave the control to the next decoder */
   next_decoder = get_decoder(NET_LAYER, ntohs(pppoe->proto));

   EXECUTE_DECODER(next_decoder);

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

