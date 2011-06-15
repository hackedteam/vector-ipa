/*
    MODULE -- MPLS decoder module

    Copyright (c) Alberto Ornaghi

    $Id: mpls.c 2657 2010-07-07 07:18:33Z alor $
*/

#include <main.h>
#include <decode.h>
#include <capture.h>

/* globals */

struct mpls_header
{
   u_int32  mpls;                    /* mpls header */
};

/* protos */

FUNC_DECODER(decode_mpls);
void mpls_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init mpls_init(void)
{
   add_decoder(NET_LAYER, LL_TYPE_MPLS, decode_mpls);
}


FUNC_DECODER(decode_mpls)
{
   FUNC_DECODER_PTR(next_decoder);
   struct mpls_header *mpls;

   DEBUG_MSG(D_EXCESSIVE, "%s", __FUNCTION__);

   DECODED_LEN = sizeof(struct mpls_header);

   mpls = (struct mpls_header *)DECODE_DATA;

   /* HOOK POINT : HOOK_PACKET_mpls */
   hook_point(HOOK_PACKET_MPLS, po);

   /* leave the control to the next decoder */
   next_decoder = get_decoder(NET_LAYER, LL_TYPE_IP);

   EXECUTE_DECODER(next_decoder);

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

