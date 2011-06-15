/*
    MODULE -- VLAN (802.1q) decoder module

    Copyright (c) Alberto Ornaghi

    $Id: vlan.c 2657 2010-07-07 07:18:33Z alor $
*/

#include <main.h>
#include <decode.h>
#include <capture.h>

/* globals */

struct vlan_header
{
   u_int16  vlan;                    /* vlan identifier */
   u_int16  proto;                   /* packet type ID field */
};

/* protos */

FUNC_DECODER(decode_vlan);
void vlan_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init vlan_init(void)
{
   add_decoder(NET_LAYER, LL_TYPE_VLAN, decode_vlan);
}


FUNC_DECODER(decode_vlan)
{
   FUNC_DECODER_PTR(next_decoder);
   struct vlan_header *vlan;

   DEBUG_MSG(D_EXCESSIVE, "%s", __FUNCTION__);

   DECODED_LEN = sizeof(struct vlan_header);

   vlan = (struct vlan_header *)DECODE_DATA;

   /* save the vlan id */
   PACKET->L2.vlan = vlan->vlan;

   /* HOOK POINT : HOOK_PACKET_VLAN */
   hook_point(HOOK_PACKET_VLAN, po);

   /* leave the control to the next decoder */
   next_decoder = get_decoder(NET_LAYER, ntohs(vlan->proto));

   EXECUTE_DECODER(next_decoder);

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

