/*
    MODULE -- FDDI decoder module

    Copyright (c) Alberto Ornaghi

    $Id: fddi.c 2657 2010-07-07 07:18:33Z alor $
*/

#include <main.h>
#include <decode.h>
#include <capture.h>

/* globals */
struct fddi_header
{
   u_int8  frame_control;
   u_int8  dha[FDDI_ADDR_LEN];
   u_int8  sha[FDDI_ADDR_LEN];
   u_int8  llc_dsap;
   u_int8  llc_ssap;
   u_int8  llc_control;
   u_int8  llc_org_code[3];
   /*
    * ARGH ! org_core is 3 and it has disaligned the struct !
    * we can rely in on the alignment of the buffer...
    */
   u_int16 proto;
};

/* encapsulated ethernet */
u_int8 FDDI_ORG_CODE[3] = {0x00, 0x00, 0x00};

/* protos */

FUNC_DECODER(decode_fddi);
void fddi_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init fddi_init(void)
{
   //add_decoder(LINK_LAYER, IL_TYPE_FDDI, decode_fddi);
}


FUNC_DECODER(decode_fddi)
{
   FUNC_DECODER_PTR(next_decoder);
   struct fddi_header *fddi;

   DEBUG_MSG(D_EXCESSIVE, "%s", __FUNCTION__);

   DECODED_LEN = sizeof(struct fddi_header);

   fddi = (struct fddi_header *)DECODE_DATA;

   /* org_code != encapsulated ethernet not yet supported */
   if (memcmp(fddi->llc_org_code, FDDI_ORG_CODE, 3))
      NOT_IMPLEMENTED();

   /* fill the packet object with sensitive data */
   PACKET->L2.header = (u_char *)DECODE_DATA;
   PACKET->L2.proto = IL_TYPE_FDDI;
   PACKET->L2.len = DECODED_LEN;

   memcpy(PACKET->L2.src, fddi->sha, FDDI_ADDR_LEN);
   memcpy(PACKET->L2.dst, fddi->dha, FDDI_ADDR_LEN);

   /* HOOK POINT : HOOK_PACKET_fddi */
   hook_point(HOOK_PACKET_FDDI, po);

   /* leave the control to the next decoder */
   next_decoder = get_decoder(NET_LAYER, ntohs(fddi->proto));

   EXECUTE_DECODER(next_decoder);

   /* fddi header does not care about modification of upper layer */

   return NULL;
}

/* EOF */

// vim:ts=3:expandtab

