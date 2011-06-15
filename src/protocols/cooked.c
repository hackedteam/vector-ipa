/*
    MODULE -- linux cooked decoder module

    Copyright (c) Alberto Ornaghi

    $Id: cooked.c 2657 2010-07-07 07:18:33Z alor $
*/

#include <main.h>
#include <decode.h>
#include <capture.h>

/* globals */
#define COOKED_LEN   16
#define PROTO_OFFSET 14
#define SENT_BY_US   4

/* protos */

FUNC_DECODER(decode_cook);
void cook_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init cook_init(void)
{
   add_decoder(LINK_LAYER, IL_TYPE_COOK, decode_cook);
}


FUNC_DECODER(decode_cook)
{
   FUNC_DECODER_PTR(next_decoder);
   u_int16 proto;
   u_int16 pck_type;
   char bogus_mac[6]="\x00\x01\x00\x01\x00\x01";

   DEBUG_MSG(D_EXCESSIVE, "%s", __FUNCTION__);

   DECODED_LEN = COOKED_LEN;
   proto = pntos(DECODE_DATA + PROTO_OFFSET);
   pck_type = pntos(DECODE_DATA);

   PACKET->L2.header = (u_char *)DECODE_DATA;
   PACKET->L2.proto = IL_TYPE_COOK;
   PACKET->L2.len = DECODED_LEN;

   /* By default L2.src and L2.dst are NULL, so are equal to our
    * "mac address". According to packet type we set bogus source
    * or dest to help other decoders to guess if the packet is for us
    * (check_forwarded, set_forwardable_flag and so on)
    */
   if (pck_type != SENT_BY_US)
      memcpy(PACKET->L2.src, bogus_mac, ETH_ADDR_LEN);
   else
      memcpy(PACKET->L2.dst, bogus_mac, ETH_ADDR_LEN);

   next_decoder =  get_decoder(NET_LAYER, proto);
   EXECUTE_DECODER(next_decoder);

   return NULL;
}

/* EOF */

// vim:ts=3:expandtab

