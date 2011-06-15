/*
    MODULE -- ERF (endace) decoder module

    Copyright (c) Alberto Ornaghi

    $Id: erf.c 2657 2010-07-07 07:18:33Z alor $
*/

#include <main.h>
#include <decode.h>
#include <capture.h>

/* globals */

struct erf_header
{
   u_int32  timestamp1;
   u_int32  timestamp2;
   u_int8   type;
   u_int8   flags;
   u_int16  rlen;
   u_int16  color;
   u_int16  wlen;
};

/* protos */

FUNC_DECODER(decode_erf);
void erf_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init erf_init(void)
{
   add_decoder(LINK_LAYER, IL_TYPE_ERF, decode_erf);
}


FUNC_DECODER(decode_erf)
{
   FUNC_DECODER_PTR(next_decoder);
   struct erf_header *erf;

   DEBUG_MSG(D_EXCESSIVE, "%s", __FUNCTION__);

   DECODED_LEN = sizeof(struct erf_header);

   erf = (struct erf_header *)DECODE_DATA;

   /* check presence of extension header */
   if (erf->type & 0x80) {
      DEBUG_MSG(D_INFO, "ERF Extension header not supported");
      return NULL;
   }

   /* HOOK POINT : HOOK_PACKET_ERF */
   hook_point(HOOK_PACKET_ERF, po);

   /* ethernet packets */
   if (erf->type == 0x02) {

      /* remove the padding */
      DECODED_LEN += 2;

      /* leave the control to the ethernet decoder */
      next_decoder = get_decoder(LINK_LAYER, IL_TYPE_ETH);

      EXECUTE_DECODER(next_decoder);
   }

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

