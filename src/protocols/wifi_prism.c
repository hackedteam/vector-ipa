/*
    MODULE -- Prism2 header for WiFi packets

    Copyright (c) Alberto Ornaghi

    $Id: wifi_prism.c 2667 2010-07-12 11:47:31Z alor $
*/

#include <main.h>
#include <decode.h>
#include <capture.h>

/* protos */

FUNC_DECODER(decode_prism);
void prism_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init prism_init(void)
{
   add_decoder(LINK_LAYER, IL_TYPE_PRISM, decode_prism);
}


FUNC_DECODER(decode_prism)
{
   FUNC_DECODER_PTR(next_decoder);

   DEBUG_MSG(D_EXCESSIVE, "%s", __FUNCTION__);

   /* Simply skip the first 0x90 Bytes (the Prism2 header) and pass
    * the whole packet on to the wifi layer */
   DECODED_LEN = 0x90;

   next_decoder = get_decoder(LINK_LAYER, IL_TYPE_WIFI);
   EXECUTE_DECODER(next_decoder);

   return NULL;
}

/* EOF */

// vim:ts=3:expandtab

