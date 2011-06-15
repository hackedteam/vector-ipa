/*
    MODULE -- Module for dhcp parsing

    Copyright (C) Alberto Ornaghi

    $Id: dhcp.c 1149 2009-11-17 09:53:46Z alor $
*/

#include <main.h>
#include <inet.h>
#include <dhcp.h>

/* globals */


/* protos */

u_char * dhcp_get_option(u_char opt, u_char *ptr, u_char *end);

/************************************************/

/*
 * return the pointer to the named option
 * or NULL if not found
 * ptr will point to the length of the option
 */
u_char * dhcp_get_option(u_char opt, u_char *ptr, u_char *end)
{
   do {

      /* we have found our option */
      if (*ptr == opt)
         return ptr + 1;

      /*
       * move thru options :
       *
       * OPT LEN .. .. .. OPT LEN .. ..
       */
      ptr = ptr + 2 + (*(ptr + 1));

   } while (*ptr != DHCP_OPT_END && ptr < end);

   return NULL;
}

/* EOF */

// vim:ts=3:expandtab

