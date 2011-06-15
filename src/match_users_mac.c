/*
    MODULE -- Module to match an user based on static mac address

    Copyright (C) Alberto Ornaghi

    $Id: match_users_mac.c 2674 2010-07-13 10:03:12Z alor $
*/

#include <main.h>
#include <hook.h>
#include <packet.h>

#include <match.h>
#include <match_users.h>

/* global vars */


/* proto */

void match_user_mac_add(char *value, char *tag);

/*******************************************/

void match_user_mac_add(char *value, char *tag)
{
   u_char mac[MEDIA_ADDR_LEN];

   /* transform the target string into mac struct */
   if (mac_addr_aton(value, mac) == 0) {
      DEBUG_MSG(D_ERROR, "Invalid STATIC-MAC %s in %s", value, GBL_CONF->redirected_users);
   } else {
      struct timeval tv;

      /* null end_time means there is no timeout */
      memset(&tv, 0, sizeof(struct timeval));

      /*
       * static-mac users are ALWAYS considered active.
       * that's all.
       * the hook to the LINK level will trigger the tagging
       */
      active_user_add(NULL, mac, tag, tv);
   }
}

/* EOF */

// vim:ts=3:expandtab

