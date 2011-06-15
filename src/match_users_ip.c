/*
    MODULE -- Module to match an user based on static ip

    Copyright (C) Alberto Ornaghi

    $Id: match_users_ip.c 2661 2010-07-09 08:33:01Z alor $
*/

#include <main.h>
#include <hook.h>
#include <packet.h>

#include <match.h>
#include <match_users.h>

/* global vars */


/* proto */

void match_user_ip_add(char *value, char *tag);

/*******************************************/

void match_user_ip_add(char *value, char *tag)
{
   struct in_addr ip;

   /* transform the target string into ip_addr struct */
   if (inet_pton(AF_INET, value, &ip) <= 0) {
      DEBUG_MSG(D_ERROR, "Invalid STATIC-IP %s in %s", value, GBL_CONF->redirected_users);
   } else {
      struct ip_addr uip;
      struct timeval tv;

      /* fill the values */
      ip_addr_init(&uip, AF_INET, (u_char *)&ip);

      /* null end_time means there is no timeout */
      memset(&tv, 0, sizeof(struct timeval));

      /*
       * static-ip users are ALWAYS considered active.
       * that's all.
       * the hook to the IP level will trigger the tagging
       */
      active_user_add(&uip, NULL, tag, tv);
   }
}

/* EOF */

// vim:ts=3:expandtab

