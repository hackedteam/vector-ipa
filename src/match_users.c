/*
    MODULE -- Module to match an user

    Copyright (C) Alberto Ornaghi

    $Id: match_users.c 2910 2010-09-23 09:40:28Z alor $
*/

#include <main.h>
#include <hook.h>
#include <file.h>
#include <packet.h>
#include <threads.h>
#include <timer.h>

#include <match.h>
#include <match_users.h>

/* global vars */

static LIST_HEAD(, user_node) users_root;
static pthread_mutex_t root_mutex = PTHREAD_MUTEX_INITIALIZER;

/* proto */

void load_users(void);
int userslist_load(void);
void match_users_init(void);
void match_user_ip(struct packet_object *po);
void match_user_mac(struct packet_object *po);
void active_user_add(struct ip_addr *ip, u_char *mac, char *tag, struct timeval time);
void active_user_del(struct ip_addr *ip);
static void active_user_timeout(void);
void active_user_purge(void);

/*******************************************/

void active_user_add(struct ip_addr *ip, u_char *mac, char *tag, struct timeval time)
{
   struct user_node *e, *s;
   char tmp[MAX_ASCII_ADDR_LEN];

   /* alloc the new element */
   SAFE_CALLOC(e, 1, sizeof(struct user_node));

   if (ip)
      memcpy(&e->ip, ip, sizeof(struct ip_addr));

   if (mac)
      memcpy(&e->mac, mac, MEDIA_ADDR_LEN);

   if (tag)
      snprintf(e->tag, MAX_TAG_LEN-1, "%s", tag);

   /* the timeout */
   e->end_time = time;
   /* add the timeout only if it was not explicitly set to zero */
   if (e->end_time.tv_sec != 0)
      e->end_time.tv_sec += GBL_TARGETS->user_timeout;

   /* insert it in the list */
   pthread_mutex_lock(&root_mutex);

   /* check if the ip address and the mac address was already associated with a tag */
   LIST_FOREACH(s, &users_root, next) {
      if (!memcmp(&e->ip, &s->ip, sizeof(struct ip_addr)) && !memcmp(&e->mac, &s->mac, MEDIA_ADDR_LEN)) {
         pthread_mutex_unlock(&root_mutex);
         /* already present in the list */
         return;
      }
   }

   LIST_INSERT_HEAD(&users_root, e, next);
   GBL_STATS->active_users++;
   pthread_mutex_unlock(&root_mutex);

   if (ip)
      DEBUG_MSG(D_INFO, "User [%s] identified on [%s]", e->tag, ip_addr_ntoa(&e->ip, tmp));

   if (mac)
      DEBUG_MSG(D_INFO, "User [%s] identified on [%s]", e->tag, mac_addr_ntoa(e->mac, tmp));
}


void active_user_del(struct ip_addr *ip)
{
   struct user_node *e, *tmp;
   char tip[MAX_ASCII_ADDR_LEN];

   pthread_mutex_lock(&root_mutex);
   LIST_FOREACH_SAFE(e, &users_root, next, tmp) {
      if (!ip_addr_cmp(&e->ip, ip)) {
         LIST_REMOVE(e, next);
         DEBUG_MSG(D_INFO, "User [%s][%s] removed from active users", e->tag, ip_addr_ntoa(&e->ip, tip));
         SAFE_FREE(e);
         GBL_STATS->active_users--;
      }
   }
   pthread_mutex_unlock(&root_mutex);
}


static void active_user_timeout(void)
{
   struct user_node *e, *tmp;
   struct timeval tv;
   char ip[MAX_ASCII_ADDR_LEN];

   gettimeofday(&tv, NULL);

   /* walk the list searching for timeouted elements */
   pthread_mutex_lock(&root_mutex);
   LIST_FOREACH_SAFE(e, &users_root, next, tmp) {

      /* no timeout if the value is ZERO */
      if (e->end_time.tv_sec == 0)
         continue;

      /* remove the timeouted element */
      if (tv.tv_sec > e->end_time.tv_sec) {
         LIST_REMOVE(e, next);
         DEBUG_MSG(D_INFO, "%s removed from active users (timeouted)", ip_addr_ntoa(&e->ip, ip));
         SAFE_FREE(e);
         GBL_STATS->active_users--;
      }
   }
   pthread_mutex_unlock(&root_mutex);

}


void active_user_purge(void)
{
   struct user_node *e, *tmp;
   char ip[MAX_ASCII_ADDR_LEN];

   DEBUG_MSG(D_INFO, "active_user_purge: deleting all active users");

   pthread_mutex_lock(&root_mutex);
   LIST_FOREACH_SAFE(e, &users_root, next, tmp) {
      LIST_REMOVE(e, next);
      DEBUG_MSG(D_INFO, "%s removed from active users (purged)", ip_addr_ntoa(&e->ip, ip));
      SAFE_FREE(e);
   }

   GBL_STATS->active_users = 0;
   pthread_mutex_unlock(&root_mutex);
}


int userslist_load(void)
{
   FILE *fc;
   char line[512];
   int counter = 0;
   char *p, *q;
   char *type, *value, *tag;

   DEBUG_MSG(D_INFO, "load_users: %s", GBL_CONF->redirected_users);

   ON_ERROR(GBL_CONF->redirected_users, NULL, "Cannot open a NULL file!");

   /* errors are handled by the function */
   fc = open_data("etc", GBL_CONF->redirected_users, FOPEN_READ_TEXT);
   ON_ERROR(fc, NULL, "Cannot open %s", GBL_CONF->redirected_users);

   /* read the file */
   while (fgets(line, 512, fc) != 0) {

      /* trim out the comments */
      if ((p = strchr(line, '#')))
         *p = '\0';

      /* trim out the new line */
      if ((p = strchr(line, '\n')))
         *p = '\0';

      if ((p = strchr(line, '\r')))
         *p = '\0';

      q = line;

      /* trim the initial spaces */
      while (q < line + sizeof(line) && *q == ' ')
         q++;

      /* skip empty lines */
      if (line[0] == '\0' || *q == '\0')
         continue;

      type = line;

      /* null terminate at the space */
      if ((p = strchr(type, ' ')))
         *p = '\0';

      value = p + 1;

      /* null terminate at the space */
      if ((p = strchr(value, ' ')))
    	  *p = '\0';

      tag = p + 1;

      /* check the user's type */
      if (!strncmp(type, "STATIC-IP", strlen("STATIC-IP"))) {
         /* pass the target to the parsing module */
         match_user_ip_add(value, tag);
      } else if (!strncmp(type, "STATIC-MAC", strlen("STATIC-MAC"))) {
         /* pass the target to the parsing module */
         match_user_mac_add(value, tag);
      } else if (!strncmp(type, "RADIUS-LOGIN", strlen("RADIUS-LOGIN"))) {
         /* pass the target to the parsing module */
         match_user_radius_add(value, tag, RADIUS_LOGIN);
      } else if (!strncmp(type, "RADIUS-CALLID", strlen("RADIUS-CALLID"))) {
         /* pass the target to the parsing module */
         match_user_radius_add(value, tag, RADIUS_CALLID);
      } else if (!strncmp(type, "RADIUS-TECHKEY", strlen("RADIUS-TECHKEY"))) {
         /* pass the target to the parsing module */
         match_user_radius_add(value, tag, RADIUS_TECHKEY);
      } else if (!strncmp(type, "RADIUS-SESSID", strlen("RADIUS-SESSID"))) {
         /* pass the target to the parsing module */
         match_user_radius_add(value, tag, RADIUS_SESSID);
      } else if (!strncmp(type, "STRING-CLIENT", strlen("STRING-CLIENT"))) {
         /* pass the target to the parsing module */
         match_user_string_add(value, tag, STRING_CLIENT);
      } else if (!strncmp(type, "STRING-SERVER", strlen("STRING-SERVER"))) {
         /* pass the target to the parsing module */
         match_user_string_add(value, tag, STRING_SERVER);
      } else if (!strncmp(type, "DHCP", strlen("DHCP"))) {
         /* pass the target to the parsing module */
         match_user_dhcp_add(value, tag);
      } else {
         DEBUG_MSG(D_ERROR, "ERROR: Invalid entry [%s][%s][%s]", type, value, tag);
         continue;
      }

      /* update the line count */
      counter++;
   }

   fclose(fc);

   DEBUG_MSG(D_INFO, "List of redirected USERS contains : %04d entries.", counter);

   GBL_STATS->tot_users = counter;

   return 0;
}

void load_users(void)
{
   struct user_node *current, *tmp;

   pthread_mutex_lock(&root_mutex);

   /* free the old list */
   LIST_FOREACH_SAFE(current, &users_root, next, tmp) {
      LIST_REMOVE(current, next);
      SAFE_FREE(current);
   }

   pthread_mutex_unlock(&root_mutex);

   /* purge the old active users */
   active_user_purge();

   /* purge the internal matching lists */
   match_user_string_clear();
   match_user_radius_clear();
   match_user_dhcp_clear();

   /* load the new URL list */
   userslist_load();

   return;
}

void match_user_ip(struct packet_object *po)
{
   struct user_node *current;
   struct timeval tv;

   pthread_mutex_lock(&root_mutex);

   /* search the target in the list */
   LIST_FOREACH(current, &users_root, next) {
      if (!ip_addr_cmp(&po->L3.src, &current->ip) || !ip_addr_cmp(&po->L3.dst, &current->ip)) {

         /* tag the packet */
         snprintf(po->tag, MAX_TAG_LEN-1, "%s", current->tag);

         /*
          * add the timeout to every packet so if no packets are seen before the timeout
          * the entry will be removed by the timeouter
          */
         gettimeofday(&tv, NULL);

         if (current->end_time.tv_sec != 0)
            current->end_time.tv_sec = tv.tv_sec + GBL_TARGETS->user_timeout;

         DEBUG_MSG(D_EXCESSIVE, "IP packet tagged with [%s] timeout [%d]", current->tag, current->end_time.tv_sec);

         pthread_mutex_unlock(&root_mutex);
         return;
      }
   }

   pthread_mutex_unlock(&root_mutex);
}


void match_user_mac(struct packet_object *po)
{
   struct user_node *current;
   struct timeval tv;
   u_char zero_mac[MEDIA_ADDR_LEN];

   memset(zero_mac, 0, MEDIA_ADDR_LEN);

   pthread_mutex_lock(&root_mutex);

   /* search the target in the list */
   LIST_FOREACH(current, &users_root, next) {

      /* don't check not initialized targets */
      if (!memcmp(current->mac, zero_mac, MEDIA_ADDR_LEN))
         continue;

      if (!memcmp(&po->L2.src, &current->mac, MEDIA_ADDR_LEN) || !memcmp(&po->L2.dst, &current->mac, MEDIA_ADDR_LEN)) {

         /* tag the packet */
         snprintf(po->tag, MAX_TAG_LEN-1, "%s", current->tag);

         /*
          * add the timeout to every packet so if no packets are seen before the timeout
          * the entry will be removed by the timeouter
          */
         gettimeofday(&tv, NULL);

         if (current->end_time.tv_sec != 0)
            current->end_time.tv_sec = tv.tv_sec + GBL_TARGETS->user_timeout;

         DEBUG_MSG(D_EXCESSIVE, "LINK LAYER packet tagged with [%s] timeout [%d]", current->tag, current->end_time.tv_sec);

         pthread_mutex_unlock(&root_mutex);
         return;
      }
   }

   pthread_mutex_unlock(&root_mutex);
}

void match_users_init(void)
{
   struct timer_hook th;

   DEBUG_MSG(D_INFO, "match_users_init");

   /* set up the hook to receive the IP packets */
   hook_add(HOOK_PACKET_IP, &match_user_ip);

   /* set up the hook to receive the LINK LAYER packets */
   hook_add(HOOK_PACKET_ETH, &match_user_mac);
   hook_add(HOOK_PACKET_WIFI, &match_user_mac);

   /* every 10 seconds check if we have to timeout something */
   th.sec = 10;
   th.func = &active_user_timeout;
   add_timer(&th);
}

/* EOF */

// vim:ts=3:expandtab

