/*
    MODULE -- Module to match an user based on radius packets

    Copyright (C) Alberto Ornaghi

    $Id: match_users_dhcp.c 2653 2010-07-06 07:31:19Z alor $
*/

#include <main.h>
#include <hook.h>
#include <packet.h>

#include <match.h>
#include <match_users.h>
#include <dhcp.h>

/* global vars */

struct dhcp_node {
   char tag[MAX_TAG_LEN];
   char mac[ETH_ASCII_ADDR_LEN];
   LIST_ENTRY (dhcp_node) next;
};

static LIST_HEAD(, dhcp_node) dhcp_root;
static pthread_mutex_t dhcp_mutex = PTHREAD_MUTEX_INITIALIZER;

/* proto */

void match_user_dhcp_add(char *value, char *tag);
void match_user_dhcp_clear(void);
struct dhcp_node * find_dhcp_user(char *mac);
void dissector_dhcp(struct packet_object *po);

/*******************************************/

void match_user_dhcp_add(char *value, char *tag)
{
   struct dhcp_node *e;

   /*
    * remove the hook. we must do this because we are called on every reload list.
    * otherwise the hook will be setup multiple time
    */
   hook_del(HOOK_PACKET_UDP, dissector_dhcp);

   /* add the hook on UDP packet, this will pass us all the DHCP packets to look into */
   hook_add(HOOK_PACKET_UDP, dissector_dhcp);

   /* create the element for the list */
   SAFE_CALLOC(e, 1, sizeof(struct dhcp_node));

   snprintf(e->tag, MAX_TAG_LEN-1, "%s", tag);
   snprintf(e->mac, ETH_ASCII_ADDR_LEN-1, "%s", value);

   pthread_mutex_lock(&dhcp_mutex);
   LIST_INSERT_HEAD(&dhcp_root, e, next);
   pthread_mutex_unlock(&dhcp_mutex);
}


void match_user_dhcp_clear(void)
{
   struct dhcp_node *e, *tmp;

   pthread_mutex_lock(&dhcp_mutex);

   /* remove all the elements */
   LIST_FOREACH_SAFE(e, &dhcp_root, next, tmp) {
      LIST_REMOVE(e, next);
      SAFE_FREE(e);
   }

   pthread_mutex_unlock(&dhcp_mutex);
}


struct dhcp_node * find_dhcp_user(char *mac)
{
   struct dhcp_node *e;

   pthread_mutex_lock(&dhcp_mutex);

   /* search into the list */
   LIST_FOREACH(e, &dhcp_root, next) {
      if (match_pattern(mac, e->mac)) {
         pthread_mutex_unlock(&dhcp_mutex);
         return e;
      }
   }

   pthread_mutex_unlock(&dhcp_mutex);

   return NULL;
}


void dissector_dhcp(struct packet_object *po)
{
   struct dhcp_header *dhcp;
   struct ip_addr ip;
   struct dhcp_node *e;
   struct timeval tv;
   u_char *data = po->DATA.data;
   u_char *end = po->DATA.data + po->DATA.len;
   u_char *options, *opt;
   char tmp[MAX_ASCII_ADDR_LEN];
   char mac[ETH_ASCII_ADDR_LEN];

   /* packet is not dhcp */
   if (ntohs(po->L4.dst) != 68)
      return;

   /* sanity check */
   if (po->DATA.len < sizeof(struct dhcp_header))
      return;

   DEBUG_MSG(D_VERBOSE, "dissector_dhcp");

   /* cast the header and options */
   dhcp = (struct dhcp_header *)data;
   options = (u_char *)(dhcp + 1);

   /* check for the magic cookie */
   if (dhcp->magic != htonl(DHCP_MAGIC_COOKIE))
      return;

   /* servers only send replies */
   if (dhcp->op != BOOTREPLY)
      return;

   /* search the "message type" option */
   if ((opt = dhcp_get_option(DHCP_OPT_MSG_TYPE, options, end)) == NULL)
      return;

   /*
    * we are interested only in DHCP ACK replies from the server.
    * we take this and parse the address release to the client
    */
   if (*(opt + 1) != DHCP_ACK)
      return;

   /* get the client mac address */
   mac_addr_ntoa(dhcp->chaddr, mac);

   DEBUG_MSG(D_EXCESSIVE, "DHCP mac: [%s]", mac);

   /* search if the mac address belongs to our targets */
   if ((e = find_dhcp_user(mac)) == NULL)
      return;

   /* get the assigned ip */
   ip_addr_init(&ip, AF_INET, (u_char *)&dhcp->yiaddr);

   DEBUG_MSG(D_INFO, "DHCP TARGET DISCOVERED [%s] [%s] [%s]", e->tag, mac, ip_addr_ntoa(&ip, tmp));

   gettimeofday(&tv, NULL);
   active_user_add(&ip, NULL, e->tag, tv);
}

/* EOF */

// vim:ts=3:expandtab

