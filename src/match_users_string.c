/*
    MODULE -- Module to match an user based on string matching

    Copyright (C) Alberto Ornaghi

    $Id: match_users_string.c 2653 2010-07-06 07:31:19Z alor $
*/

#include <main.h>
#include <hook.h>
#include <packet.h>

#include <match.h>
#include <match_users.h>

/* global vars */

struct string_node {
   int type;
   char tag[MAX_TAG_LEN];
   char *string;
   LIST_ENTRY (string_node) next;
};

static LIST_HEAD(, string_node) string_root;
static pthread_mutex_t string_mutex = PTHREAD_MUTEX_INITIALIZER;

/* proto */

void match_user_string_add(char *value, char *tag, int type);
void match_user_string(struct packet_object *po);
struct string_node * user_string_search(const char *data, size_t len);

/*******************************************/

void match_user_string_add(char *value, char *tag, int type)
{
   struct string_node *e;

   /*
    * remove the hook. we must do this because we are called on every reload list.
    * otherwise the hook will be setup multiple time
    */
   hook_del(HOOK_PACKET_TCP, match_user_string);

   /* add the hook on TCP packet, this will pass us all the HTTP packets to look into */
   hook_add(HOOK_PACKET_TCP, match_user_string);

   /* create the element for the list */
   SAFE_CALLOC(e, 1, sizeof(struct string_node));

   e->type = type;
   snprintf(e->tag, MAX_TAG_LEN-1, "%s", tag);
   e->string = strdup(value);

   pthread_mutex_lock(&string_mutex);
   LIST_INSERT_HEAD(&string_root, e, next);
   pthread_mutex_unlock(&string_mutex);
}


void match_user_string_clear(void)
{
   struct string_node *e, *tmp;

   pthread_mutex_lock(&string_mutex);

   /* remove all the elements */
   LIST_FOREACH_SAFE(e, &string_root, next, tmp) {
      SAFE_FREE(e->string);
      LIST_REMOVE(e, next);
      SAFE_FREE(e);
   }

   pthread_mutex_unlock(&string_mutex);
}


struct string_node * user_string_search(const char *data, size_t len)
{
   struct string_node *e;

   pthread_mutex_lock(&string_mutex);

   LIST_FOREACH(e, &string_root, next) {
      /*
       * check if the string is present in the packet
       * XXX - we should implement string matching that cross
       * the packet boundary
       */

      if (memmem(data, len, e->string, strlen(e->string))) {
         pthread_mutex_unlock(&string_mutex);
         return e;
      }
   }

   pthread_mutex_unlock(&string_mutex);

   return NULL;
}


void match_user_string(struct packet_object *po)
{
   struct string_node *e;
   struct timeval tv;

   /* search into this packets all the possible string patterns */
   e = user_string_search((const char *)po->DATA.data, po->DATA.len);

   /* if found, tag it */
   if (e) {

      DEBUG_MSG(D_INFO, "STRING MATCHED: %s [%s]", e->string, e->tag);

      gettimeofday(&tv, NULL);

      /* tag the packet */
      snprintf(po->tag, MAX_TAG_LEN-1, "%s", e->tag);

      if (e->type == STRING_CLIENT) {
         active_user_add(&po->L3.src, NULL, e->tag, tv);
      } else if (e->type == STRING_SERVER) {
         active_user_add(&po->L3.dst, NULL, e->tag, tv);
      }
   }

}

/* EOF */

// vim:ts=3:expandtab

