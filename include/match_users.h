
/* $Id: match_users.h 2653 2010-07-06 07:31:19Z alor $ */

#ifndef __MATCH_USERS_H
#define __MATCH_USERS_H

#include <sys/time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inet.h>

/*
 * this is the list of active users associated with their ip addresses
 * it contains the static-ip match and the dynamically discovered users
 */
struct user_node {
   u_char mac[MEDIA_ADDR_LEN];
	struct ip_addr ip;
	char tag[MAX_TAG_LEN];
	struct timeval end_time;
	LIST_ENTRY (user_node) next;
};

extern void active_user_add(struct ip_addr *ip, u_char *mac, char *tag, struct timeval time);
extern void active_user_del(struct ip_addr *ip);

extern void match_user_ip_add(char *value, char *tag);

extern void match_user_mac_add(char *value, char *tag);

extern void match_user_string_add(char *value, char *tag, int type);
   #define STRING_CLIENT 0
   #define STRING_SERVER 1
extern void match_user_string_clear(void);

extern void match_user_radius_add(char *value, char *tag, int type);
   #define RADIUS_LOGIN   0
   #define RADIUS_CALLID  1
   #define RADIUS_TECHKEY 2
   #define RADIUS_SESSID  3
extern void match_user_radius_clear(void);

extern void match_user_dhcp_add(char *value, char *tag);
extern void match_user_dhcp_clear(void);

#endif
