
/* $Id: match_url.h 3041 2010-10-26 10:11:18Z daniele $ */

#ifndef __MATCH_URL_H
#define __MATCH_URL_H

#include <sys/time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#define MAX_URL	1024

#define SPLASH_PAGE_LEN 1200

struct url_node {
   int probability;
   int first_match;
   char tag[MAX_TAG_LEN];
	char url[MAX_URL];
	LIST_ENTRY (url_node) next;
};

#endif
