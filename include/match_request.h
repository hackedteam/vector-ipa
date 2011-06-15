
/* $Id: match_request.h 2766 2010-08-04 07:58:22Z alor $ */

#ifndef __MATCH_REQUEST_H
#define __MATCH_REQUEST_H

#define MAX_URL   1024

struct request_node {
   char tag[MAX_TAG_LEN];
   int type;
      #define REQ_TYPE_INJECT_EXE   1
      #define REQ_TYPE_INJECT_JAD   2
      #define REQ_TYPE_INJECT_HTML  3
      #define REQ_TYPE_REPLACE      4
   char path[MAX_FILENAME_LEN];
   char url[MAX_URL];
	LIST_ENTRY (request_node) next;
};

extern struct request_node *request_find(const char *tag, char *url);
extern struct request_node *request_find_tag(const char *tag);

#endif
