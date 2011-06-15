
/* $Id: match_fqdn.h 1062 2009-10-28 14:32:48Z alor $ */

#ifndef __MATCH_FQDN_H
#define __MATCH_FQDN_H

#include <sys/time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#define ENTRIES 51
#define DISPLACE 45
#define MILLION 1000000
#define ITERATOR 1
#define CYCLES 100

struct dns_header {
	uint16_t id;                /* DNS packet ID */
#ifdef WORDS_BIGENDIAN
	u_char  qr: 1;             /* response flag */
	u_char  opcode: 4;         /* purpose of message */
	u_char  aa: 1;             /* authoritative answer */
	u_char  tc: 1;             /* truncated message */
	u_char  rd: 1;             /* recursion desired */
	u_char  ra: 1;             /* recursion available */
	u_char  unused: 1;         /* unused bits */
	u_char  ad: 1;             /* authentic data from named */
	u_char  cd: 1;             /* checking disabled by resolver */
	u_char  rcode: 4;          /* response code */
#else /* WORDS_LITTLEENDIAN */
	u_char  rd: 1;             /* recursion desired */
	u_char  tc: 1;             /* truncated message */
	u_char  aa: 1;             /* authoritative answer */
	u_char  opcode: 4;         /* purpose of message */
	u_char  qr: 1;             /* response flag */
	u_char  rcode: 4;          /* response code */
	u_char  cd: 1;             /* checking disabled by resolver */
	u_char  ad: 1;             /* authentic data from named */
	u_char  unused: 1;         /* unused bits */
	u_char  ra: 1;             /* recursion available */
#endif
	uint16_t num_q;             /* Number of questions */
	uint16_t num_answer;        /* Number of answer resource records */
	uint16_t num_auth;          /* Number of authority resource records */
	uint16_t num_res;           /* Number of additional resource records */
};


struct trie_node_t {
	char value;
	char type;
	struct trie_node_t* next[ENTRIES];
};

typedef struct trie_node_t tn_t;

#endif
