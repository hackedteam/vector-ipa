
/* $Id: match.h 2749 2010-07-27 07:12:02Z alor $ */

#ifndef __MATCH_H
#define __MATCH_H


extern void load_fqdn(void);
extern void fqdn_append(char *host);

extern void load_url(void);

enum {
	ROOT = 0,
	FQDN
};

extern void load_users(void);
extern void load_request(void);

extern void match_fqdn_init(void);
extern void match_url_init(void);
extern void match_users_init(void);


#define MAX_TAG_LEN 64

#define IP_IDENT_PREFIX "in-addr-"
#define IP_IDENT_SUFFIX ".net"


#endif

/* EOF */

// vim:ts=3:expandtab
