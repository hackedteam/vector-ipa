
/* $Id: bio_replacer.h 3000 2010-10-08 11:52:16Z alor $ */

#ifndef __BIO_REPLACER_H
#define __BIO_REPLACER_H

#include <openssl/ssl.h>
#include <openssl/bio.h>

struct bio_replace_setup {
   char *search;
   char *replace;
};

/* protos */

extern BIO_METHOD* BIO_f_replace(void);

#endif

/* EOF */

// vim:ts=3:expandtab

