
/* $Id: bio_injector.h 2999 2010-10-08 10:23:29Z alor $ */

#ifndef __BIO_INJECTOR_H
#define __BIO_INJECTOR_H

#include <openssl/ssl.h>
#include <openssl/bio.h>

struct bio_inject_setup {
   char *search;
   char *inject;
   size_t inject_len;
};

/* protos */

extern BIO_METHOD* BIO_f_inject(void);

#endif

/* EOF */

// vim:ts=3:expandtab

