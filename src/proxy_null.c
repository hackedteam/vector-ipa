/*
    MODULE -- proxy module (the actual injector)

    Copyright (C) Alberto Ornaghi

    $Id: proxy_null.c 3000 2010-10-08 11:52:16Z alor $
*/

#include <main.h>
#include <proxy.h>
#include <threads.h>
#include <file.h>
#include <match.h>
#include <match_request.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <signal.h>

/* globals */

/* protos */

int proxy_null(BIO **cbio, BIO **sbio, char *header);

/************************************************/

int proxy_null(BIO **cbio, BIO **sbio, char *header)
{
   char data[READ_BUFF_SIZE];
   int len, written;
   char *host, *p;

   /* retrieve the host tag */
   host = strcasestr(header, HTTP_HOST_TAG);

   if (host == NULL)
      return -EINVALID;

   SAFE_STRDUP(host, host + strlen(HTTP_HOST_TAG));

   /* trim the eol */
   if ((p = strchr(host, '\r')) != NULL)
      *p = 0;
   if ((p = strchr(host, '\n')) != NULL)
      *p = 0;

   /* connect to the real server */
   *sbio = BIO_new(BIO_s_connect());
   BIO_set_conn_hostname(*sbio, host);
   BIO_set_conn_port(*sbio, "http");

   if (BIO_do_connect(*sbio) <= 0) {
      DEBUG_MSG(D_ERROR, "Cannot connect to [%s]", host);
      SAFE_FREE(host);
      return -ENOADDRESS;
   }

   DEBUG_MSG(D_INFO, "Connection to [%s]", host);

   /*
    * sanitize the header to avoid strange reply from the server.
    * we don't want to cope with keep-alive !!!
    */
   sanitize_header(header);

   /* send the request to the server */
   BIO_puts(*sbio, header);

   memset(data, 0, sizeof(data));
   written = 0;

   /* read the reply header from the server */
   LOOP {
      len = BIO_read(*sbio, data + written, sizeof(char));
      if (len <= 0)
         break;

      written += len;
      if (strstr(data, CR LF CR LF) || strstr(data, LF LF))
         break;
   }

   /* send the headers to the client, the data will be sent in the callee function */
   BIO_write(*cbio, data, written);

   SAFE_FREE(host);

   return ESUCCESS;
}


/* EOF */

// vim:ts=3:expandtab

