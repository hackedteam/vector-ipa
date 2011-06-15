/*
 MODULE -- BIO replacer module (replace data into search pattern)

 Copyright (C) Alberto Ornaghi

 $Id: bio_replacer.c 3033 2010-10-25 13:49:37Z alor $
 */

#include <main.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include <bio_replacer.h>

/* globals */

#define BIO_TYPE_REPLACE_FILTER (97|0x200)

struct replacer_obj {
   /* internal buffer */
   char *buf;
   int bsize;
   int curr;
   /* repalce part */
   char *search;
   char *replace;
   int rsize;
   int diff_size;
};

/* protos */

void *replacer_new(void);
void replacer_free(void *);
int replacer_feed(void *, const char *, int);
int replacer_eat(void *, char **, int *);

static int replace_write(BIO *h, const char *buf, int num);
static int replace_read(BIO *h, char *buf, int size);
static int replace_puts(BIO *h, const char *str);
static int replace_gets(BIO *h, char *str, int size);
static long replace_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int replace_new(BIO *h);
static int replace_free(BIO *data);
static long replace_callback_ctrl(BIO *h, int cmd, bio_info_cb *fp);

BIO_METHOD* BIO_f_replace(void);

BIO_METHOD method_replace = { BIO_TYPE_REPLACE_FILTER, "RCS Replace filter",
      replace_write, replace_read, replace_puts, replace_gets, replace_ctrl,
      replace_new, replace_free, replace_callback_ctrl, };
/************************************************/

void *replacer_new(void) {
   struct replacer_obj *rep;

   SAFE_CALLOC(rep, sizeof(struct replacer_obj), 1);

   return rep;
}

void replacer_free(void *self) {
   struct replacer_obj *rep = (struct replacer_obj *) self;

   /* sanity check */
   if (self == NULL)
      return;

   SAFE_FREE(rep->search);
   SAFE_FREE(rep->replace);
   SAFE_FREE(rep->buf);
   SAFE_FREE(self);
}

int replacer_feed(void *self, const char *in, int inl) {
   struct replacer_obj *rep = (struct replacer_obj *) self;

   /* sanity check */
   if (self == NULL)
      return 0;

   /* append the data to the buffer */
   SAFE_REALLOC(rep->buf, rep->bsize + inl + sizeof(char));
   memcpy(rep->buf + rep->bsize, in, inl);
   rep->bsize += inl;
   /* null terminate */
   memset(rep->buf + rep->bsize, '\0', sizeof(char));

   /* sanity check */
   if (rep->search == NULL || rep->replace == NULL) {
      DEBUG_MSG(D_ERROR, "replacer_feed: cannot search for NULL");
      return rep->bsize;
   }

   /* replace the 'search' string with the 'replace' one */
   str_replace(&rep->buf, rep->search, rep->replace);

   /* calculate the new size */
   rep->bsize = strlen(rep->buf);

   return rep->bsize;
}

int replacer_eat(void *self, char **out, int *outl) {
   struct replacer_obj *rep = (struct replacer_obj *) self;

   /* sanity check */
   if (self == NULL)
      return 0;

   /* pass the pointer and size to the caller */
   *out = rep->buf + rep->curr;
   *outl = rep->bsize - rep->curr;

   /* update the current internal pointer */
   rep->curr = rep->bsize;

   return *outl;
}

BIO_METHOD* BIO_f_replace(void) {
   return (&method_replace);
}

static int replace_new(BIO *b) {
   //DEBUG_MSG(D_DEBUG, "%s", __FUNCTION__);

   b->ptr = replacer_new();
   b->init = 1;
   b->flags = 0;

   return (1);
}

static int replace_free(BIO *b) {
   //DEBUG_MSG(D_DEBUG, "%s", __FUNCTION__);

   if (b == NULL)
      return (0);

   replacer_free(b->ptr);

   return (1);
}

static int replace_read(BIO *b, char *out, int outl) {
   DEBUG_MSG(D_EXCESSIVE, "%s: %d bytes", __FUNCTION__, outl);

   int ret = 0;

   if (out == NULL)
      return (0);

   if (b->next_bio == NULL)
      return (0);

   /* read from the next BIO */
   ret = BIO_read(b->next_bio, out, outl);

   BIO_clear_retry_flags(b);
   BIO_copy_next_retry(b);

   return (ret);
}

static int replace_write(BIO *b, const char *in, int inl) {
   char *out;
   int outl;

   DEBUG_MSG(D_EXCESSIVE, "%s: %d bytes", __FUNCTION__, inl);

   int ret = 0;

   if ((in == NULL) || (inl == 0))
      return 0;

   if (b->next_bio == NULL || b->ptr == NULL)
      return 0;

   /* feed the replacer which will modify the input as needed */
   replacer_feed(b->ptr, in, inl);

   /* if the replacer has some bytes for us, take them and push to the next bio */
   if (replacer_eat(b->ptr, &out, &outl)) {
      /* send data to the next BIO */
      ret = BIO_write(b->next_bio, out, outl);
   }

   BIO_clear_retry_flags(b);
   BIO_copy_next_retry(b);

   return ret;
}

static long replace_ctrl(BIO *b, int cmd, long num, void *ptr) {
   long ret;

   //DEBUG_MSG(D_DEBUG, "%s: %d", __FUNCTION__, cmd);

   /* my case */
   switch (cmd) {
   case BIO_C_SET_BUF_MEM: {
      struct bio_replace_setup *bis = (struct bio_replace_setup *) ptr;
      struct replacer_obj *rep = (struct replacer_obj *) b->ptr;

      /* prevent missing pointer if called twice */
      SAFE_FREE(rep->search);
      SAFE_FREE(rep->replace);

      rep->search = strdup(bis->search);
      rep->replace = strdup(bis->replace);
      rep->rsize = strlen(bis->replace);
      rep->diff_size = strlen(rep->replace) - strlen(rep->search);
      return 1;
   }
      break;
   }

   if (b->next_bio == NULL)
      return 0;

   /* default stuff */
   switch (cmd) {
   case BIO_C_DO_STATE_MACHINE:
      BIO_clear_retry_flags(b);
      ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
      BIO_copy_next_retry(b);
      break;

   case BIO_CTRL_FLUSH:
      ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
      break;

   case BIO_CTRL_DUP:
      ret = 0L;
      break;

   default:
      ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
      break;
   }

   return (ret);
}

static long replace_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp) {
   //DEBUG_MSG(D_DEBUG, "%s", __FUNCTION__);

   if (b->next_bio == NULL)
      return (0);

   return (BIO_callback_ctrl(b->next_bio, cmd, fp));
}

static int replace_gets(BIO *bp, char *buf, int size) {
   //DEBUG_MSG(D_DEBUG, "%s", __FUNCTION__);

   if (bp->next_bio == NULL)
      return (0);

   return (BIO_gets(bp->next_bio, buf, size));
}

static int replace_puts(BIO *bp, const char *str) {
   //DEBUG_MSG(D_DEBUG, "%s", __FUNCTION__);

   if (bp->next_bio == NULL)
      return (0);

   return (BIO_puts(bp->next_bio, str));
}

/* EOF */

// vim:ts=3:expandtab

